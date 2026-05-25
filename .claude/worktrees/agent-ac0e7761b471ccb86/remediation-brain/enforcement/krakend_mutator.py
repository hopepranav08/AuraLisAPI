# enforcement/krakend_mutator.py — Atomic KrakenD config mutation engine (Phase 4)
#
# Design: atomic mutation with idempotency guard and validation.
#
#   Read krakend.json
#       ↓
#   Parse JSON → dict
#       ↓
#   Idempotency guard — skip methods already quarantined for this path
#       ↓
#   Inject 410 Gone blocks (one per HTTP method) via _build_krakend_410_block()
#       ↓
#   Re-validate: endpoints is a list, no duplicate (endpoint, method) pairs
#       ↓
#   Atomic write: tempfile in same directory → os.replace() (atomic on POSIX,
#   best-effort on Windows — still avoids a partial-write corrupt config)
#       ↓
#   Return KrakendMutationResult
#
# Integration:
#   enforce_node imports mutate_krakend() and calls it BEFORE the GitHub PR so
#   the gateway enforces instantly without waiting for PR review/merge.
#   The KRAKEND_CONFIG_PATH env var must point to a writable copy of krakend.json
#   (mounted into the brain container via docker-compose.yml volumes).
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

# Default path where krakend.json is mounted into the brain container.
_DEFAULT_CONFIG_PATH = os.getenv("KRAKEND_CONFIG_PATH", "/app/krakend.json")

# All HTTP methods that must return 410 for a fully quarantined endpoint.
_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]


@dataclass
class KrakendMutationResult:
    """Result returned by mutate_krakend(). Always inspect .success before using."""
    success: bool
    path: str
    methods_added: list[str]
    diff_preview: str
    endpoint_count_before: int
    endpoint_count_after: int
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "success":                self.success,
            "path":                   self.path,
            "methods_added":          self.methods_added,
            "diff_preview":           self.diff_preview,
            "endpoint_count_before":  self.endpoint_count_before,
            "endpoint_count_after":   self.endpoint_count_after,
            "error":                  self.error,
        }


def _build_410_block(endpoint_path: str, method: str, incident_id: str) -> dict:
    """
    Build a KrakenD v3 endpoint block that returns 410 Gone for the given
    path+method combination.

    Follows krakend-gitops-compliance.md: v3 schema, proxy/static strategy.
    The backend entry is required by KrakenD's schema validator even though
    proxy/static:always never calls it.
    """
    return {
        "endpoint":        endpoint_path,
        "method":          method,
        "output_encoding": "json",
        "backend": [
            {
                "url_pattern": "/gone",
                "host":        ["http://remediation-brain:8000"],
                "encoding":    "json",
            }
        ],
        "extra_config": {
            "proxy/static": {
                "data": {
                    "error":   "Gone",
                    "code":    410,
                    "message": (
                        f"This endpoint has been quarantined by AuralisAPI "
                        f"(incident {incident_id}). Migrate to /api/v3/."
                    ),
                    "sunset":  "2025-01-01T00:00:00Z",
                },
                "strategy": "always",
            }
        },
    }


def _validate_config(cfg: dict) -> Optional[str]:
    """
    Lightweight structural validation of a KrakenD v3 config dict.
    Returns an error string if invalid, None if valid.
    """
    if not isinstance(cfg, dict):
        return "config is not a JSON object"
    if not isinstance(cfg.get("endpoints", []), list):
        return "'endpoints' is not a list"
    # Check for duplicate (endpoint, method) pairs.
    seen: set[tuple[str, str]] = set()
    for ep in cfg.get("endpoints", []):
        key = (ep.get("endpoint", ""), ep.get("method", ""))
        if key in seen:
            return f"duplicate endpoint+method pair: {key}"
        seen.add(key)
    return None


def mutate_krakend(
    endpoint_path: str,
    incident_id: str,
    config_path: str = _DEFAULT_CONFIG_PATH,
    methods: Optional[list[str]] = None,
) -> KrakendMutationResult:
    """
    Atomically inject 410 Gone blocks into krakend.json for the given endpoint.

    Args:
        endpoint_path:  API path to quarantine, e.g. "/api/v1/users".
        incident_id:    AuralisAPI incident ID (embedded in the 410 message).
        config_path:    Absolute path to krakend.json (must be writable).
                        Defaults to KRAKEND_CONFIG_PATH env var or /app/krakend.json.
        methods:        HTTP methods to quarantine. Defaults to all 5 standard methods.

    Returns:
        KrakendMutationResult with success=True on success, error set on failure.
        Always returns a result — never raises.
    """
    if methods is None:
        methods = _ALL_METHODS

    # ── 1. Read current config ─────────────────────────────────────────────────
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = f.read()
        cfg = json.loads(raw)
    except FileNotFoundError:
        return KrakendMutationResult(
            success=False, path=endpoint_path, methods_added=[],
            diff_preview="", endpoint_count_before=0, endpoint_count_after=0,
            error=f"krakend.json not found at {config_path}",
        )
    except json.JSONDecodeError as exc:
        return KrakendMutationResult(
            success=False, path=endpoint_path, methods_added=[],
            diff_preview="", endpoint_count_before=0, endpoint_count_after=0,
            error=f"corrupt krakend.json — JSON parse failed: {exc}",
        )

    # Ensure endpoints key exists.
    if "endpoints" not in cfg or not isinstance(cfg["endpoints"], list):
        cfg["endpoints"] = []

    endpoints: list[dict] = cfg["endpoints"]
    count_before = len(endpoints)

    # ── 2. Idempotency guard ───────────────────────────────────────────────────
    existing_pairs: set[tuple[str, str]] = {
        (ep.get("endpoint", ""), ep.get("method", ""))
        for ep in endpoints
    }

    added_methods: list[str] = []
    added_blocks:  list[dict] = []

    for method in methods:
        if (endpoint_path, method) not in existing_pairs:
            added_blocks.append(_build_410_block(endpoint_path, method, incident_id))
            added_methods.append(method)

    if not added_methods:
        log.info("krakend.json — endpoint already quarantined (idempotent)", path=endpoint_path)
        return KrakendMutationResult(
            success=True, path=endpoint_path, methods_added=[],
            diff_preview=f"(already quarantined for all methods — no changes made)",
            endpoint_count_before=count_before, endpoint_count_after=count_before,
        )

    endpoints.extend(added_blocks)
    count_after = len(endpoints)

    # ── 3. Validate updated config ────────────────────────────────────────────
    validation_error = _validate_config(cfg)
    if validation_error:
        return KrakendMutationResult(
            success=False, path=endpoint_path, methods_added=added_methods,
            diff_preview="", endpoint_count_before=count_before,
            endpoint_count_after=count_after,
            error=f"post-mutation validation failed: {validation_error}",
        )

    diff_preview = (
        f"+ 410 Gone blocks for '{endpoint_path}' "
        f"[{', '.join(added_methods)}]\n"
        f"  endpoints: {count_before} → {count_after}"
    )

    # ── 4. Atomic write ────────────────────────────────────────────────────────
    updated_json = json.dumps(cfg, indent=4)
    config_dir   = os.path.dirname(os.path.abspath(config_path))
    tmp_path: Optional[str] = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".tmp",
            dir=config_dir, delete=False,
        ) as tmp:
            tmp.write(updated_json)
            tmp_path = tmp.name
        os.replace(tmp_path, config_path)
    except OSError as exc:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return KrakendMutationResult(
            success=False, path=endpoint_path, methods_added=added_methods,
            diff_preview=diff_preview, endpoint_count_before=count_before,
            endpoint_count_after=count_after,
            error=f"atomic write failed: {exc}",
        )

    log.info(
        "krakend.json mutated — 410 blocks injected",
        endpoint=endpoint_path,
        methods=added_methods,
        count_before=count_before,
        count_after=count_after,
        config_path=config_path,
    )

    return KrakendMutationResult(
        success=True, path=endpoint_path, methods_added=added_methods,
        diff_preview=diff_preview, endpoint_count_before=count_before,
        endpoint_count_after=count_after,
    )


def read_gateway_state(config_path: str = _DEFAULT_CONFIG_PATH) -> dict:
    """
    Read krakend.json and return a summary of its current state.

    Returns a dict with:
        total:       total endpoint count
        quarantined: list of paths returning 410 Gone
        active:      list of non-410 endpoint paths
        raw_ok:      True if file parsed successfully
        error:       error message if raw_ok is False
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.loads(f.read())
    except FileNotFoundError:
        return {
            "total": 0, "quarantined": [], "active": [],
            "raw_ok": False, "error": f"file not found: {config_path}",
        }
    except json.JSONDecodeError as exc:
        return {
            "total": 0, "quarantined": [], "active": [],
            "raw_ok": False, "error": f"JSON parse error: {exc}",
        }

    endpoints  = cfg.get("endpoints", [])
    quarantined: list[str] = []
    active:      list[str] = []

    for ep in endpoints:
        path   = ep.get("endpoint", "")
        is_410 = (
            ep.get("extra_config", {})
              .get("proxy/static", {})
              .get("data", {})
              .get("code") == 410
        )
        target = quarantined if is_410 else active
        if path not in target:
            target.append(path)

    return {
        "total":       len(endpoints),
        "quarantined": sorted(quarantined),
        "active":      sorted(active),
        "raw_ok":      True,
        "error":       "",
    }
