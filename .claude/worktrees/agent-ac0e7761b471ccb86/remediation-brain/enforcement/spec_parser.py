# enforcement/spec_parser.py — OpenAPI spec utilities + KrakenD CLI wrapper (Phase 4)
#
# Two distinct responsibilities:
#
#   1. openapi_to_krakend_via_cli()
#      Wraps `krakend generate openapi -i <spec> -o <output>`.
#      Used when a FULL spec-to-config conversion is needed (e.g. new API version
#      discovered). Falls back gracefully if the krakend binary is not in PATH.
#
#   2. extract_deprecated_paths()
#      Pure-Python OpenAPI 3.0 spec parser. Returns all paths where any HTTP
#      method carries `deprecated: true`. Used by AnalyzerNode for spec diffing
#      and by the enforcement layer to build batch quarantine lists.
#
#   3. extract_schema_for_path()
#      Extracts the JSON schema of the first successful response (200/2xx) for
#      a given path+method combination. Used by EnforcerNode to pass a realistic
#      schema to the honeypot server so it can generate structurally correct fakes.
from __future__ import annotations

import subprocess
from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)


# ── CLI wrapper ────────────────────────────────────────────────────────────────

def openapi_to_krakend_via_cli(
    spec_path: str,
    output_path: str,
    krakend_binary: str = "krakend",
) -> bool:
    """
    Convert an OpenAPI spec file to a KrakenD config using the KrakenD CLI.

    Invokes: krakend generate openapi -i <spec_path> -o <output_path>

    Args:
        spec_path:       Absolute path to the OpenAPI YAML/JSON spec file.
        output_path:     Where to write the generated krakend.json.
        krakend_binary:  Name/path of the krakend binary (must be in PATH).

    Returns:
        True on success, False on any failure (binary not found, non-zero exit,
        timeout). Callers must handle False gracefully — this path is optional.
    """
    try:
        result = subprocess.run(
            [krakend_binary, "generate", "openapi", "-i", spec_path, "-o", output_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            log.info(
                "krakend CLI converted spec to config",
                spec=spec_path,
                output=output_path,
            )
            return True
        log.warning(
            "krakend CLI returned non-zero exit code",
            returncode=result.returncode,
            stderr=result.stderr[:500],
        )
        return False
    except FileNotFoundError:
        log.warning(
            "krakend binary not in PATH — CLI conversion skipped",
            binary=krakend_binary,
        )
        return False
    except subprocess.TimeoutExpired:
        log.warning("krakend CLI timed out after 30s")
        return False
    except OSError as exc:
        log.warning("krakend CLI subprocess error", error=str(exc))
        return False


# ── OpenAPI 3.0 spec analysis ─────────────────────────────────────────────────

def extract_deprecated_paths(spec: dict[str, Any]) -> list[str]:
    """
    Return all API paths in the spec where any HTTP method is marked deprecated.

    OpenAPI 3.0 marks deprecation per-operation (method level), not per-path.
    A path is returned if AT LEAST ONE of its methods has deprecated: true.

    Args:
        spec: Parsed OpenAPI 3.0 spec dict (from yaml.safe_load or json.loads).

    Returns:
        Sorted list of path strings, e.g. ["/api/v1/users", "/api/v1/payments"].
        Empty list if spec has no paths section or no deprecated operations.
    """
    deprecated: list[str] = []
    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                if isinstance(operation, dict) and operation.get("deprecated", False):
                    if path not in deprecated:
                        deprecated.append(path)
                    break  # one deprecated method is enough to include the path
    return sorted(deprecated)


def extract_schema_for_path(
    spec: dict[str, Any],
    path: str,
    method: str = "get",
) -> dict[str, Any]:
    """
    Extract the JSON schema of the first 2xx response body for a given operation.

    Used by EnforcerNode to pass a realistic schema to the honeypot server
    so it generates structurally correct fake data instead of generic fields.

    Args:
        spec:   Parsed OpenAPI 3.0 spec dict.
        path:   API path string, e.g. "/api/v1/users".
        method: HTTP method (case-insensitive), e.g. "get".

    Returns:
        JSON schema dict (may be empty {} if no schema found — callers must
        handle empty schema gracefully by falling back to heuristic generation).
    """
    path_item = spec.get("paths", {}).get(path, {})
    operation = path_item.get(method.lower(), {})
    responses  = operation.get("responses", {})

    # Prefer 200, then any 2xx response.
    for status_code in ["200", "201", "202", "204"]:
        response = responses.get(status_code, {})
        schema   = _extract_schema_from_response(response)
        if schema:
            return schema

    # Fallback: first response available
    for response in responses.values():
        if isinstance(response, dict):
            schema = _extract_schema_from_response(response)
            if schema:
                return schema

    return {}


def _extract_schema_from_response(response: dict[str, Any]) -> dict[str, Any]:
    """
    Dig into a response object to find the application/json schema.
    Handles both inline schemas and $ref (returns the $ref dict — callers
    resolve refs themselves or use the properties if directly present).
    """
    if not isinstance(response, dict):
        return {}
    content = response.get("content", {})
    json_content = (
        content.get("application/json")
        or content.get("application/json; charset=utf-8")
        or {}
    )
    schema = json_content.get("schema", {})
    # If the schema is an array wrapper, extract items schema.
    if schema.get("type") == "array" and "items" in schema:
        return schema["items"]
    return schema


def list_all_paths(spec: dict[str, Any]) -> list[str]:
    """
    Return all paths defined in the spec, sorted alphabetically.
    Convenience helper for AnalyzerNode spec diffing.
    """
    return sorted(spec.get("paths", {}).keys())


def diff_traffic_vs_spec(
    live_paths: list[str],
    spec: dict[str, Any],
) -> dict[str, list[str]]:
    """
    Compare live traffic paths against the spec and categorise the differences.

    Returns a dict with three lists:
        missing_from_spec:  paths seen in traffic but not in the spec (shadow APIs)
        deprecated_active:  paths in traffic AND in spec, but marked deprecated
        dormant:            paths in spec but NOT seen in traffic (dormant zombies)
    """
    spec_paths       = set(spec.get("paths", {}).keys())
    live_set         = set(live_paths)
    deprecated_set   = set(extract_deprecated_paths(spec))

    missing_from_spec  = sorted(live_set - spec_paths)
    deprecated_active  = sorted(live_set & deprecated_set)
    dormant            = sorted((spec_paths - live_set) & deprecated_set)

    return {
        "missing_from_spec":  missing_from_spec,
        "deprecated_active":  deprecated_active,
        "dormant":            dormant,
    }
