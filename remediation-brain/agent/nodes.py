# agent/nodes.py — LangGraph Node Implementations (Phase 3)
#
# Node topology:
#   ingest → analyze → plan → [interrupt_before enforce] → enforce → generate_report → END
#
# AnalyzerNode  — diffs live traffic against OpenAPI 3.0 spec fetched from GitHub.
#                 Falls back to path-prefix heuristics if GITHUB_TOKEN is absent.
#                 Applies enhanced PII/PCI detection with regex + entropy analysis.
#
# PlannerNode   — formulates GitOps PR strategy based on classification + PII flag.
#                 Produces a concrete action list for human reviewer approval.
#
# EnforcerNode  — executes the plan: creates a GitHub PR updating krakend.json.
#                 Stub mode (no PR) when GITHUB_TOKEN is absent.
#
# Rules enforced:
#   - LangGraph state management: TypedDict, Annotated reducers (see state.py)
#   - KrakenD GitOps: all gateway changes via krakend.json PR, never mutate live config
#   - Human-in-the-loop: interrupt_before=["enforce"] in graph.py — enforce never
#     runs without explicit /incidents/{id}/approve API call
from __future__ import annotations

import asyncio
import base64
import copy
import json
import math
import os
import re
import uuid
import yaml  # type: ignore[import]
from typing import Any, Literal, Optional

import httpx  # type: ignore[import]
import structlog  # type: ignore[import]
from pydantic import BaseModel, Field  # type: ignore[import]

from agent.state import IncidentState


# ── Structured report schema (used by Groq .with_structured_output) ───────────

class IncidentReport(BaseModel):
    executive_summary: str = Field(
        description="3-4 sentence summary suitable for a non-technical stakeholder"
    )
    risk_level: Literal["critical", "high", "medium", "low"] = Field(
        description="Overall risk assessment — must match the incident severity"
    )
    recommended_action: str = Field(
        description="The single most important next step for the security team"
    )
    technical_detail: str = Field(
        description="Technical explanation of what was detected and why it matters"
    )

# Phase 4: KrakenD mutator — imported with graceful fallback so the module
# still loads even if the enforcement package is temporarily unavailable.
try:
    from enforcement.krakend_mutator import mutate_krakend
    _MUTATOR_AVAILABLE = True
except ImportError:
    _MUTATOR_AVAILABLE = False

log = structlog.get_logger(__name__)

_HONEYPOT_URL = os.getenv("HONEYPOT_URL", "http://honeypot-decoy:8082")

# ── LLM: Claude claude-haiku-4-5 primary, Groq fallback, heuristics last resort ────────────
_llm = None
_llm_structured = None

_anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
_groq_key      = os.getenv("GROQ_API_KEY", "")

if _anthropic_key:
    try:
        from langchain_anthropic import ChatAnthropic  # type: ignore[import]
        _llm = ChatAnthropic(
            model="claude-haiku-4-5-20251001",
            anthropic_api_key=_anthropic_key,
            temperature=0,
            max_tokens=1024,
        )
        _llm_structured = _llm.with_structured_output(IncidentReport)
        log.info("LLM: Claude claude-haiku-4-5 loaded (primary)")
    except Exception as exc:
        log.warning("Claude claude-haiku-4-5 init failed", error=str(exc))
        _llm = None
        _llm_structured = None

if _llm is None and _groq_key:
    try:
        from langchain_groq import ChatGroq  # type: ignore[import]
        _llm = ChatGroq(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            groq_api_key=_groq_key,
            temperature=0,
        )
        _llm_structured = _llm.with_structured_output(IncidentReport)
        log.info("LLM: Groq loaded (fallback)")
    except Exception as exc:
        log.warning("Groq init failed", error=str(exc))
        _llm = None
        _llm_structured = None

if _llm is None:
    log.warning("No LLM configured — incident reports will use heuristics. Set ANTHROPIC_API_KEY for AI summaries.")

# ── LLM rate-limit cooldown tracker (Fix H2) ─────────────────────────────────
# When a 429 (rate limit) is received, we skip LLM calls for _LLM_COOLDOWN_SECS
# to avoid burning tokens on doomed requests. Resets after the cooldown expires.
import time as _time  # noqa: E402 (import after statements intentional here)
_llm_rate_limited_until: float = 0.0   # epoch seconds; 0 = not rate-limited
_LLM_COOLDOWN_SECS = 300               # 5 minutes — matches Groq TPD reset window


def _llm_available() -> bool:
    """Return True if the LLM is configured and not in rate-limit cooldown."""
    if _llm_structured is None:
        return False
    if _time.time() < _llm_rate_limited_until:
        return False
    return True


def _mark_rate_limited() -> None:
    """Enter cooldown after receiving a 429. Thread-safe via GIL (float assign)."""
    global _llm_rate_limited_until
    _llm_rate_limited_until = _time.time() + _LLM_COOLDOWN_SECS
    log.warning("LLM rate-limited — switching to heuristics",
                cooldown_secs=_LLM_COOLDOWN_SECS)



# ── GitHub client (optional — graceful degradation when token absent) ──────────
_github = None
_github_token = os.getenv("GITHUB_TOKEN", "")
_github_repo = os.getenv("GITHUB_REPO", "")
if _github_token:
    try:
        from github import Github, GithubException  # type: ignore[import]
        _github = Github(_github_token, timeout=8)
    except Exception:
        _github = None

# ── PII / PCI detection patterns ──────────────────────────────────────────────
_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email":       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "ssn":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ \-]?){13,16}\b"),
    "phone":       re.compile(r"\b\d{3}[.\-\s]?\d{3}[.\-\s]?\d{4}\b"),
    "iban":        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?\b"),
    "dob":         re.compile(r"\b(?:19|20)\d{2}[\/\-\.]\d{2}[\/\-\.]\d{2}\b"),
    "passport":    re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
}

# Paths that definitively indicate deprecated API versions
_DEPRECATED_PREFIXES = ["/api/v1/", "/api/v0/", "/legacy/", "/old/", "/v1/", "/v0/"]
_CURRENT_PREFIX      = "/api/v3/"
_OPENAPI_SPEC_PATH   = "openapi.yaml"  # path inside GitHub repo

# ── Shannon entropy threshold for detecting encoded PII in long values ─────────
_ENTROPY_THRESHOLD   = 4.5   # bits/char — base64, AES keys, tokens
_ENTROPY_MIN_LENGTH  = 20    # only check values longer than this


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _detect_pii(payload_str: str) -> list[str]:
    """
    Run all PII/PCI regex patterns + entropy analysis against a payload string.
    Returns a list of matched labels (e.g. ['email', 'credit_card']).
    """
    findings: list[str] = []

    # 1. Regex matching
    for label, pattern in _PII_PATTERNS.items():
        if pattern.search(payload_str):
            findings.append(label)

    # 2. Entropy analysis — detect base64/encrypted values that might contain PII.
    #    Scan all string-like tokens > _ENTROPY_MIN_LENGTH chars.
    words = re.split(r'[\s,{}"\':=&]+', payload_str)
    for word in words:
        if len(word) >= _ENTROPY_MIN_LENGTH:
            if _shannon_entropy(word) >= _ENTROPY_THRESHOLD:
                if "high_entropy_value" not in findings:
                    findings.append("high_entropy_value")
                break

    return findings


def _fetch_openapi_spec() -> Optional[dict[str, Any]]:
    """
    Fetch and parse the OpenAPI 3.0 spec.

    Priority: GitHub (authoritative) → local /app/openapi.yaml (mounted fallback).
    Returns parsed dict on success, None when neither source is available.
    """
    if _github is not None and _github_repo:
        try:
            from github import GithubException  # type: ignore[import]
            repo = _github.get_repo(_github_repo)
            contents = repo.get_contents(_OPENAPI_SPEC_PATH)
            raw = base64.b64decode(contents.content).decode("utf-8")
            return yaml.safe_load(raw)
        except Exception as exc:
            log.warning("openapi github fetch failed — trying local fallback", error=str(exc))

    # Local fallback: openapi.yaml mounted at /app/openapi.yaml in the container
    import os as _os
    local_path = "/app/openapi.yaml"
    if _os.path.exists(local_path):
        try:
            with open(local_path) as f:
                return yaml.safe_load(f)
        except Exception as exc:
            log.warning("openapi local spec read failed", error=str(exc))

    return None


def _extract_spec_paths(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Extract a flat map of {path: path_item} from an OpenAPI 3.0 spec.
    Returns empty dict if spec has no 'paths' section.
    """
    return spec.get("paths", {}) if spec else {}


def _is_deprecated_in_spec(path: str, spec_paths: dict[str, dict[str, Any]]) -> bool:
    """Return True if the path is present in the spec and marked deprecated: true."""
    path_item = spec_paths.get(path, {})
    for method_item in path_item.values():
        if isinstance(method_item, dict) and method_item.get("deprecated", False):
            return True
    return False


def _build_krakend_410_block(path: str, incident_id: str) -> dict[str, Any]:
    """
    Build a KrakenD v3 endpoint block that returns 410 Gone for the given path.
    Follows krakend-gitops-compliance.md: v3 schema, proxy/static strategy.
    """
    return {
        "endpoint": path,
        "method": "GET",
        "output_encoding": "json",
        "backend": [
            {
                "url_pattern": "/gone",
                "host": ["http://remediation-brain:8000"],
                "encoding": "json",
            }
        ],
        "extra_config": {
            "proxy/static": {
                "data": {
                    "error": "Gone",
                    "code": 410,
                    "message": (
                        "This endpoint has been quarantined by AuralisAPI "
                        f"(incident {incident_id}). Migrate to /api/v3/."
                    ),
                    "sunset": "2025-01-01T00:00:00Z",
                    **({"docs": f"https://github.com/{_github_repo}/blob/main/MIGRATION.md"} if _github_repo else {}),
                },
                "strategy":    "always",
                "status_code": 410,
            }
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Node: ingest  (unchanged from Phase 1 — stable, do not modify)
# ─────────────────────────────────────────────────────────────────────────────

async def ingest_node(state: IncidentState) -> dict[str, Any]:
    """Normalize the raw event and assign an incident ID.

    For drift_alert events, 'path' is pre-populated from 'endpoint' by the
    consumer (agent/consumer.py) before the graph is invoked, so all nodes
    can use raw_event['path'] uniformly regardless of event type.
    """
    incident_id = state.get("incident_id") or str(uuid.uuid4())
    raw = state["raw_event"]
    event_type = raw.get("event_type", "http_event")
    path = raw.get("path", "unknown")
    return {
        "incident_id":    incident_id,
        "reasoning_trace": [
            f"[ingest] Received {event_type} event for path: {path}",
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Node: analyze  (Phase 3 — replaces classify_node + assess_risk_node)
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_node(state: IncidentState) -> dict[str, Any]:
    """
    AnalyzerNode: diffs live traffic against OpenAPI 3.0 spec + detects PII/PCI.

    Steps:
    1. Fetch canonical OpenAPI spec from GitHub (graceful fallback to heuristics).
    2. Classify the endpoint: active_zombie | dormant_zombie | shadow | unknown.
    3. Run enhanced PII/PCI regex + entropy analysis on the full event payload.
    4. Compute severity: critical > high > medium > low.
    5. Populate spec_diff for PlannerNode.

    Drift alerts (from the eBPF drift detection engine) carry their own context
    (alarm_type, resurrected) which short-circuits the spec lookup.
    """
    raw         = state["raw_event"]
    path        = raw.get("path", "")
    payload_str = str(raw)
    event_type  = raw.get("event_type", "http_event")

    # ── Step 1: Fetch spec ─────────────────────────────────────────────────────
    # PyGithub makes synchronous HTTP requests — run in thread pool to avoid
    # blocking the asyncio event loop.
    spec       = await asyncio.to_thread(_fetch_openapi_spec)
    spec_paths = _extract_spec_paths(spec) if spec else {}
    used_spec  = bool(spec_paths)

    spec_diff: dict[str, Any] = {
        "used_github_spec": used_spec,
        "found_in_spec":    path in spec_paths,
        "deprecated_in_spec": _is_deprecated_in_spec(path, spec_paths) if used_spec else False,
    }

    # Extract the OpenAPI response schema for this path so the honeypot can
    # serve spec-accurate fake responses instead of pure heuristic ones.
    if used_spec and path in spec_paths:
        path_item = spec_paths[path]
        for method_item in path_item.values():
            if not isinstance(method_item, dict):
                continue
            ok = method_item.get("responses", {}).get("200", method_item.get("responses", {}).get("201", {}))
            schema = ok.get("content", {}).get("application/json", {}).get("schema", {})
            if schema:
                spec_diff["response_schema"] = schema
                break

    # ── Step 2: Classify ──────────────────────────────────────────────────────
    classification: Literal["shadow", "active_zombie", "dormant_zombie", "unknown"]

    if event_type == "drift_alert":
        # Drift alerts carry explicit alarm context from the PH engine.
        alarm_type  = raw.get("alarm_type", "")
        resurrected = raw.get("resurrected", False)
        if resurrected or "resurrection" in alarm_type:
            classification = "active_zombie"
            spec_diff["drift_trigger"] = "resurrection"
        elif alarm_type == "sustained_attack":
            classification = "active_zombie"
            spec_diff["drift_trigger"] = "sustained_attack"
        else:
            is_deprecated = any(path.startswith(p) for p in _DEPRECATED_PREFIXES)
            classification = "active_zombie" if is_deprecated else "shadow"
            spec_diff["drift_trigger"] = alarm_type
    elif used_spec:
        # Use the spec as the authoritative source.
        if path in spec_paths:
            if _is_deprecated_in_spec(path, spec_paths):
                classification = "active_zombie"          # in spec + deprecated
                spec_diff["deprecated_active"] = True
            else:
                classification = "unknown"                # in spec, current, healthy
        else:
            classification = "shadow"                     # in traffic, not in spec
            spec_diff["missing_from_spec"] = True
    else:
        # Fallback: path-prefix heuristics when GitHub is unavailable.
        if any(path.startswith(p) for p in _DEPRECATED_PREFIXES):
            classification = "active_zombie"
        elif path and not path.startswith(_CURRENT_PREFIX):
            classification = "shadow"
        else:
            classification = "unknown"

    # ── Step 3: PII / PCI detection ───────────────────────────────────────────
    pii_found     = _detect_pii(payload_str)
    is_pii_exposed = bool(pii_found)

    # ── Step 4: Severity ──────────────────────────────────────────────────────
    severity: Literal["critical", "high", "medium", "low"]

    alarm_type = raw.get("alarm_type", "") if event_type == "drift_alert" else ""
    if alarm_type == "sustained_attack":
        severity = "critical"
    elif is_pii_exposed and classification in ("active_zombie", "shadow"):
        severity = "critical"
    elif classification == "active_zombie":
        severity = "high"
    elif classification == "shadow":
        severity = "medium"
    else:
        severity = "low"

    drift_note = (
        f", alarm_type={raw.get('alarm_type')}, ph_score={raw.get('ph_score', 'n/a')}"
        if event_type == "drift_alert" else ""
    )
    spec_note = f" [spec:{'github' if used_spec else 'heuristics'}]"

    return {
        "classification": classification,
        "severity":       severity,
        "is_pii_exposed": is_pii_exposed,
        "pii_findings":   pii_found,
        "spec_diff":      spec_diff,
        # enforcement_approved is intentionally NOT set here.
        # It is initialised to False in consumer.py and can only be set to True
        # by POST /incidents/{id}/approve — the mandatory human-in-the-loop gate.
        "reasoning_trace": [
            f"[analyze] path='{path}' → classification={classification}, "
            f"severity={severity}, pii={pii_found}{drift_note}{spec_note}"
        ],
    }



# ─────────────────────────────────────────────────────────────────────────────
# Node: plan  (Phase 3 — NEW)
# ─────────────────────────────────────────────────────────────────────────────

async def plan_node(state: IncidentState) -> dict[str, Any]:
    """
    PlannerNode: formulates the GitOps remediation strategy.

    Reads classification, severity, is_pii_exposed from state and produces:
    - A concrete planned_actions list shown to the human reviewer
    - The exact krakend.json block that will be injected by EnforcerNode
    - Escalation flag if PII is involved

    This node runs BEFORE the interrupt — the human sees the full plan
    before approving or rejecting enforcement.
    """
    classification = state.get("classification", "unknown")
    severity       = state.get("severity", "low")
    is_pii         = state.get("is_pii_exposed", False)
    path           = state["raw_event"].get("path", "unknown")
    incident_id    = state.get("incident_id", "unknown")

    planned: list[str] = []
    plan_notes: list[str] = []

    if severity in ("critical", "high"):
        # Generate the exact krakend.json block for human review.
        krakend_block = _build_krakend_410_block(path, incident_id)
        planned.append(f"quarantine_gateway:{path}")
        planned.append(f"krakend_block:{json.dumps(krakend_block)}")
        planned.append(f"spin_up_honeypot:{path}")
        plan_notes.append(
            f"[plan] Will inject 410 Gone route for '{path}' into krakend.json via GitHub PR"
        )
        if is_pii:
            planned.append("escalate_to_ciso")
            plan_notes.append(
                "[plan] PII detected — CISO escalation queued (critical incident)"
            )
        if classification == "active_zombie":
            plan_notes.append(
                f"[plan] Active Zombie: endpoint is deprecated but receiving live traffic"
            )
        elif classification == "dormant_zombie":
            plan_notes.append(
                f"[plan] Dormant Zombie: endpoint is deprecated with zero traffic window"
            )

    elif severity == "medium":
        # Shadow API — document but don't quarantine yet.
        planned.append(f"document_endpoint:{path}")
        planned.append(f"add_to_inventory:{path}")
        plan_notes.append(
            f"[plan] Shadow API detected — adding to inventory, no enforcement yet"
        )

    else:
        planned.append(f"log_only:{path}")
        plan_notes.append(
            f"[plan] Low severity — logging only, no enforcement action"
        )

    return {
        "planned_actions": planned,
        "reasoning_trace": plan_notes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Conditional edge: should_enforce  (routes after plan_node)
# ─────────────────────────────────────────────────────────────────────────────

def should_enforce(state: IncidentState) -> Literal["enforce", "report"]:
    """
    Route graph to 'enforce' (human-approval gate) or skip to 'report'.

    IMPORTANT: This edge fires BEFORE the interrupt_before=["enforce"] halt.
    The interrupt halts the graph. When resumed via POST /approve, LangGraph
    resumes from the enforce node (enforcement_approved is now True).
    When rejected via POST /reject, the graph is re-routed externally to
    generate_report without calling enforce.

    Routing logic:
    - critical / high severity  → route to "enforce"
      → graph pauses at interrupt (awaiting_approval)
      → human approves → enforce runs → report
      → human rejects → report directly (via /reject API)
    - medium / low severity → skip to "report" immediately
      (no enforcement action warranted for low-signal events)
    """
    severity = (state.get("severity") or "").lower()
    if severity in ("critical", "high"):
        return "enforce"
    return "report"



# ─────────────────────────────────────────────────────────────────────────────
# Node: enforce  (Phase 3 — real GitHub PR implementation)
# ─────────────────────────────────────────────────────────────────────────────

async def enforce_node(state: IncidentState) -> dict[str, Any]:
    """
    EnforcerNode: executes the quarantine plan by creating a GitHub PR.

    NOTE: This node is guarded by interrupt_before=["enforce"] in graph.py.
    A human MUST explicitly call POST /incidents/{thread_id}/approve before
    this node executes — this is the hard enforcement barrier.

    Execution:
    1. Extracts the krakend_block from planned_actions (set by plan_node).
    2. Fetches current krakend.json from the GitHub repo.
    3. Injects the 410 Gone block for the deprecated path.
    4. Creates a branch and PR with the updated config.
    5. Stores the PR URL in state for the report.

    Stub mode: if GITHUB_TOKEN is absent, logs the intended action without
    creating a real PR (github_pr_url = None). Demo still works fully.
    """
    path        = state["raw_event"].get("path", "unknown")
    incident_id = state.get("incident_id", "unknown")
    severity    = state.get("severity", "unknown")
    planned     = state.get("planned_actions", [])

    # Extract the krakend block from planned_actions (serialised by plan_node).
    krakend_block: Optional[dict[str, Any]] = None
    for action in planned:
        if action.startswith("krakend_block:"):
            try:
                krakend_block = json.loads(action.split("krakend_block:", 1)[1])
            except (json.JSONDecodeError, IndexError):
                pass
            break

    action_msg = (
        f"[enforce] Quarantine '{path}' — "
        f"inject 410 Gone route into krakend.json via GitHub PR"
    )

    pr_url:   Optional[str] = None
    executed: list[str]     = [action_msg]

    # ── Stub mode (no GITHUB_TOKEN) ────────────────────────────────────────────
    if _github is None or not _github_repo:
        log.warning(
            "enforce running in stub mode — GITHUB_TOKEN not set",
            path=path,
            incident_id=incident_id,
        )
        stub_msg = (
            f"[enforce:STUB] Would create PR on {_github_repo or '<repo not set>'}: "
            f"add 410 route for '{path}'"
        )
        executed.append(stub_msg)

    else:
        # ── Real GitHub PR creation ────────────────────────────────────────────
        try:
            from github import GithubException  # type: ignore[import]

            repo         = _github.get_repo(_github_repo)
            base_branch  = os.getenv("GITHUB_BRANCH", "main")
            new_branch   = f"auralis/quarantine/{incident_id[:8]}"

            # 1. Get current krakend.json from the repo.
            try:
                krakend_file = repo.get_contents("api-gateway/krakend.json", ref=base_branch)
                current_str  = base64.b64decode(krakend_file.content).decode("utf-8")
                current_cfg  = json.loads(current_str)
            except Exception as exc:
                raise RuntimeError(f"failed to fetch krakend.json: {exc}") from exc

            # 2. Inject 410 blocks for all 5 methods — consistent with local mutator.
            existing_pairs = {
                (ep.get("endpoint"), ep.get("method"))
                for ep in current_cfg.get("endpoints", [])
            }
            if krakend_block:
                ep_path = krakend_block.get("endpoint")
                for http_method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    if (ep_path, http_method) not in existing_pairs:
                        method_block = copy.deepcopy(krakend_block)
                        method_block["method"] = http_method
                        current_cfg["endpoints"].append(method_block)

            updated_str = json.dumps(current_cfg, indent=4)

            # 3. Create branch from base.
            base_sha = repo.get_branch(base_branch).commit.sha
            try:
                repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_sha)
            except GithubException as exc:
                if exc.status == 422:
                    pass  # Branch already exists — idempotent (retry scenario).
                else:
                    raise

            # 4. Commit the updated krakend.json to the new branch.
            repo.update_file(
                path="api-gateway/krakend.json",
                message=f"[AuralisAPI] Quarantine {path} (incident {incident_id[:8]})",
                content=updated_str,
                sha=krakend_file.sha,
                branch=new_branch,
            )

            # 5. Open the Pull Request.
            pr = repo.create_pull(
                title=f"[AuralisAPI] Quarantine {path} — {severity} severity",
                body=_build_pr_body(state),
                head=new_branch,
                base=base_branch,
            )
            pr_url = pr.html_url
            executed.append(f"[enforce] PR created: {pr_url}")
            log.info(
                "quarantine PR created",
                path=path,
                pr_url=pr_url,
                incident_id=incident_id,
            )

        except Exception as exc:
            err_msg = f"[enforce:ERROR] GitHub PR creation failed: {exc}"
            log.error("enforce node failed", error=str(exc), incident_id=incident_id)
            executed.append(err_msg)

    # ── Phase 4A: Instant local krakend.json mutation ─────────────────────────
    # Mutates the locally-mounted krakend.json immediately so the 410 block is
    # visible in GET /gateway/config without waiting for the PR to be merged.
    if _MUTATOR_AVAILABLE:
        # mutate_krakend() is synchronous file I/O — run in thread pool to
        # avoid blocking the asyncio event loop during the write.
        mutation = await asyncio.to_thread(mutate_krakend, path, incident_id)
        if mutation.success and mutation.methods_added:
            executed.append(
                f"[enforce] krakend.json mutated locally: "
                f"+{len(mutation.methods_added)} 410 blocks "
                f"({mutation.endpoint_count_before}→{mutation.endpoint_count_after} endpoints)"
            )
        elif mutation.success:
            executed.append(f"[enforce] krakend.json — {path} already quarantined (idempotent)")
        else:
            executed.append(
                f"[enforce:WARN] local krakend.json mutation skipped: {mutation.error}"
            )
        log.info("local krakend mutation result", **mutation.to_dict())

    # ── Phase 4B: Register path with dynamic honeypot server ──────────────────
    # Fire-and-forget HTTP POST to honeypot-decoy:8082/admin/register-path so
    # the deception server immediately starts serving fake responses for this path.
    spec_diff = state.get("spec_diff") or {}
    schema    = spec_diff.get("response_schema", {})
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            resp = await client.post(
                f"{_HONEYPOT_URL}/admin/register-path",
                json={"path": path, "response_schema": schema},
            )
            if resp.status_code in (200, 201):
                executed.append(f"[enforce] honeypot path registered: {path}")
            else:
                executed.append(
                    f"[enforce:WARN] honeypot registration returned HTTP {resp.status_code}"
                )
    except httpx.ConnectError:
        executed.append("[enforce:WARN] honeypot-decoy unreachable — path not registered")
    except Exception as exc:
        executed.append(f"[enforce:WARN] honeypot registration failed: {exc}")

    action_msg = f"[enforce] completed: {len(executed)} action(s) taken for {state['raw_event'].get('path', 'unknown')}"
    return {
        "executed_actions": executed,
        "github_pr_url":   pr_url,
        "reasoning_trace": [action_msg],
    }


def _build_pr_body(state: IncidentState) -> str:
    """Build the GitHub PR description markdown from incident state."""
    incident_id    = state.get("incident_id", "N/A")
    path           = state["raw_event"].get("path", "unknown")
    classification = state.get("classification", "unknown")
    severity       = state.get("severity", "unknown")
    pii            = ", ".join(state.get("pii_findings", [])) or "None"
    actions        = state.get("planned_actions", [])
    trace          = state.get("reasoning_trace", [])

    return "\n".join([
        "## AuralisAPI Automated Quarantine",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Incident ID | `{incident_id}` |",
        f"| Endpoint | `{path}` |",
        f"| Classification | **{classification}** |",
        f"| Severity | **{severity}** |",
        f"| PII Detected | {pii} |",
        "",
        "### Planned Actions",
        *[f"- `{a}`" for a in actions],
        "",
        "### Reasoning Trace",
        *[f"- {r}" for r in trace],
        "",
        "---",
        "_Generated autonomously by [AuralisAPI](https://github.com/hopepranav08/AuraLisAPI). "
        "Human review and merge required before enforcement takes effect._",
    ])


# ─────────────────────────────────────────────────────────────────────────────
# Node: generate_report  (Phase 3 — enhanced with spec_diff + PR URL)
# ─────────────────────────────────────────────────────────────────────────────

async def report_node(state: IncidentState) -> dict[str, Any]:
    """Compile a structured incident report from accumulated state.

    Returns report as a typed dict with fields consumable by the UI:
      executive_summary, risk_level, recommended_action, technical_detail,
      actions_taken, reasoning_trace, plus incident metadata.

    When Groq is configured the four AI fields are generated via
    .with_structured_output(IncidentReport) — no string parsing required.
    Falls back to heuristic values when GROQ_API_KEY is absent.
    """
    incident_id    = state.get("incident_id", "N/A")
    classification = state.get("classification")
    severity       = state.get("severity")
    pii_list       = state.get("pii_findings", [])
    pii            = ", ".join(pii_list) or "None"
    is_pii         = state.get("is_pii_exposed", False)
    actions        = state.get("executed_actions", [])
    trace          = state.get("reasoning_trace", [])
    path           = state["raw_event"].get("path", "unknown")
    pr_url         = state.get("github_pr_url")
    spec_diff      = state.get("spec_diff") or {}

    spec_source = "GitHub" if spec_diff.get("used_github_spec") else "path-prefix heuristics"

    # Metadata always included regardless of LLM availability
    meta: dict[str, Any] = {
        "incident_id":    incident_id,
        "endpoint":       path,
        "classification": classification,
        "severity":       severity,
        "pii_detected":   pii,
        "is_pii_exposed": is_pii,
        "spec_source":    spec_source,
        "pr_url":         pr_url,
        "actions_taken":  actions,
        "reasoning_trace": trace,
    }

    if not _llm_available():
        # Heuristic fallback — LLM not configured or in rate-limit cooldown
        pii_note = f" PII exposure detected: {pii}. CISO escalation recommended." if is_pii else ""
        action_summary = "; ".join(actions) if actions else "no enforcement actions taken"
        meta.update({
            "executive_summary": (
                f"Endpoint {path} was classified as {classification} with {severity} severity.{pii_note} "
                f"Automated analysis used {spec_source}. {action_summary.capitalize()}."
            ),
            "risk_level":         severity or "unknown",
            "recommended_action": (
                "Review the planned actions and enforce quarantine via the Approve button."
                if not actions else
                "Verify the quarantine is active in the gateway config and monitor for traffic resumption."
            ),
            "technical_detail": (
                f"The endpoint {path} was detected via eBPF traffic analysis. "
                f"Classification: {classification}. Spec diff source: {spec_source}. "
                f"Executed: {action_summary}."
            ),
        })
        return {"report": meta}

    prompt = (
        f"You are a security analyst writing a concise API security incident report.\n"
        f"Endpoint: {path}\n"
        f"Classification: {classification} (zombie = deprecated API still receiving traffic)\n"
        f"Severity: {severity}\n"
        f"PII detected in response: {pii}\n"
        f"Spec analysis source: {spec_source}\n"
        f"Actions taken: {'; '.join(actions) or 'none'}\n"
        f"GitHub PR: {pr_url or 'not created'}\n\n"
        f"Fill in all four fields of the report schema. "
        f"Be direct and factual. Mention PII risk explicitly if applicable. "
        f"The recommended_action must be a single concrete step."
    )
    try:
        assert _llm_structured is not None  # guaranteed by _llm_available() check above
        llm_report: IncidentReport = await _llm_structured.ainvoke(prompt)
        meta.update({
            "executive_summary":  llm_report.executive_summary,
            "risk_level":         llm_report.risk_level,
            "recommended_action": llm_report.recommended_action,
            "technical_detail":   llm_report.technical_detail,
        })
    except Exception as exc:
        err_str = str(exc)
        # Detect rate-limit (429) and enter cooldown to avoid repeated failed calls.
        if "429" in err_str or "rate_limit" in err_str.lower() or "rate limit" in err_str.lower():
            _mark_rate_limited()
        else:
            log.warning("structured LLM report failed, using heuristics", error=err_str)
        meta.update({
            "executive_summary":  "AI analysis unavailable — see technical detail.",
            "risk_level":         severity or "unknown",
            "recommended_action": "Manually review the actions taken and confirm quarantine status.",
            "technical_detail":   f"Endpoint {path} | {classification} | {severity} | actions: {'; '.join(actions) or 'none'}",
        })

    return {"report": meta}
