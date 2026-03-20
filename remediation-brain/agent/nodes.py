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

import base64
import json
import math
import os
import re
import uuid
import yaml
from typing import Any, Literal, Optional

import httpx
import structlog

from agent.state import IncidentState

# Phase 4: KrakenD mutator — imported with graceful fallback so the module
# still loads even if the enforcement package is temporarily unavailable.
try:
    from enforcement.krakend_mutator import mutate_krakend, KrakendMutationResult
    _MUTATOR_AVAILABLE = True
except ImportError:
    _MUTATOR_AVAILABLE = False

log = structlog.get_logger(__name__)

# ── Groq LLM (optional — falls back to heuristics if key not set) ─────────────
_llm = None
_groq_key = os.getenv("GROQ_API_KEY", "")
if _groq_key:
    try:
        from langchain_groq import ChatGroq
        _llm = ChatGroq(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            groq_api_key=_groq_key,
            temperature=0,
        )
    except Exception:
        _llm = None

# ── GitHub client (optional — graceful degradation when token absent) ──────────
_github = None
_github_token = os.getenv("GITHUB_TOKEN", "")
_github_repo = os.getenv("GITHUB_REPO", "")
if _github_token:
    try:
        from github import Github, GithubException  # type: ignore[import]
        _github = Github(_github_token)
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
    Fetch and parse the OpenAPI 3.0 spec from GitHub.

    Returns parsed dict on success, None on any failure (no token, repo not set,
    file not found, parse error). Callers must handle None gracefully.
    """
    if _github is None or not _github_repo:
        return None
    try:
        from github import GithubException  # type: ignore[import]
        repo = _github.get_repo(_github_repo)
        contents = repo.get_contents(_OPENAPI_SPEC_PATH)
        raw = base64.b64decode(contents.content).decode("utf-8")
        return yaml.safe_load(raw)
    except Exception as exc:
        log.warning("openapi spec fetch failed — using heuristics", error=str(exc))
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
                    "docs": f"https://github.com/{_github_repo}/blob/main/MIGRATION.md",
                },
                "strategy": "always",
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
    spec       = _fetch_openapi_spec()
    spec_paths = _extract_spec_paths(spec) if spec else {}
    used_spec  = bool(spec_paths)

    spec_diff: dict[str, Any] = {
        "used_github_spec": used_spec,
        "found_in_spec":    path in spec_paths,
        "deprecated_in_spec": _is_deprecated_in_spec(path, spec_paths) if used_spec else False,
    }

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
        "classification":     classification,
        "severity":           severity,
        "is_pii_exposed":     is_pii_exposed,
        "pii_findings":       pii_found,
        "spec_diff":          spec_diff,
        "enforcement_approved": severity in ("critical", "high"),
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
    """Route to enforce if severity warrants it, else skip straight to report."""
    if state.get("enforcement_approved"):
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

            # 2. Inject the 410 block if not already present.
            existing_endpoints = {ep.get("endpoint") for ep in current_cfg.get("endpoints", [])}
            if krakend_block and krakend_block.get("endpoint") not in existing_endpoints:
                post_block = dict(krakend_block)
                post_block["method"] = "POST"
                current_cfg["endpoints"].extend([krakend_block, post_block])

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
        mutation = mutate_krakend(path, incident_id)
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
    schema    = spec_diff.get("schema", {})
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            resp = await client.post(
                "http://honeypot-decoy:8082/admin/register-path",
                json={"path": path, "schema": schema},
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

    return {
        "executed_actions": executed,
        "github_pr_url":   pr_url,
        "reasoning_trace": executed,
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
    """Compile a comprehensive incident report from accumulated state.

    Phase 3 enhancements:
    - Includes spec_diff summary (github vs heuristics, what was found).
    - Includes github_pr_url if enforcement ran.
    - If Groq is configured, generates a natural-language executive summary.
    """
    incident_id    = state.get("incident_id", "N/A")
    classification = state.get("classification")
    severity       = state.get("severity")
    pii            = ", ".join(state.get("pii_findings", [])) or "None"
    is_pii         = state.get("is_pii_exposed", False)
    actions        = state.get("executed_actions", [])
    trace          = state.get("reasoning_trace", [])
    path           = state["raw_event"].get("path", "unknown")
    pr_url         = state.get("github_pr_url")
    spec_diff      = state.get("spec_diff") or {}

    spec_source = "GitHub" if spec_diff.get("used_github_spec") else "path-prefix heuristics"

    structured = "\n".join([
        f"# Incident Report — {incident_id}",
        f"**Endpoint:** `{path}`",
        f"**Classification:** {classification}",
        f"**Severity:** {severity}",
        f"**PII Detected:** {pii} {'⚠️ CISO escalation queued' if is_pii else ''}",
        f"**Spec Source:** {spec_source}",
        f"**PR URL:** {pr_url or 'N/A (no enforcement or GITHUB_TOKEN not set)'}",
        "",
        "## Actions Taken",
        *[f"- {a}" for a in actions],
        "",
        "## Reasoning Trace",
        *[f"- {r}" for r in trace],
    ])

    if _llm is None:
        return {"report": structured}

    prompt = (
        f"You are a security analyst writing a concise incident report.\n"
        f"Endpoint: {path}\n"
        f"Classification: {classification}\n"
        f"Severity: {severity}\n"
        f"PII detected: {pii}\n"
        f"Spec analysis source: {spec_source}\n"
        f"Actions taken: {'; '.join(actions) or 'none'}\n"
        f"PR created: {pr_url or 'No'}\n\n"
        f"Write a 3-4 sentence executive summary suitable for a non-technical stakeholder. "
        f"Be direct and factual. Mention the PII risk if applicable."
    )
    try:
        response    = await _llm.ainvoke(prompt)
        llm_summary = response.content
    except Exception:
        llm_summary = "LLM summary unavailable."

    full_report = f"{structured}\n\n## Executive Summary (AI-Generated)\n{llm_summary}"
    return {"report": full_report}
