# api/routes.py — FastAPI Route Definitions (Phase 3 + Phase 4 + Phase 5)
#
# Phase 3 endpoints:
#   GET  /incidents                    — list all incidents from LangGraph checkpoint store
#   GET  /incidents/{thread_id}        — full state snapshot for one incident
#   POST /incidents/{thread_id}/approve — resume graph past enforce interrupt (human approval)
#   POST /incidents/{thread_id}/reject  — skip enforce, route to report with rejection note
#   POST /remediate                    — manual workflow trigger
#   GET  /inventory                    — API inventory aggregated from all checkpoints
#
# Phase 4 endpoints:
#   GET  /gateway/config               — live krakend.json state (quarantined vs active)
#   POST /gateway/quarantine           — trigger local mutation + honeypot registration
#   POST /webhooks/honeypot-alert      — receive deception hit events, publish to Redis
#
# Phase 5 endpoints:
#   GET  /honeypot/events              — read recent honeypot hits from Redis stream
# NOTE: 'from __future__ import annotations' intentionally omitted.
# slowapi's @limiter.limit() wraps route functions via functools.wraps, but the
# wrapper's __globals__ is the slowapi module — not api.routes. With PEP 563
# (future annotations), all annotations become ForwardRef strings, and FastAPI
# resolves them using the wrapper's __globals__ where RemediateRequest etc. are
# not defined, leaving them as unresolved ForwardRefs treated as query params.
# Python 3.12 supports dict[str, Any], list[...] etc. natively, so the import
# is not needed.

import asyncio
import json
import os
import re
import uuid
from typing import Any, Optional

import httpx  # type: ignore[import]
import structlog  # type: ignore[import]
from fastapi import APIRouter, Depends, HTTPException, Request, status  # type: ignore[import]
from pydantic import BaseModel  # type: ignore[import]
from slowapi import Limiter  # type: ignore[import]
from slowapi.util import get_remote_address  # type: ignore[import]

from api.auth import require_auth

_limiter = Limiter(key_func=get_remote_address)

_VALID_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
_IP_RE = re.compile(
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}"          # IPv4
    r"|([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"  # IPv6 (simplified)
    r"|unknown"
    r")$"
)

try:
    from enforcement.krakend_mutator import mutate_krakend, read_gateway_state
    _MUTATOR_AVAILABLE = True
except ImportError:
    mutate_krakend = None  # type: ignore[assignment]
    read_gateway_state = None  # type: ignore[assignment]
    _MUTATOR_AVAILABLE = False

try:
    from agent.nodes import _fetch_openapi_spec, _extract_spec_paths
    _SPEC_AVAILABLE = True
except ImportError:
    _fetch_openapi_spec = None  # type: ignore[assignment]
    _extract_spec_paths = None  # type: ignore[assignment]
    _SPEC_AVAILABLE = False

log = structlog.get_logger(__name__)
router = APIRouter()


def _redis_url() -> str:
    """Build the Redis URL, including password when REDIS_PASSWORD env var is set."""
    password = os.getenv("REDIS_PASSWORD", "")
    host     = os.getenv("REDIS_HOST", "redis:6379")
    base     = os.getenv("REDIS_URL", f"redis://{host}")
    if password and "@" not in base:
        base = base.replace("redis://", f"redis://:{password}@", 1)
    return base


def _get_redis(request: Request):
    """
    Return a Redis client backed by the shared connection pool when available.
    Falls back to a per-request client when pool is not initialised (dev/test).
    Callers should use this as an async context manager:
        async with _get_redis(request) as client: ...
    """
    import redis.asyncio as _aioredis  # type: ignore[import]
    pool = getattr(request.app.state, "redis_pool", None)
    if pool:
        return _aioredis.Redis(connection_pool=pool)
    return _aioredis.from_url(_redis_url(), decode_responses=True)


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "remediation-brain"}


@router.get("/health/live", tags=["System"])
async def health_live():
    """Kubernetes/Docker liveness probe — always 200 if the process is running."""
    return {"status": "alive"}


@router.get("/health/ready", tags=["System"])
async def health_ready(request: Request):
    """
    Readiness probe — returns 200 only when all backing services are reachable.
    Checks: asyncpg pool (SELECT 1) + Redis pool (PING).
    Returns 503 with details when any dependency is down.
    """
    checks: dict[str, str] = {}
    healthy = True

    pool = getattr(request.app.state, "asyncpg_pool", None)
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            checks["postgres"] = "ok"
        except Exception as exc:
            checks["postgres"] = f"error: {exc}"
            healthy = False
    else:
        checks["postgres"] = "unavailable (no pool)"

    redis_pool = getattr(request.app.state, "redis_pool", None)
    if redis_pool is not None:
        try:
            import redis.asyncio as aioredis  # type: ignore[import]
            async with aioredis.Redis(connection_pool=redis_pool) as client:
                await client.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {exc}"
            healthy = False
    else:
        checks["redis"] = "unavailable (no pool)"

    status_code = 200 if healthy else 503
    from fastapi.responses import JSONResponse  # type: ignore[import]
    return JSONResponse(
        content={"status": "ready" if healthy else "degraded", "checks": checks},
        status_code=status_code,
    )


# ── Gone stub ─────────────────────────────────────────────────────────────────
# KrakenD 2.7 CE's proxy/static requires a 2xx from the backend to apply its
# static override. A 4xx backend response causes KrakenD to emit 500 instead.
# This stub returns 200; proxy/static overlays the "Gone" body. The resulting
# client response carries the static JSON but with a 200 status — a known
# KrakenD CE limitation. The brain's direct krakend_mutator injects real 410
# blocks for quarantined endpoints via a separate mechanism.
@router.get("/gone", tags=["System"])
@router.post("/gone", tags=["System"])
async def gone_stub():
    return {"status": "gone", "code": 410}


# ── Drift Stats Proxy ─────────────────────────────────────────────────────────
# The eBPF sensor (network_mode: host) exposes /drift/stats on port 9090.
# On Docker Desktop for Windows, host.docker.internal resolves to the Hyper-V
# VM gateway IP — not the Linux VM loopback — so bridge-network containers
# cannot reach the sensor directly. This proxy endpoint runs inside the brain
# container (bridge network) which also cannot reach the host network, BUT the
# sensor's port 9090 is published to the Docker host via host networking.
# We attempt to reach the sensor at SENSOR_METRICS_URL (default: host.docker.internal:9090)
# and fall back to an empty list when unavailable (graceful degradation).

SENSOR_URL = os.getenv("SENSOR_METRICS_URL", "http://host.docker.internal:9090")

# How many seconds of stream history to scan for per-endpoint counts.
_DRIFT_WINDOW_SECS = 60


@router.get("/drift/stats", tags=["Drift"])
async def proxy_drift_stats(request: Request):
    """
    Serve per-endpoint drift stats.

    Strategy (in priority order):
    1. Try the eBPF sensor's HTTP endpoint (real PH scores, zero-latency).
    2. Fall back to scanning the Redis stream for the last 60 seconds of
       ingress events and computing a simple per-endpoint request count
       (no PH score — ph_score is set to current_window as a proxy).

    This ensures the dashboard always shows real traffic data even when
    the sensor's HTTP port is unreachable from the bridge network.
    """
    # ── Strategy 1: Sensor HTTP (preferred) ───────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
            resp = await client.get(f"{SENSOR_URL}/drift/stats")
            if resp.status_code == 200:
                data = resp.json()
                if data:  # non-empty — sensor is serving real data
                    return data
    except Exception:
        pass  # fall through to Redis strategy

    # ── Strategy 2: Redis stream scan ─────────────────────────────────────────
    # Read recent stream entries and count ingress events per endpoint.
    import time as _t

    stream    = os.getenv("REDIS_STREAM", "auralis:events")
    cutoff_ms = int((_t.time() - _DRIFT_WINDOW_SECS) * 1000)
    min_id    = f"{cutoff_ms}-0"

    counts: dict[str, int] = {}
    try:
        async with _get_redis(request) as client:
            entries = await client.xrange(stream, min=min_id, max="+", count=500)
            for _eid, fields in entries:
                raw = fields.get("data", "")
                try:
                    payload = json.loads(raw)
                except Exception:
                    continue
                # Only count ingress events (traffic inbound to the API).
                if payload.get("direction") != "ingress":
                    continue
                path = payload.get("path", "")
                if path:
                    counts[path] = counts.get(path, 0) + 1
    except Exception as exc:
        log.warning("drift stats: redis scan failed", error=str(exc))
        return []

    # Build EndpointStats-shaped response compatible with the UI.
    now_ns = int(_t.time() * 1e9)
    return [
        {
            "endpoint":        path,
            "current_window":  count,
            "running_mean":    round(count / 6, 3),  # rough: 60s / 10s_window = 6 ticks
            "ph_score":        round(count / 2, 3),  # proxy score — not real PH
            "dormant":         count == 0,
            "dormant_windows": 0,
            "total_observations": 1,
            "source":          "redis_stream",        # signals UI this is not real PH
            "timestamp_ns":    now_ns,
        }
        for path, count in sorted(counts.items(), key=lambda x: -x[1])
    ]


@router.get("/drift/health", tags=["Drift"])
async def proxy_drift_health():
    """Proxy /drift/health from the eBPF sensor."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            resp = await client.get(f"{SENSOR_URL}/health")
            if resp.status_code == 200:
                return resp.json()
    except Exception as exc:
        log.warning("drift health proxy: sensor unreachable", url=SENSOR_URL, error=str(exc))
    return {"status": "unavailable", "sensor_url": SENSOR_URL}



# ── Incidents ─────────────────────────────────────────────────────────────────

@router.get("/incidents", tags=["Incidents"])
async def list_incidents(request: Request, limit: int = 50, deduplicate: bool = True):
    """
    List recent incidents from the LangGraph checkpoint store.

    Each entry includes the thread_id (incident ID), the endpoint path,
    classification, severity, and whether the graph is waiting for human
    approval (interrupted before enforce).
    """
    graph = getattr(request.app.state, "graph", None)
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    incidents: list[dict[str, Any]] = []
    try:
        # Use _iter_states_fast: reads channel_values directly from CheckpointTuple,
        # avoiding one aget_state() DB round-trip per thread (N+1 → O(1) queries).
        async for thread_id, values in _iter_states_fast(graph, limit=limit):
            severity      = (values.get("severity") or "").lower()
            has_plan      = bool(values.get("planned_actions"))
            has_report    = bool(values.get("report"))
            has_executed  = bool(values.get("executed_actions"))
            # Authoritative: __interrupt__ channel is set by LangGraph when the
            # graph pauses at an interrupt() call (i.e. awaiting human approval).
            has_interrupt = bool(values.get("__interrupt__"))
            # Fallback heuristic for checkpoints written before __interrupt__ was
            # captured or by MemorySaver variants that omit that channel.
            is_waiting = has_interrupt or (
                has_plan and not has_report and not has_executed
                and severity in ("critical", "high")
            )

            raw_report = values.get("report")
            report_summary: dict[str, Any] | None = None
            if isinstance(raw_report, dict):
                report_summary = {
                    "executive_summary":  raw_report.get("executive_summary"),
                    "risk_level":         raw_report.get("risk_level"),
                    "recommended_action": raw_report.get("recommended_action"),
                }

            incidents.append({
                "thread_id":      thread_id,
                "endpoint":       (values.get("raw_event") or {}).get("path", "unknown"),
                "classification": values.get("classification"),
                "severity":       values.get("severity"),
                "is_pii_exposed": values.get("is_pii_exposed", False),
                "status":         "awaiting_approval" if is_waiting else "completed",
                "next":           ["enforce"] if is_waiting else [],
                "github_pr_url":  values.get("github_pr_url"),
                "report_summary": report_summary,
            })
    except Exception as exc:
        log.warning("incident listing failed", error=str(exc))
        return {"incidents": [], "total": 0, "error": str(exc)}

    if not deduplicate:
        return {"incidents": incidents, "total": len(incidents)}

    # ── Deduplication: keep one incident per endpoint ─────────────────────────
    # Priority: awaiting_approval > completed (most recent wins within same status).
    seen: dict = {}
    for inc in incidents:
        ep = inc["endpoint"]
        if ep not in seen:
            seen[ep] = inc
        elif inc["status"] == "awaiting_approval" and seen[ep]["status"] != "awaiting_approval":
            seen[ep] = inc

    deduped = list(seen.values())
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
    deduped.sort(key=lambda i: (
        0 if i["status"] == "awaiting_approval" else 1,
        sev_order.get(i["severity"], 4),
    ))
    return {"incidents": deduped, "total": len(deduped)}


@router.get("/incidents/{thread_id}", tags=["Incidents"])
async def get_incident(thread_id: str, request: Request):
    """
    Return the full LangGraph state snapshot for a specific incident.

    Shows: classification, severity, pii_findings, planned_actions,
    executed_actions, reasoning_trace, spec_diff, github_pr_url, report.
    The 'next' field shows which node the graph is paused before (if any).
    """
    graph = getattr(request.app.state, "graph", None)
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    config = {"configurable": {"thread_id": thread_id}}
    try:
        snapshot = await graph.aget_state(config)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"State fetch failed: {exc}") from exc

    if not snapshot or not snapshot.values:
        raise HTTPException(status_code=404, detail=f"Incident '{thread_id}' not found")

    values     = snapshot.values or {}
    next_nodes = list(snapshot.next or [])

    return {
        "thread_id":        thread_id,
        "status":           "awaiting_approval" if "enforce" in next_nodes else "completed",
        "next":             next_nodes,
        "endpoint":         (values.get("raw_event") or {}).get("path", "unknown"),
        "classification":   values.get("classification"),
        "severity":         values.get("severity"),
        "is_pii_exposed":   values.get("is_pii_exposed", False),
        "pii_findings":     values.get("pii_findings", []),
        "planned_actions":  values.get("planned_actions", []),
        "executed_actions": values.get("executed_actions", []),
        "reasoning_trace":  values.get("reasoning_trace", []),
        "spec_diff":        values.get("spec_diff"),
        "github_pr_url":    values.get("github_pr_url"),
        "report":           values.get("report"),
    }


# ── Human-in-the-loop approval / rejection ────────────────────────────────────

class ApprovalRequest(BaseModel):
    notes: Optional[str] = None  # optional human reviewer notes appended to state


@router.post("/incidents/{thread_id}/approve", tags=["Incidents"])
async def approve_incident(thread_id: str, request: Request, body: ApprovalRequest = ApprovalRequest(), _user: str = Depends(require_auth)):
    """
    Resume the LangGraph graph past the enforce interrupt (human approval).

    Calling this is the ONLY way to trigger the EnforcerNode. Passing None
    as the state update resumes the graph from the checkpoint without
    modifying state — the interrupt is lifted and enforce runs normally.

    Optionally supply 'notes' which are appended to human_notes in state.
    """
    graph = getattr(request.app.state, "graph", None)
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    config = {"configurable": {"thread_id": thread_id}}

    # Verify the incident exists and is actually waiting for approval.
    try:
        snapshot = await graph.aget_state(config)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not snapshot or not snapshot.values:
        raise HTTPException(status_code=404, detail=f"Incident '{thread_id}' not found")

    if "enforce" not in list(snapshot.next or []):
        return {
            "status":    "already_processed",
            "thread_id": thread_id,
            "detail":    "This incident is not awaiting enforcement approval.",
        }

    # Append human notes to state if provided.
    if body.notes:
        await graph.aupdate_state(
            config,
            {"human_notes": [f"[approved] {body.notes}"]},
        )

    # Resume the graph — passing None continues from the checkpoint.
    try:
        await graph.ainvoke(None, config=config)
    except Exception as exc:
        log.error("enforce invocation failed after approval", thread_id=thread_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Enforce failed: {exc}") from exc

    # Fetch updated state to return PR URL.
    snapshot = await graph.aget_state(config)
    pr_url   = (snapshot.values or {}).get("github_pr_url")
    report   = (snapshot.values or {}).get("report")

    return {
        "status":        "enforced",
        "thread_id":     thread_id,
        "github_pr_url": pr_url,
        "report_preview": (report or {}).get("executive_summary", "")[:300] if isinstance(report, dict) else "",
    }


@router.post("/incidents/{thread_id}/reject", tags=["Incidents"])
async def reject_incident(thread_id: str, request: Request, body: ApprovalRequest = ApprovalRequest(), _user: str = Depends(require_auth)):
    """
    Reject enforcement — skip the enforce node and route directly to report.

    Updates state to set enforcement_approved=False and adds the rejection
    note, then resumes the graph. Because should_enforce will now return
    'report', the graph skips enforce and runs generate_report directly.
    """
    graph = getattr(request.app.state, "graph", None)
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    config = {"configurable": {"thread_id": thread_id}}

    try:
        snapshot = await graph.aget_state(config)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not snapshot or not snapshot.values:
        raise HTTPException(status_code=404, detail=f"Incident '{thread_id}' not found")

    if "enforce" not in list(snapshot.next or []):
        return {
            "status":    "already_processed",
            "thread_id": thread_id,
            "detail":    "This incident is not awaiting a decision.",
        }

    rejection_note = body.notes or "Enforcement rejected by human reviewer."
    await graph.aupdate_state(
        config,
        {
            "enforcement_approved": False,
            "human_notes":          [f"[rejected] {rejection_note}"],
            "executed_actions":     [f"[rejected] No enforcement actions taken — {rejection_note}"],
        },
        # as_node="enforce" tells LangGraph this update came from the enforce node,
        # so the graph's next pointer moves to ["generate_report"] instead of
        # re-evaluating should_enforce (which would route back to enforce again).
        as_node="enforce",
    )

    try:
        await graph.ainvoke(None, config=config)
    except Exception as exc:
        log.error("report generation failed after rejection", thread_id=thread_id, error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    snapshot = await graph.aget_state(config)
    return {
        "status":        "rejected",
        "thread_id":     thread_id,
        "rejection_note": rejection_note,
        "report_preview": ((snapshot.values or {}).get("report") or {}).get("executive_summary", "")[:300],
    }


# ── Demo seed ─────────────────────────────────────────────────────────────────

_DEMO_EVENTS = [
    {"method": "GET",  "path": "/api/v1/payments",
     "reason": "Deprecated v1 payment endpoint with live PII (card, CVV) exposure"},
    {"method": "GET",  "path": "/api/v1/users",
     "reason": "Deprecated v1 user endpoint leaking PII (email, SSN)"},
    {"method": "GET",  "path": "/legacy/export/users",
     "reason": "Undocumented shadow endpoint exporting bulk user PII"},
    {"method": "GET",  "path": "/api/v1/admin/config",
     "reason": "Internal admin config endpoint reachable externally"},
    {"method": "GET",  "path": "/api/v2/payments",
     "reason": "v2 payment endpoint with anomalous drift pattern"},
]


@router.post("/demo/seed", tags=["Demo"])
async def seed_demo_incidents(request: Request, _user: str = Depends(require_auth)):
    """
    Seed the dashboard with demo incidents for presentations.

    Triggers real LangGraph remediation workflows for 5 representative endpoints
    (zombie, shadow, drifting, internal). Each workflow runs asynchronously and
    the incident appears in the panel as the AI analysis completes (~30s each).
    Workflows are staggered 4s apart to avoid LLM rate-limit spikes.
    """
    graph = getattr(request.app.state, "graph", None)
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    seeded: list[dict[str, str]] = []

    for i, event in enumerate(_DEMO_EVENTS):
        thread_id = str(uuid.uuid4())
        config = {"configurable": {"thread_id": thread_id}}
        initial_state = {
            "raw_event":            event,
            "incident_id":          thread_id,
            "pii_findings":         [],
            "drift_scores":         [],
            "planned_actions":      [],
            "executed_actions":     [],
            "human_notes":          [],
            "reasoning_trace":      [],
            "enforcement_approved": False,
            "is_pii_exposed":       False,
            "spec_diff":            None,
            "github_pr_url":        None,
            "report":               None,
            "classification":       None,
            "severity":             None,
        }

        async def _run_demo(state=initial_state, cfg=config, path=event["path"], delay=i * 4.0):
            await asyncio.sleep(delay)
            try:
                await graph.ainvoke(state, config=cfg)
            except Exception as exc:
                log.warning("demo seed workflow failed", path=path, error=str(exc))

        asyncio.create_task(_run_demo())
        seeded.append({"thread_id": thread_id, "path": event["path"]})

    return {
        "status":   "seeding",
        "count":    len(seeded),
        "incidents": seeded,
        "message":  "Demo workflows started. Incidents will appear in /incidents as AI analysis completes (~30s per incident, staggered 4s apart).",
    }


# ── Remediation (manual trigger) ──────────────────────────────────────────────

class RemediateRequest(BaseModel):
    path: str
    method: str = "GET"
    reason: str = "manual"


@router.post("/remediate", tags=["Remediation"])
@_limiter.limit("10/minute")
async def trigger_remediation(req: RemediateRequest, request: Request, _user: str = Depends(require_auth)):
    """
    Manually trigger the LangGraph remediation workflow for a given API path.
    Returns a thread_id for async polling via GET /incidents/{thread_id}.
    """
    graph = getattr(request.app.state, "graph", None)
    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    thread_id = str(uuid.uuid4())
    config    = {"configurable": {"thread_id": thread_id}}
    initial_state = {
        "raw_event":           {"method": req.method, "path": req.path, "reason": req.reason},
        "incident_id":         thread_id,
        "pii_findings":        [],
        "drift_scores":        [],
        "planned_actions":     [],
        "executed_actions":    [],
        "human_notes":         [],
        "reasoning_trace":     [],
        "enforcement_approved": False,
        "is_pii_exposed":      False,
        "spec_diff":           None,
        "github_pr_url":       None,
        "report":              None,
        "classification":      None,
        "severity":            None,
    }

    # Fire-and-forget: return thread_id immediately so KrakenD doesn't timeout.
    # The full LangGraph workflow (LLM calls + checkpointing) can take 30-60s;
    # the client polls GET /incidents/{thread_id} for the result.
    async def _run():
        try:
            await graph.ainvoke(initial_state, config=config)
        except Exception as exc:
            log.error("manual remediation failed", path=req.path, error=str(exc))

    asyncio.create_task(_run())

    return {
        "status":     "queued",
        "thread_id":  thread_id,
        "path":       req.path,
        "poll_url":   f"/incidents/{thread_id}",
        "approve_url": f"/incidents/{thread_id}/approve",
    }


# ── API Inventory ─────────────────────────────────────────────────────────────

@router.get("/inventory", tags=["Inventory"])
async def get_inventory(request: Request):
    """
    Return the current API inventory snapshot from active incidents.
    Aggregates classification data from all stored LangGraph checkpoints.
    """
    graph = getattr(request.app.state, "graph", None)
    if graph is None:
        return {"endpoints": [], "total": 0, "zombies": 0, "shadows": 0}

    endpoints: list[dict[str, Any]] = []
    zombies, shadows, orphaned = 0, 0, 0

    try:
        async for _, values in _iter_states_fast(graph, limit=200):
            cls  = values.get("classification")
            path = (values.get("raw_event") or {}).get("path", "unknown")
            if not path or path == "unknown":
                continue
            if cls in ("active_zombie", "dormant_zombie"):
                zombies += 1
            elif cls == "shadow":
                shadows += 1
            endpoints.append({
                "path":           path,
                "classification": cls,
                "severity":       values.get("severity"),
                "is_pii_exposed": values.get("is_pii_exposed", False),
            })
    except Exception as exc:
        log.warning("inventory aggregation failed", error=str(exc))

    # Orphaned detection: spec-documented paths that have never appeared in traffic.
    # Hard 10s timeout so a slow GitHub API call never blocks the inventory response.
    if _SPEC_AVAILABLE and _fetch_openapi_spec is not None and _extract_spec_paths is not None:
        _fos, _esp = _fetch_openapi_spec, _extract_spec_paths
        try:
            spec = await asyncio.wait_for(asyncio.to_thread(_fos), timeout=10.0)
            spec_paths = _esp(spec) if spec else {}
            seen = {ep["path"] for ep in endpoints}
            for spec_path in spec_paths:
                if spec_path not in seen:
                    orphaned += 1
                    endpoints.append({
                        "path":           spec_path,
                        "classification": "orphaned",
                        "severity":       "low",
                        "is_pii_exposed": False,
                    })
        except asyncio.TimeoutError:
            log.warning("orphaned detection timed out — skipping")
        except Exception as exc:
            log.warning("orphaned detection failed", error=str(exc))

    return {
        "endpoints": endpoints,
        "total":     len(endpoints),
        "zombies":   zombies,
        "shadows":   shadows,
        "orphaned":  orphaned,
    }


# ── Phase 4: Gateway config inspection ────────────────────────────────────────

@router.get("/gateway/config", tags=["Gateway"])
async def get_gateway_config():
    """
    Return the live state of the locally-mounted krakend.json.

    Shows which endpoints are quarantined (returning 410 Gone) vs active.
    This reflects any mutations made by enforce_node without waiting for a
    PR to be reviewed and merged.
    """
    if not _MUTATOR_AVAILABLE or read_gateway_state is None:
        raise HTTPException(status_code=503, detail="Enforcement module unavailable")
    # read_gateway_state() does file I/O — run in thread pool to avoid blocking
    # the asyncio event loop.
    _rgs = read_gateway_state
    state = await asyncio.to_thread(_rgs)
    return {
        "config_path":         os.getenv("KRAKEND_CONFIG_PATH", "/app/krakend.json"),
        "total_endpoints":     state["total"],
        "quarantined":         state["quarantined"],
        "quarantined_count":   len(state["quarantined"]),
        "active":              state["active"],
        "active_count":        len(state["active"]),
        "parse_ok":            state["raw_ok"],
        "error":               state["error"] or None,
    }


# ── Phase 4: Internal quarantine trigger ──────────────────────────────────────

class QuarantineRequest(BaseModel):
    path:            str
    incident_id:     str  = ""
    response_schema: dict = {}    # JSON schema for honeypot fake-data generation
    severity:        str  = "high"


@router.post("/gateway/quarantine", tags=["Gateway"])
async def trigger_quarantine(body: QuarantineRequest, _user: str = Depends(require_auth)):
    """
    Trigger an immediate local quarantine: mutate krakend.json AND register
    the path with the dynamic honeypot server.

    This endpoint is called by enforce_node internally, but can also be called
    directly from the dashboard or CI pipelines for manual quarantine actions.
    Idempotent — calling twice for the same path is safe.
    """
    if not _MUTATOR_AVAILABLE or mutate_krakend is None:
        raise HTTPException(status_code=503, detail="Enforcement module unavailable")

    incident_id = body.incident_id or str(uuid.uuid4())

    # 1. Mutate local krakend.json (synchronous file I/O — run in thread pool)
    _mk = mutate_krakend
    mutation = await asyncio.to_thread(_mk, body.path, incident_id)

    # 2. Register with honeypot server (best-effort)
    honeypot_status = "skipped"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            resp = await client.post(
                "http://honeypot-decoy:8082/admin/register-path",
                json={"path": body.path, "response_schema": body.response_schema},
            )
            honeypot_status = "registered" if resp.status_code in (200, 201) else f"http_{resp.status_code}"
    except Exception as exc:
        honeypot_status = f"error: {exc}"
        log.warning("honeypot registration from /gateway/quarantine failed", error=str(exc))

    log.info(
        "quarantine triggered via API",
        path=body.path,
        incident_id=incident_id,
        mutation_success=mutation.success,
        honeypot_status=honeypot_status,
    )

    return {
        "path":             body.path,
        "incident_id":      incident_id,
        "mutation":         mutation.to_dict(),
        "honeypot_status":  honeypot_status,
        "severity":         body.severity,
    }


# ── Phase 4: Honeypot webhook ingestion ───────────────────────────────────────

class HoneypotAlertPayload(BaseModel):
    src_ip:    str
    timestamp: str
    method:    str
    path:      str
    headers:   dict = {}
    body:      str  = ""
    node_id:   str  = "unknown"


@router.post("/webhooks/honeypot-alert", tags=["Webhooks"])
async def receive_honeypot_alert(payload: HoneypotAlertPayload, request: Request):
    """
    Receive a deception hit from the dynamic honeypot server.
    Input is sanitized before publishing to Redis via the shared connection pool.
    """
    stream = "auralis:honeypot-events"

    # Sanitize inputs before storing in Redis stream
    src_ip  = payload.src_ip if _IP_RE.match(payload.src_ip) else "invalid"
    method  = payload.method.upper() if payload.method.upper() in _VALID_HTTP_METHODS else "UNKNOWN"
    path    = payload.path[:512].replace("\x00", "")  # truncate + strip null bytes
    body    = payload.body[:4096]

    event_data = {
        "event_type": "honeypot_hit",
        "src_ip":     src_ip,
        "timestamp":  payload.timestamp[:64],
        "method":     method,
        "path":       path,
        "node_id":    payload.node_id[:64],
        "body_len":   str(len(body)),
        "user_agent": payload.headers.get("user-agent", "")[:256],
    }

    log.info(
        "honeypot hit received",
        src_ip=payload.src_ip,
        method=payload.method,
        path=payload.path,
        node_id=payload.node_id,
    )

    try:
        async with _get_redis(request) as client:
            await client.xadd(stream, {"data": json.dumps(event_data)}, maxlen=1000, approximate=True)
    except Exception as exc:
        log.warning("failed to publish honeypot event to Redis", error=str(exc))
        # Return 200 anyway — the honeypot server must not retry on Redis failures.

    return {"status": "received", "path": payload.path}


# ── Phase 5: Honeypot events feed ─────────────────────────────────────────────

@router.get("/honeypot/events", tags=["Honeypot"])
async def get_honeypot_events(request: Request, limit: int = 50):
    """
    Return the most recent honeypot hit events from the auralis:honeypot-events Redis stream.
    Events are returned newest-first (xrevrange), via the shared connection pool.
    """
    try:
        async with _get_redis(request) as client:
            raw_entries = await client.xrevrange("auralis:honeypot-events", count=limit)
        _NOISE_PATHS = frozenset({"/favicon.ico", "/favicon.png", "/robots.txt", "/sitemap.xml"})
        events = []
        for _entry_id, fields in raw_entries:
            if "data" in fields:
                try:
                    evt = json.loads(fields["data"])
                    if evt.get("path") not in _NOISE_PATHS:
                        events.append(evt)
                except json.JSONDecodeError:
                    pass
        return {"events": events, "total": len(events)}
    except Exception as exc:
        log.warning("honeypot events fetch failed", error=str(exc))
        return {"events": [], "total": 0, "error": str(exc)}


# ── Company Sensor Registry (install.sh / remote sensor onboarding) ───────────
#
# Sensors register via POST /sensor/register and receive a bearer token.
# Registrations are persisted to PostgreSQL via db.sensors.SensorRegistry
# (in-memory fallback when DB is unavailable).

async def _validate_sensor_token(request: Request) -> str:
    """
    Validate a sensor bearer token against the SensorRegistry.
    Uses the shared registry (PostgreSQL-backed or in-memory fallback).
    Returns sensor_id on success, raises 401 on failure.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sensor token required")
    token = auth_header.split("Bearer ", 1)[1].strip()
    registry = getattr(request.app.state, "sensor_registry", None)
    if registry is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Sensor registry not ready")
    sensor_id = await registry.get_sensor_id_for_token(token)
    if sensor_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or invalid sensor token")
    return sensor_id


class SensorRegistration(BaseModel):
    sensor_id: str
    hostname: str
    mode: str = "live"
    version: str = "1.0.0"


@router.post("/sensor/register", tags=["Sensor Onboarding"])
async def register_sensor(payload: SensorRegistration, request: Request):
    """
    Called by the eBPF sensor on startup when BRAIN_URL is configured.
    Returns a sensor_token that must be sent as 'Authorization: Bearer <token>'
    on all subsequent /sensor/ingest calls.
    Registrations are persisted to PostgreSQL (in-memory fallback when DB is down).
    """
    registry  = request.app.state.sensor_registry
    sensor_id = payload.sensor_id or f"sensor-{uuid.uuid4().hex[:8]}"
    token     = str(uuid.uuid4())
    ip        = request.client.host if request.client else "unknown"

    await registry.register(
        sensor_id=sensor_id,
        token=token,
        hostname=payload.hostname,
        mode=payload.mode,
        version=payload.version,
        ip=ip,
    )
    log.info("sensor registered", sensor_id=sensor_id, hostname=payload.hostname)
    return {"status": "registered", "sensor_id": sensor_id, "sensor_token": token}


@router.post("/sensor/ingest", tags=["Sensor Onboarding"])
@_limiter.limit("120/minute")
async def ingest_sensor_event(request: Request):
    """
    Accepts raw event JSON forwarded by a remote eBPF sensor.
    Requires 'Authorization: Bearer <sensor_token>' from /sensor/register.
    Publishes the event to the Redis stream via the shared connection pool.
    """
    sensor_id = await _validate_sensor_token(request)
    try:
        body       = await request.body()
        event_data = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Persist last_seen + increment counter (non-blocking best-effort)
    asyncio.create_task(request.app.state.sensor_registry.touch(sensor_id))

    event_data.setdefault("event_type", "http_event")

    stream = os.getenv("REDIS_STREAM", "auralis:events")
    try:
        async with _get_redis(request) as client:
            await client.xadd(stream, {"data": json.dumps(event_data)}, maxlen=10000, approximate=True)
    except Exception as exc:
        log.warning("sensor ingest: redis publish failed", error=str(exc))
        raise HTTPException(status_code=503, detail="Redis unavailable")

    return {"status": "accepted"}


@router.get("/sensors", tags=["Sensor Onboarding"])
async def list_sensors(request: Request):
    """Returns all registered remote sensors (sensor_token excluded)."""
    registry = request.app.state.sensor_registry
    sensors  = await registry.list_all()
    return {"sensors": sensors, "total": len(sensors)}


# ── Internal helpers ───────────────────────────────────────────────────────────

async def _iter_checkpoints(graph, limit: int = 50):
    """
    Iterate over stored LangGraph checkpoints, yielding (config, metadata) pairs.

    LangGraph's AsyncPostgresSaver exposes alist() for enumerating thread IDs.
    The in-memory MemorySaver exposes .storage for direct dict access.
    Falls back gracefully when neither is available.

    Deduplicates by thread_id — alist() returns newest-first, so the first
    checkpoint seen per thread is always the latest state, avoiding redundant
    aget_state() calls for older checkpoint versions of the same thread.
    """
    checkpointer = getattr(graph, "checkpointer", None)
    if checkpointer is None:
        return

    seen_threads: set[str] = set()
    count = 0

    # AsyncPostgresSaver: alist() returns async iterator of CheckpointTuple newest-first
    if hasattr(checkpointer, "alist"):
        try:
            async for item in checkpointer.alist({}):
                if count >= limit:
                    break
                thread_id = (item.config.get("configurable") or {}).get("thread_id", "")
                if thread_id in seen_threads:
                    continue
                seen_threads.add(thread_id)
                yield item.config, item.metadata
                count += 1
        except Exception as exc:
            log.warning("checkpoint alist failed", error=str(exc))
        return

    # MemorySaver: synchronous storage dict keyed by thread_id
    if hasattr(checkpointer, "storage"):
        for thread_id, versions in list(checkpointer.storage.items())[:limit]:
            yield {"configurable": {"thread_id": thread_id}}, {}


async def _iter_states_fast(graph, limit: int = 200):
    """
    Fast O(1-DB-call) inventory scan.

    alist() streams CheckpointTuples newest-first. We deduplicate by thread_id
    so we get only the LATEST checkpoint per thread, and read channel_values
    directly from the tuple — avoiding one aget_state() round-trip per thread.
    """
    checkpointer = getattr(graph, "checkpointer", None)
    if checkpointer is None:
        return

    seen: set[str] = set()
    count = 0

    if hasattr(checkpointer, "alist"):
        try:
            async for item in checkpointer.alist({}):
                cfg        = item.config or {}
                thread_id  = (cfg.get("configurable") or {}).get("thread_id", "")
                if not thread_id or thread_id in seen:
                    continue
                seen.add(thread_id)
                values = ((item.checkpoint or {}).get("channel_values") or {})
                yield thread_id, values
                count += 1
                if count >= limit:
                    break
        except Exception as exc:
            log.warning("fast checkpoint iteration failed", error=str(exc))
        return

    # MemorySaver fallback
    # MemorySaver.storage is {thread_id: {checkpoint_id: CheckpointTuple}}
    # CheckpointTuple is a namedtuple: (config, checkpoint, metadata, parent_config)
    # Iteration order = insertion order, so last value = latest checkpoint.
    if hasattr(checkpointer, "storage"):
        for thread_id, versions in list(checkpointer.storage.items())[:limit]:
            if not versions:
                continue
            # Get the latest checkpoint (last inserted entry).
            latest_tuple = list(versions.values())[-1]
            # CheckpointTuple index 1 = checkpoint dict with channel_values.
            checkpoint_dict = latest_tuple[1] if (isinstance(latest_tuple, (list, tuple)) and len(latest_tuple) > 1) else {}
            values = (checkpoint_dict.get("channel_values") or {}) if isinstance(checkpoint_dict, dict) else {}
            yield thread_id, values
