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
from __future__ import annotations

import json
import os
import uuid
from typing import Any, Optional

import httpx
import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

try:
    from enforcement.krakend_mutator import mutate_krakend, read_gateway_state
    _MUTATOR_AVAILABLE = True
except ImportError:
    mutate_krakend = None  # type: ignore[assignment]
    read_gateway_state = None  # type: ignore[assignment]
    _MUTATOR_AVAILABLE = False

log = structlog.get_logger(__name__)
router = APIRouter()


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "remediation-brain"}


# ── Incidents ─────────────────────────────────────────────────────────────────

@router.get("/incidents", tags=["Incidents"])
async def list_incidents(request: Request, limit: int = 50):
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
        # LangGraph CompiledGraph exposes aget_state_history on the checkpointer.
        # We iterate over all stored thread checkpoints.
        async for config, metadata in _iter_checkpoints(graph, limit=limit):
            thread_id = config.get("configurable", {}).get("thread_id", "unknown")

            # Get the latest state for this thread.
            state_snapshot = await graph.aget_state(config)
            if state_snapshot is None:
                continue

            values = state_snapshot.values or {}
            next_nodes = list(state_snapshot.next or [])
            is_waiting = "enforce" in next_nodes  # interrupted before enforce

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
                "next":           next_nodes,
                "github_pr_url":  values.get("github_pr_url"),
                "report_summary": report_summary,
            })
    except Exception as exc:
        log.warning("incident listing failed", error=str(exc))
        # Return empty list rather than 500 — checkpointer may be empty on first boot.
        return {"incidents": [], "total": 0, "error": str(exc)}

    return {"incidents": incidents, "total": len(incidents)}


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

    if snapshot is None:
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
async def approve_incident(thread_id: str, request: Request, body: ApprovalRequest = ApprovalRequest()):
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

    if snapshot is None:
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
async def reject_incident(thread_id: str, request: Request, body: ApprovalRequest = ApprovalRequest()):
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

    if snapshot is None:
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
        },
        # Force the graph to jump to generate_report instead of enforce.
        as_node="plan",
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


# ── Remediation (manual trigger) ──────────────────────────────────────────────

class RemediateRequest(BaseModel):
    path: str
    method: str = "GET"
    reason: str = "manual"


@router.post("/remediate", tags=["Remediation"])
async def trigger_remediation(req: RemediateRequest, request: Request):
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

    try:
        await graph.ainvoke(initial_state, config=config)
    except Exception as exc:
        log.error("manual remediation failed", path=req.path, error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc

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
    zombies, shadows = 0, 0

    try:
        async for config, _ in _iter_checkpoints(graph, limit=200):
            snapshot = await graph.aget_state(config)
            if snapshot is None:
                continue
            values = snapshot.values or {}
            cls    = values.get("classification")
            path   = (values.get("raw_event") or {}).get("path", "unknown")
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

    return {"endpoints": endpoints, "total": len(endpoints), "zombies": zombies, "shadows": shadows}


# ── Phase 4: Gateway config inspection ────────────────────────────────────────

@router.get("/gateway/config", tags=["Gateway"])
async def get_gateway_config():
    """
    Return the live state of the locally-mounted krakend.json.

    Shows which endpoints are quarantined (returning 410 Gone) vs active.
    This reflects any mutations made by enforce_node without waiting for a
    PR to be reviewed and merged.
    """
    if not _MUTATOR_AVAILABLE:
        raise HTTPException(status_code=503, detail="Enforcement module unavailable")
    state = read_gateway_state()
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
    path:        str
    incident_id: str = ""
    schema:      dict = {}    # JSON schema for honeypot fake-data generation
    severity:    str = "high"


@router.post("/gateway/quarantine", tags=["Gateway"])
async def trigger_quarantine(body: QuarantineRequest):
    """
    Trigger an immediate local quarantine: mutate krakend.json AND register
    the path with the dynamic honeypot server.

    This endpoint is called by enforce_node internally, but can also be called
    directly from the dashboard or CI pipelines for manual quarantine actions.
    Idempotent — calling twice for the same path is safe.
    """
    if not _MUTATOR_AVAILABLE:
        raise HTTPException(status_code=503, detail="Enforcement module unavailable")

    incident_id = body.incident_id or str(uuid.uuid4())

    # 1. Mutate local krakend.json
    mutation = mutate_krakend(body.path, incident_id)

    # 2. Register with honeypot server (best-effort)
    honeypot_status = "skipped"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            resp = await client.post(
                "http://honeypot-decoy:8082/admin/register-path",
                json={"path": body.path, "schema": body.schema},
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
async def receive_honeypot_alert(payload: HoneypotAlertPayload):
    """
    Receive a deception hit from the dynamic honeypot server (honeypot_server.py).

    The honeypot fires this webhook every time an attacker probes a quarantined
    path. This endpoint:
      1. Publishes the event to the auralis:honeypot-events Redis stream.
      2. Logs the attacker details with structlog.

    The intelligence-ui polls this stream (or the /inventory endpoint) to display
    the threat intelligence dashboard.
    """
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
    stream    = "auralis:honeypot-events"

    event_data = {
        "event_type": "honeypot_hit",
        "src_ip":     payload.src_ip,
        "timestamp":  payload.timestamp,
        "method":     payload.method,
        "path":       payload.path,
        "node_id":    payload.node_id,
        "body_len":   str(len(payload.body)),
        "user_agent": payload.headers.get("user-agent", ""),
    }

    log.info(
        "honeypot hit received",
        src_ip=payload.src_ip,
        method=payload.method,
        path=payload.path,
        node_id=payload.node_id,
    )

    try:
        client = aioredis.from_url(redis_url, decode_responses=True)
        await client.xadd(stream, {"data": json.dumps(event_data)}, maxlen=1000, approximate=True)
        await client.aclose()
    except Exception as exc:
        log.warning("failed to publish honeypot event to Redis", error=str(exc))
        # Return 200 anyway — the honeypot server must not retry on Redis failures.

    return {"status": "received", "path": payload.path}


# ── Phase 5: Honeypot events feed ─────────────────────────────────────────────

@router.get("/honeypot/events", tags=["Honeypot"])
async def get_honeypot_events(limit: int = 50):
    """
    Return the most recent honeypot hit events from the auralis:honeypot-events Redis stream.
    Used by the intelligence dashboard threat intel feed.

    Events are returned newest-first (xrevrange). Each entry is the JSON payload
    published by receive_honeypot_alert. The stream uses MAXLEN ~= 1000 so it
    never grows unboundedly — this endpoint is safe to poll every 5 seconds.
    """
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
    try:
        client = aioredis.from_url(redis_url, decode_responses=True)
        raw_entries = await client.xrevrange("auralis:honeypot-events", count=limit)
        await client.aclose()
        events = []
        for _entry_id, fields in raw_entries:
            if "data" in fields:
                try:
                    events.append(json.loads(fields["data"]))
                except json.JSONDecodeError:
                    pass
        return {"events": events, "total": len(events)}
    except Exception as exc:
        log.warning("honeypot events fetch failed", error=str(exc))
        return {"events": [], "total": 0, "error": str(exc)}


# ── Internal helpers ───────────────────────────────────────────────────────────

async def _iter_checkpoints(graph, limit: int = 50):
    """
    Iterate over stored LangGraph checkpoints, yielding (config, metadata) pairs.

    LangGraph's AsyncPostgresSaver exposes alist() for enumerating thread IDs.
    The in-memory MemorySaver exposes .storage for direct dict access.
    Falls back gracefully when neither is available.
    """
    checkpointer = getattr(graph, "checkpointer", None)
    if checkpointer is None:
        return

    count = 0

    # AsyncPostgresSaver: alist() returns async iterator of CheckpointTuple
    if hasattr(checkpointer, "alist"):
        try:
            async for item in checkpointer.alist({}):
                if count >= limit:
                    break
                yield item.config, item.metadata
                count += 1
        except Exception as exc:
            log.warning("checkpoint alist failed", error=str(exc))
        return

    # MemorySaver: synchronous storage dict keyed by thread_id
    if hasattr(checkpointer, "storage"):
        for thread_id in list(checkpointer.storage.keys())[:limit]:
            yield {"configurable": {"thread_id": thread_id}}, {}
