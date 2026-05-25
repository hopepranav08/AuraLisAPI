# agent/consumer.py — Redis Streams consumer for the remediation-brain
#
# FIXES applied:
#   C1: Pre-filter events — only invoke LangGraph for security-relevant events
#       (drift_alerts + HTTP events on deprecated/shadow paths). Healthy v3
#       traffic is counted but NOT routed through the full incident graph.
#   C2: Consumer group uses id="$" on creation so a fresh brain does NOT replay
#       historical stream events. Existing groups are left as-is (BUSYGROUP).
#   M4: Each event is dispatched as an asyncio background Task (fire-and-forget)
#       so the consumer loop never blocks waiting for a workflow to complete.
#       A bounded semaphore caps concurrent graph invocations at MAX_CONCURRENT.
from __future__ import annotations

import asyncio
import json
import os
import time as _time
import uuid
from typing import Any

import structlog  # type: ignore[import]
import redis.asyncio as aioredis  # type: ignore[import]

log = structlog.get_logger(__name__)

# Consumer group and consumer name (stable across restarts for the same replica).
_GROUP_NAME    = "auralis-brain"
_CONSUMER_NAME = os.getenv("HOSTNAME", "brain-0")  # unique per pod/container

# How long (ms) to block waiting for new stream entries before looping.
_BLOCK_MS = 5_000

# Maximum events to fetch per XREADGROUP call.
_COUNT = 10

# Maximum concurrent LangGraph invocations — prevents event storm overload.
_MAX_CONCURRENT = 4

# Seconds to wait for in-flight graph invocations to finish on SIGTERM before
# force-cancelling them. PostgreSQL checkpointing means partial state is safe.
_MAX_DRAIN_SECONDS: float = float(os.getenv("MAX_DRAIN_SECONDS", "30"))

# ── Per-path deduplication window ─────────────────────────────────────────────
# Prevents creating one LangGraph incident per Redis event when a deprecated
# endpoint receives a burst of traffic (e.g. 20 attack requests in 3 seconds
# or a real company's 1000 deprecated-path hits per day).
#
# drift_alerts are exempt — the PH engine only fires on real anomalies and
# each alert carries unique alarm context that warrants a separate incident.
_DEDUP_WINDOW_SECS: float = 60.0
_recent_paths: dict[str, float] = {}   # path → last_processed epoch seconds


def _is_duplicate(payload: dict[str, Any]) -> bool:
    """Return True if an incident was already dispatched for this path within the dedup window."""
    if payload.get("event_type") == "drift_alert":
        return False  # drift alerts always warrant a new incident
    path = payload.get("path", "")
    if not path:
        return False
    now = _time.time()
    last = _recent_paths.get(path)
    if last is not None and (now - last) < _DEDUP_WINDOW_SECS:
        return True
    _recent_paths[path] = now
    # Evict stale entries to bound memory usage.
    if len(_recent_paths) > 500:
        cutoff = now - _DEDUP_WINDOW_SECS * 2
        for k in [k for k, v in _recent_paths.items() if v < cutoff]:
            del _recent_paths[k]
    return False


# ── Path-prefix security filter ───────────────────────────────────────────────
# Paths in these prefixes represent deprecated API versions — any traffic to
# them warrants a full incident workflow.
_DEPRECATED_PREFIXES = (
    "/api/v0/", "/api/v1/", "/api/v2/",
    "/legacy/", "/old/", "/v0/", "/v1/",
)

# Paths matching these prefixes are "current" — healthy traffic, skip workflow.
_CURRENT_PREFIXES = (
    "/api/v3/", "/api/v4/", "/health", "/metrics",
)

# High-signal path fragments that always warrant investigation regardless of version.
_SENSITIVE_FRAGMENTS = (
    "/admin/", "/internal/", "/debug/", "/config",
    "/auth/", "/login", "/token", "/secret",
)


def _should_process(payload: dict[str, Any]) -> bool:
    """
    Return True if this event warrants a full LangGraph incident workflow.

    Rules (in priority order):
    1. drift_alert events → ALWAYS process (PH engine only fires on real anomalies)
    2. Current-version healthy paths (v3+) → SKIP unless they hit sensitive fragments
    3. Deprecated-version paths (v0, v1, v2) → ALWAYS process
    4. Paths not matching any known prefix → process (shadow API candidate)

    This prevents the brain from burning Groq tokens on every /api/v3/users 200 OK.
    """
    event_type = payload.get("event_type", "http_event")

    # Rule 1: drift alerts always trigger
    if event_type == "drift_alert":
        return True

    path = payload.get("path", "")

    # Rule 2: current-version paths — check for sensitive fragments first
    if any(path.startswith(p) for p in _CURRENT_PREFIXES):
        return any(frag in path for frag in _SENSITIVE_FRAGMENTS)

    # Rule 3: deprecated-version paths
    if any(path.startswith(p) for p in _DEPRECATED_PREFIXES):
        return True

    # Rule 4: unknown prefix → possible shadow API
    return True


async def _ensure_consumer_group(client: aioredis.Redis, stream: str) -> None:
    """Create the consumer group starting from '$' (new messages only).

    Using id="$" means a freshly-restarted brain does NOT replay all historical
    stream events — it only consumes events published after startup.

    If the group already exists (BUSYGROUP) we leave it as-is so a gracefully-
    restarted brain resumes from its last acknowledged message.
    """
    try:
        # id="$" — only new messages after group creation
        await client.xgroup_create(stream, _GROUP_NAME, id="$", mkstream=True)
        log.info("consumer group created (fresh start — new messages only)",
                 stream=stream, group=_GROUP_NAME)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            log.debug("consumer group already exists — resuming from last ACK",
                      stream=stream, group=_GROUP_NAME)
        else:
            raise


async def _process_event(
    graph: Any,
    event_id: str,
    raw_data: str,
    semaphore: asyncio.Semaphore,
) -> None:
    """Parse one stream entry, apply security filter, and invoke LangGraph if relevant.

    Wrapped in a semaphore to cap concurrent graph invocations at _MAX_CONCURRENT.
    """
    try:
        payload = json.loads(raw_data)
    except (json.JSONDecodeError, TypeError):
        log.warning("skipping unparseable stream entry", event_id=event_id, raw=raw_data[:200])
        return

    # ── Security relevance filter (Fix C1) ────────────────────────────────────
    if not _should_process(payload):
        log.debug("event filtered — not security-relevant",
                  path=payload.get("path"), event_type=payload.get("event_type"))
        return

    # ── Per-path deduplication ─────────────────────────────────────────────────
    # Skip HTTP events for a path we already dispatched an incident for within
    # the last 60 seconds. Prevents burst traffic (e.g. 20 attack requests in
    # 3s, or thousands of deprecated-path hits per day) from creating thousands
    # of identical incidents. drift_alerts are always processed.
    if _is_duplicate(payload):
        log.debug("event deduplicated — incident already dispatched for this path recently",
                  path=payload.get("path"))
        return

    # Normalise: drift_alert uses 'endpoint'; HTTP events use 'path'.
    event_type = payload.get("event_type", "http_event")
    payload.setdefault("event_type", event_type)   # ensure field always present in raw_event
    if event_type == "drift_alert" and "path" not in payload:
        payload["path"] = payload.get("endpoint", "")

    thread_id = str(uuid.uuid4())
    initial_state = {
        "raw_event":            payload,
        "incident_id":          thread_id,
        "pii_findings":         [],
        "drift_scores":         [],
        "planned_actions":      [],
        "executed_actions":     [],
        "human_notes":          [],
        "reasoning_trace":      [],
        "enforcement_approved": False,   # NEVER pre-approved — human must call /approve
        "is_pii_exposed":       False,
        "spec_diff":            None,
        "github_pr_url":        None,
        "report":               None,
        "classification":       None,
        "severity":             None,
    }

    config = {"configurable": {"thread_id": thread_id}}

    async with semaphore:
        try:
            await graph.ainvoke(initial_state, config=config)
            log.info(
                "incident workflow completed",
                thread_id=thread_id,
                event_type=event_type,
                path=payload.get("path", ""),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.error(
                "incident workflow error",
                thread_id=thread_id,
                event_type=event_type,
                error=str(exc),
            )


async def run_consumer(app_state: Any, redis_url: str, stream: str) -> None:
    """
    Background coroutine that reads from the Redis stream and dispatches
    each security-relevant event through the LangGraph graph.

    Design:
    - Consumer group starts at '$' (new messages only) on fresh creation.
    - Events are pre-filtered before LangGraph invocation (Fix C1).
    - Each event is dispatched as a background asyncio Task (Fix M4).
    - A semaphore bounds concurrent graph invocations (Fix M4).
    - Runs until asyncio.CancelledError (FastAPI shutdown).
    """
    client = aioredis.from_url(redis_url, decode_responses=True)
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT)

    # Track background tasks to allow clean shutdown.
    background_tasks: set[asyncio.Task] = set()  # type: ignore[type-arg]

    try:
        await _ensure_consumer_group(client, stream)
        log.info("Redis consumer started", stream=stream, group=_GROUP_NAME,
                 max_concurrent=_MAX_CONCURRENT)

        while True:
            try:
                entries = await client.xreadgroup(
                    _GROUP_NAME,
                    _CONSUMER_NAME,
                    {stream: ">"},
                    count=_COUNT,
                    block=_BLOCK_MS,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("xreadgroup error — retrying in 2s", error=str(exc))
                await asyncio.sleep(2)
                continue

            if not entries:
                continue  # timeout, loop back

            for _stream_key, messages in entries:
                for event_id, fields in messages:
                    raw_data = fields.get("data", "")
                    graph = getattr(app_state, "graph", None)
                    if graph is None:
                        log.warning("graph not ready, skipping event", event_id=event_id)
                        await client.xack(stream, _GROUP_NAME, event_id)
                        continue

                    # ACK immediately — we don't want re-delivery on crash
                    # (the graph has its own PostgreSQL checkpointing for durability).
                    await client.xack(stream, _GROUP_NAME, event_id)

                    # Dispatch as background task (Fix M4 — non-blocking consumer loop).
                    task = asyncio.create_task(
                        _process_event(graph, event_id, raw_data, semaphore)
                    )
                    background_tasks.add(task)
                    task.add_done_callback(background_tasks.discard)

    except asyncio.CancelledError:
        pending = len(background_tasks)
        log.info("Redis consumer shutting down — draining in-flight tasks",
                 pending=pending, timeout_s=_MAX_DRAIN_SECONDS)
        if background_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*background_tasks, return_exceptions=True),
                    timeout=_MAX_DRAIN_SECONDS,
                )
                log.info("consumer drain complete", drained=pending)
            except asyncio.TimeoutError:
                log.warning(
                    "consumer drain timed out — force-cancelling remaining tasks",
                    remaining=len([t for t in background_tasks if not t.done()]),
                )
                for task in background_tasks:
                    task.cancel()
    finally:
        await client.aclose()
