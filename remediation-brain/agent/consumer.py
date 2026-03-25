# agent/consumer.py — Redis Streams consumer for the remediation-brain
#
# Reads events from the auralis:events Redis stream and routes them through
# the LangGraph incident response workflow.
#
# Event routing:

#   event_type == "drift_alert"  → high-priority incident (resurrection / ph_threshold)
#   all other events             → standard HTTP event incident workflow
#
# The consumer uses a consumer group (auralis-brain) so that multiple brain
# replicas can process events in parallel without duplication. Each event is
# acknowledged (XACK) only after the graph invocation completes (or errors),
# preventing loss of unprocessed events on restart.
#
# Consumer group creation is idempotent — XGROUP CREATE with MKSTREAM is called
# at startup and the BUSYGROUP error is silently ignored if the group exists.
from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any

import structlog
import redis.asyncio as aioredis

log = structlog.get_logger(__name__)

# Consumer group and consumer name (stable across restarts for the same replica).
_GROUP_NAME = "auralis-brain"
_CONSUMER_NAME = os.getenv("HOSTNAME", "brain-0")  # unique per pod/container

# How long (ms) to block waiting for new stream entries before looping.
_BLOCK_MS = 5_000

# Maximum events to fetch per XREADGROUP call.
_COUNT = 10


async def _ensure_consumer_group(client: aioredis.Redis, stream: str) -> None:
    """Create the consumer group if it does not already exist.

    Uses MKSTREAM so the stream is also created if absent (avoids a race
    between the sensor first publish and the brain startup).
    """
    try:
        await client.xgroup_create(stream, _GROUP_NAME, id="0", mkstream=True)
        log.info("consumer group created", stream=stream, group=_GROUP_NAME)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            log.debug("consumer group already exists", stream=stream, group=_GROUP_NAME)
        else:
            raise


async def _process_event(
    graph: Any,
    event_id: str,
    raw_data: str,
) -> None:
    """Parse one stream entry and invoke the LangGraph workflow.

    For drift_alert events the raw_event dict includes all DriftAlert fields
    (endpoint, alarm_type, ph_score etc.) which the classify/assess_risk nodes
    use for routing. The ingest node normalises both event shapes via the
    'path' key (mapped from 'endpoint' for drift events here).
    """
    try:
        payload = json.loads(raw_data)
    except (json.JSONDecodeError, TypeError):
        log.warning("skipping unparseable stream entry", event_id=event_id, raw=raw_data)
        return

    # Normalise: drift_alert uses 'endpoint'; HTTP events use 'path'.
    # Set 'path' from 'endpoint' so nodes.py path-based logic works uniformly.
    event_type = payload.get("event_type", "http_event")
    if event_type == "drift_alert" and "path" not in payload:
        payload["path"] = payload.get("endpoint", "")

    thread_id = str(uuid.uuid4())
    initial_state = {
        "raw_event":           payload,
        "incident_id":         thread_id,
        "pii_findings":        [],
        "drift_scores":        [],
        "planned_actions":     [],
        "executed_actions":    [],
        "human_notes":         [],
        "reasoning_trace":     [],
        "enforcement_approved": False,
        "is_pii_exposed":      False,   # Phase 3
        "spec_diff":           None,    # Phase 3
        "github_pr_url":       None,    # Phase 3
        "report":              None,
        "classification":      None,
        "severity":            None,
    }

    config = {"configurable": {"thread_id": thread_id}}

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
    each event through the LangGraph graph stored in app_state.graph.

    Intended to be launched as an asyncio task from the FastAPI lifespan.
    Runs until cancelled (asyncio.CancelledError) which happens on shutdown.

    Args:
        app_state: FastAPI app.state object; app_state.graph must be set before
                   this coroutine is awaited.
        redis_url: Redis connection URL (e.g. "redis://redis:6379").
        stream:    Redis stream key to consume from.
    """
    client = aioredis.from_url(redis_url, decode_responses=True)
    try:
        await _ensure_consumer_group(client, stream)
        log.info("Redis consumer started", stream=stream, group=_GROUP_NAME)

        while True:
            # XREADGROUP: block up to _BLOCK_MS ms, fetch up to _COUNT messages.
            # ">" means "deliver only new, undelivered messages to this consumer".
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
                # Timeout — no new messages; loop back and block again.
                continue

            for _stream_key, messages in entries:
                for event_id, fields in messages:
                    raw_data = fields.get("data", "")
                    graph = getattr(app_state, "graph", None)
                    if graph is None:
                        log.warning("graph not ready, skipping event", event_id=event_id)
                        # ACK anyway to avoid redelivery loop when graph is missing.
                        await client.xack(stream, _GROUP_NAME, event_id)
                        continue

                    await _process_event(graph, event_id, raw_data)

                    # Acknowledge the message — only after successful processing.
                    await client.xack(stream, _GROUP_NAME, event_id)

    except asyncio.CancelledError:
        log.info("Redis consumer shutting down")
    finally:
        await client.aclose()
