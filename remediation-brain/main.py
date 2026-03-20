# main.py — AuralisAPI remediation-brain FastAPI Application Factory
#
# Lifespan management:
#   1. On startup: connect to PostgreSQL, initialise LangGraph checkpointer,
#      compile the incident response graph, attach to app.state.graph.
#   2. Start the Redis stream consumer as an asyncio background task. It reads
#      from auralis:events and dispatches each event through the LangGraph graph.
#   3. If PostgreSQL is unavailable (e.g. first boot before DB is ready),
#      fall back to in-memory checkpointer so the service stays healthy.
#   4. On shutdown: cancel the consumer task; AsyncPostgresSaver closes pool.
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agent.consumer import run_consumer
from agent.graph import build_graph, build_graph_in_memory, setup_postgres_checkpointer
from api.routes import router

log = structlog.get_logger()


async def _start_consumer(app: FastAPI) -> asyncio.Task:
    """Launch the Redis consumer as a background asyncio task."""
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
    stream = os.getenv("REDIS_STREAM", "auralis:events")
    task = asyncio.create_task(
        run_consumer(app.state, redis_url, stream),
        name="redis-consumer",
    )
    log.info("Redis consumer task started", stream=stream)
    return task


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan: initialise LangGraph with PostgreSQL checkpointer,
    then start the Redis stream consumer background task.

    The async context manager for AsyncPostgresSaver MUST span the entire
    application lifetime so the connection pool stays open while the app
    processes requests. The yield inside the `async with` block is what
    achieves this — FastAPI suspends the lifespan coroutine at yield,
    resumes it on shutdown, then __aexit__ closes the pool.
    """
    # LangGraph requires plain postgresql:// (psycopg3), not postgresql+asyncpg://
    raw_db_url = os.getenv(
        "LANGGRAPH_DB_URL",
        "postgresql://auralis:auralis@postgres:5432/auralis",
    )

    consumer_task: asyncio.Task | None = None

    try:
        checkpointer = await setup_postgres_checkpointer(raw_db_url)
        async with checkpointer:
            await checkpointer.setup()   # creates LangGraph checkpoint tables
            app.state.graph = build_graph(checkpointer=checkpointer)
            log.info(
                "remediation-brain started",
                checkpointer="postgres",
                db=raw_db_url.split("@")[-1],  # log only host/db, not credentials
            )
            consumer_task = await _start_consumer(app)
            yield
            consumer_task.cancel()
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass
        log.info("remediation-brain shut down — PostgreSQL pool closed")

    except Exception as exc:
        # Fallback: in-memory checkpointer when DB is unavailable.
        # State is lost on restart but the service remains operational.
        log.warning(
            "PostgreSQL unavailable — falling back to in-memory checkpointer",
            error=str(exc),
        )
        app.state.graph = build_graph_in_memory()
        log.info("remediation-brain started", checkpointer="memory")
        consumer_task = await _start_consumer(app)
        yield
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass
        log.info("remediation-brain shut down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="AuralisAPI Remediation Brain",
        description="Autonomous Zombie API discovery and remediation via LangGraph",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()
