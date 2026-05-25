# main.py — AuralisAPI remediation-brain FastAPI Application Factory
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import structlog  # type: ignore[import]
from fastapi import FastAPI  # type: ignore[import]
from fastapi.middleware.cors import CORSMiddleware  # type: ignore[import]
from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore[import]
from slowapi.errors import RateLimitExceeded  # type: ignore[import]
from slowapi.util import get_remote_address  # type: ignore[import]

from agent.consumer import run_consumer
from agent.graph import build_graph, build_graph_in_memory
from api.routes import router
from api.auth import auth_router

log = structlog.get_logger()

# ── Rate limiter (shared instance used in routes.py via request.app.state) ─────
limiter = Limiter(key_func=get_remote_address)


def _get_allowed_origins() -> list[str]:
    """
    Read ALLOWED_ORIGINS env var (comma-separated) and always include localhost
    for development. Falls back to permissive wildcard only in development mode.
    """
    raw = os.getenv("ALLOWED_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]

    # Always allow the default UI ports for dev convenience
    for dev_origin in ["http://localhost:3000", "http://127.0.0.1:3000"]:
        if dev_origin not in origins:
            origins.append(dev_origin)

    env = os.getenv("ENVIRONMENT", "development")
    if not origins or env == "development":
        # In dev, also allow wildcard — production must set ALLOWED_ORIGINS explicitly
        if env != "production":
            origins = ["*"]

    return origins


def _log_startup_config() -> None:
    """Log a startup summary of which optional features are configured."""
    env     = os.getenv("ENVIRONMENT", "development")
    secret  = os.getenv("SECRET_KEY", "")
    is_weak = not secret or secret.startswith("changeme")

    log.info("=== AuralisAPI Remediation Brain — startup config ===")
    log.info("environment",        value=env)
    log.info("anthropic_api_key",  value="[SET]" if os.getenv("ANTHROPIC_API_KEY") else "[MISSING — heuristic fallback active]")
    log.info("groq_api_key",       value="[SET]" if os.getenv("GROQ_API_KEY") else "[MISSING]")
    log.info("github_token",       value="[SET]" if os.getenv("GITHUB_TOKEN") else "[MISSING — GitHub PR creation disabled]")
    log.info("github_repo",        value=os.getenv("GITHUB_REPO", "[not set]"))
    log.info("redis_password",     value="[SET]" if os.getenv("REDIS_PASSWORD") else "[none — Redis unauthenticated]")
    log.info("secret_key",         value="[WEAK — set SECRET_KEY in production!]" if is_weak else "[SET]")
    log.info("allowed_origins",    value=_get_allowed_origins())
    log.info("admin_email",        value=os.getenv("ADMIN_EMAIL", "admin@auralisapi.dev"))

    if env == "production" and is_weak:
        log.critical(
            "SECURITY: SECRET_KEY is set to the default placeholder — "
            "JWT tokens are insecure. Set SECRET_KEY to a random 64-char string."
        )


async def _start_consumer(app: FastAPI) -> asyncio.Task:
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
    stream    = os.getenv("REDIS_STREAM", "auralis:events")
    task = asyncio.create_task(
        run_consumer(app.state, redis_url, stream),
        name="redis-consumer",
    )
    log.info("Redis consumer task started", stream=stream)
    return task


@asynccontextmanager
async def lifespan(app: FastAPI):
    _log_startup_config()

    raw_db_url = os.getenv(
        "LANGGRAPH_DB_URL",
        "postgresql://auralis:auralis@postgres:5432/auralis",
    )

    consumer_task: asyncio.Task | None = None

    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver  # type: ignore[import]
        async with AsyncPostgresSaver.from_conn_string(raw_db_url) as checkpointer:
            await checkpointer.setup()
            app.state.graph = build_graph(checkpointer=checkpointer)
            log.info("remediation-brain started", checkpointer="postgres", db=raw_db_url.split("@")[-1])
            consumer_task = await _start_consumer(app)
            yield
            consumer_task.cancel()
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass
        log.info("remediation-brain shut down — PostgreSQL pool closed")

    except Exception as exc:
        log.warning("PostgreSQL unavailable — falling back to in-memory checkpointer", error=str(exc))
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

    # ── Rate limiter ──────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # ── CORS ──────────────────────────────────────────────────────────────────
    origins = _get_allowed_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Sensor-ID", "X-Sensor-Token"],
    )

    # ── Routes ────────────────────────────────────────────────────────────────
    app.include_router(auth_router)   # /auth/token  (unauthenticated login)
    app.include_router(router)        # all other endpoints
    return app


app = create_app()
