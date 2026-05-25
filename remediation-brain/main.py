# main.py — AuralisAPI remediation-brain FastAPI Application Factory
from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager

import structlog  # type: ignore[import]
import structlog.contextvars  # type: ignore[import]
from fastapi import FastAPI, Request, Response  # type: ignore[import]
from fastapi.middleware.cors import CORSMiddleware  # type: ignore[import]
from starlette.middleware.base import BaseHTTPMiddleware  # type: ignore[import]
from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore[import]
from slowapi.errors import RateLimitExceeded  # type: ignore[import]
from slowapi.util import get_remote_address  # type: ignore[import]

from agent.consumer import run_consumer
from agent.graph import build_graph, build_graph_in_memory
from api.routes import router
from api.auth import auth_router
from db.sensors import SensorRegistry

log = structlog.get_logger()

limiter = Limiter(key_func=get_remote_address)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Passthrough middleware that attaches a correlation ID to every request.

    Priority: use the incoming X-Request-ID header value if present;
    otherwise generate a new UUID4. The ID is bound to the structlog
    context so every log line in the request lifecycle includes it,
    then echoed back in the response header.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


def _get_allowed_origins() -> list[str]:
    raw = os.getenv("ALLOWED_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    for dev_origin in ["http://localhost:3000", "http://127.0.0.1:3000"]:
        if dev_origin not in origins:
            origins.append(dev_origin)
    if os.getenv("ENVIRONMENT", "development") != "production":
        origins = ["*"]
    return origins


def _log_startup_config() -> None:
    env      = os.getenv("ENVIRONMENT", "development")
    is_prod  = env == "production"
    secret   = os.getenv("SECRET_KEY", "")
    is_weak  = not secret or secret.startswith("changeme")

    has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY"))
    has_groq      = bool(os.getenv("GROQ_API_KEY"))
    has_github    = bool(os.getenv("GITHUB_TOKEN"))
    has_redis_pw  = bool(os.getenv("REDIS_PASSWORD"))

    log.info("=== AuralisAPI Remediation Brain — startup config ===")
    log.info("environment", value=env)

    # Log each var: INFO when set, WARNING when absent/weak so operators notice missing config.
    _lvl = log.warning if (is_prod and not has_anthropic) else log.info
    _lvl("anthropic_api_key", value="[SET]" if has_anthropic else "[MISSING — heuristic fallback active]")

    (log.info if has_groq else log.warning)(
        "groq_api_key", value="[SET]" if has_groq else "[MISSING — Groq fallback disabled]"
    )
    (log.info if has_github else log.warning)(
        "github_token", value="[SET]" if has_github else "[MISSING — GitHub PR creation disabled]"
    )
    (log.info if has_redis_pw else log.warning)(
        "redis_password", value="[SET]" if has_redis_pw else "[none — Redis unauthenticated, OK for dev]"
    )
    (log.info if not is_weak else log.warning)(
        "secret_key", value="[SET]" if not is_weak else "[WEAK — set SECRET_KEY in production!]"
    )
    log.info("allowed_origins", value=_get_allowed_origins())

    if is_prod and is_weak:
        log.critical(
            "SECURITY: SECRET_KEY is the default placeholder — "
            "JWT tokens are insecure. Set SECRET_KEY to a random 64-char string."
        )
    if is_prod and not has_anthropic:
        log.critical(
            "DEGRADED: ANTHROPIC_API_KEY is not set in production — "
            "incident reports will fall back to heuristic summaries. "
            "Set ANTHROPIC_API_KEY for full LLM-powered remediation."
        )


async def _make_asyncpg_pool(db_url: str):
    """Create an asyncpg connection pool for application queries (sensor registry etc.)."""
    import asyncpg  # type: ignore[import]
    # asyncpg uses postgresql:// — strip SQLAlchemy's +asyncpg dialect prefix if present.
    url = db_url.replace("postgresql+asyncpg://", "postgresql://")
    return await asyncpg.create_pool(url, min_size=2, max_size=10, command_timeout=10)


async def _make_redis_pool(redis_url: str):
    """Create a shared aioredis connection pool for request handlers."""
    import redis.asyncio as aioredis  # type: ignore[import]
    return aioredis.ConnectionPool.from_url(redis_url, max_connections=20, decode_responses=True)


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
    asyncpg_pool = None
    redis_pool   = None
    consumer_task: asyncio.Task | None = None

    # ── Shared infrastructure ──────────────────────────────────────────────────
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
    redis_password = os.getenv("REDIS_PASSWORD", "")
    if redis_password and "://" in redis_url and "@" not in redis_url:
        redis_url = redis_url.replace("redis://", f"redis://:{redis_password}@", 1)

    try:
        redis_pool = await _make_redis_pool(redis_url)
        app.state.redis_pool = redis_pool
        log.info("shared Redis pool created")
    except Exception as exc:
        log.warning("Redis pool creation failed — handlers will create per-request clients", error=str(exc))
        app.state.redis_pool = None

    try:
        asyncpg_pool = await _make_asyncpg_pool(raw_db_url)
        app.state.asyncpg_pool = asyncpg_pool
        log.info("asyncpg pool created")
    except Exception as exc:
        log.warning("asyncpg pool creation failed — sensor registry will use in-memory mode", error=str(exc))
        app.state.asyncpg_pool = None

    # Initialise sensor registry (PostgreSQL-backed or in-memory fallback)
    registry = SensorRegistry(pool=app.state.asyncpg_pool)
    await registry.setup()
    app.state.sensor_registry = registry

    # ── LangGraph checkpointer ─────────────────────────────────────────────────
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

    finally:
        if asyncpg_pool:
            await asyncpg_pool.close()
            log.info("asyncpg pool closed")
        if redis_pool:
            await redis_pool.aclose()
            log.info("Redis pool closed")


def create_app() -> FastAPI:
    app = FastAPI(
        title="AuralisAPI Remediation Brain",
        description="Autonomous Zombie API discovery and remediation via LangGraph",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    origins = _get_allowed_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Sensor-ID", "X-Sensor-Token"],
    )
    app.add_middleware(RequestIDMiddleware)

    try:
        from prometheus_fastapi_instrumentator import Instrumentator  # type: ignore[import]
        Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
        log.info("Prometheus metrics exposed at /metrics")
    except ImportError:
        log.warning("prometheus-fastapi-instrumentator not installed — /metrics unavailable")

    app.include_router(auth_router)
    app.include_router(router)
    return app


app = create_app()
