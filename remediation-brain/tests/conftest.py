# tests/conftest.py — shared fixtures for API integration tests
#
# Provides a FastAPI test client with:
#   - app.state manually initialized (no Postgres, no Redis, no Redis consumer)
#   - MemorySaver-backed LangGraph (state survives within one test, lost after)
#   - In-memory SensorRegistry (no DB required)
#
# Note: httpx's ASGITransport sends only "http" scope requests — it never
# fires the ASGI lifespan events. We manually call _test_lifespan to set
# app.state before requests are dispatched.
from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Allow running pytest from tests/ or remediation-brain/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@asynccontextmanager
async def _test_lifespan(app):
    """Minimal lifespan that wires app.state without any external services."""
    from agent.graph import build_graph_in_memory
    from db.sensors import SensorRegistry

    app.state.graph = build_graph_in_memory()
    app.state.asyncpg_pool = None
    app.state.redis_pool = None
    registry = SensorRegistry(pool=None)
    await registry.setup()
    app.state.sensor_registry = registry
    yield


@pytest_asyncio.fixture
async def client():
    """httpx.AsyncClient with app.state pre-initialized via _test_lifespan."""
    import main as main_module

    # Patch main.lifespan so FastAPI stores _test_lifespan as its lifespan context.
    with patch.object(main_module, "lifespan", _test_lifespan):
        app = main_module.create_app()

    # ASGITransport never fires ASGI lifespan events, so manually initialize
    # app.state here. The state object is shared by the app's request handlers.
    async with _test_lifespan(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


@pytest_asyncio.fixture
async def auth_token(client):
    """Return a valid JWT obtained via POST /auth/token using default dev credentials."""
    resp = await client.post(
        "/auth/token",
        json={"email": "admin@auralisapi.dev", "password": "auralis2025"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest_asyncio.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
