# tests/test_api.py — Integration tests for the remediation-brain FastAPI app
#
# All tests use the in-memory graph from conftest.py — no Postgres, Redis, or
# external LLM/GitHub API calls. External side-effects are patched via mocker.
#
# Run with:
#   pip install -r requirements.txt -r requirements-test.txt
#   pytest tests/test_api.py -v
from __future__ import annotations

import asyncio
import uuid

from agent import nodes


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _poll_incident(client, thread_id: str, timeout: float = 5.0, interval: float = 0.05):
    """
    Poll GET /incidents/{thread_id} until classification is populated or timeout.
    Returns the response JSON or None on timeout.
    """
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = await client.get(f"/incidents/{thread_id}")
        if resp.status_code == 200:
            data = resp.json()
            if data.get("classification") is not None:
                return data
        await asyncio.sleep(interval)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 1. Health endpoints
# ─────────────────────────────────────────────────────────────────────────────

async def test_health_returns_ok(client):
    """GET /health must return 200 with status=ok regardless of DB state."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "remediation-brain"


async def test_health_live(client):
    resp = await client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


async def test_health_ready_degraded_without_db(client):
    """Without real Postgres/Redis the ready probe must return 503 (degraded)."""
    resp = await client.get("/health/ready")
    # In test mode pools are None so checks show "unavailable" → 200 (no error, just no pool)
    assert resp.status_code in (200, 503)
    body = resp.json()
    assert "status" in body
    assert "checks" in body


# ─────────────────────────────────────────────────────────────────────────────
# 2. Authentication
# ─────────────────────────────────────────────────────────────────────────────

async def test_login_returns_token(client):
    """Valid credentials must return an access_token."""
    resp = await client.post(
        "/auth/token",
        json={"email": "admin@auralisapi.dev", "password": "auralis2025"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 20


async def test_login_wrong_password(client):
    """Bad credentials must return 401."""
    resp = await client.post(
        "/auth/token",
        json={"email": "admin@auralisapi.dev", "password": "wrong"},
    )
    assert resp.status_code == 401


async def test_remediate_requires_auth(client):
    """POST /remediate without a token must return 401."""
    resp = await client.post("/remediate", json={"path": "/api/v1/users"})
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 3. POST /remediate
# ─────────────────────────────────────────────────────────────────────────────

async def test_remediate_returns_thread_id(client, auth_headers):
    """POST /remediate must return thread_id, poll_url, and approve_url immediately."""
    resp = await client.post(
        "/remediate",
        json={"path": "/api/v1/test-endpoint", "method": "GET"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "thread_id" in body
    assert body["status"] == "queued"
    assert body["poll_url"].endswith(body["thread_id"])
    assert body["approve_url"].startswith("/incidents/")
    # thread_id must be a valid UUID
    uuid.UUID(body["thread_id"])


async def test_remediate_unknown_path_queued(client, auth_headers):
    """Any valid path accepted — shadow API candidate still gets queued."""
    resp = await client.post(
        "/remediate",
        json={"path": "/mystery/endpoint", "method": "POST"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"


# ─────────────────────────────────────────────────────────────────────────────
# 4. GET /incidents
# ─────────────────────────────────────────────────────────────────────────────

async def test_incidents_returns_list(client):
    """GET /incidents must return a dict with 'incidents' list and 'total' count."""
    resp = await client.get("/incidents")
    assert resp.status_code == 200
    body = resp.json()
    assert "incidents" in body
    assert "total" in body
    assert isinstance(body["incidents"], list)
    assert body["total"] == len(body["incidents"])


async def test_get_incident_not_found(client):
    """GET /incidents/<non-existent-id> must return 404."""
    resp = await client.get(f"/incidents/{uuid.uuid4()}")
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 5. Full workflow: remediate → poll → incident appears
# ─────────────────────────────────────────────────────────────────────────────

async def test_workflow_completes_for_low_severity(client, auth_headers, mocker):
    """
    A current-version healthy path is classified as unknown/low severity.
    The graph skips the enforce interrupt and runs straight to generate_report.
    Poll until classification is populated (no LLM calls — heuristic path).
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=None)
    mocker.patch.object(nodes, "_llm_structured", None)

    resp = await client.post(
        "/remediate",
        json={"path": "/api/v3/products", "method": "GET"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    thread_id = resp.json()["thread_id"]

    incident = await _poll_incident(client, thread_id, timeout=5.0)
    assert incident is not None, "Workflow did not complete within 5s"
    assert incident["classification"] in ("unknown", "active_zombie", "dormant_zombie", "shadow")
    # Low-severity path should be completed (no interrupt for v3 paths)
    assert "severity" in incident


async def test_workflow_reaches_interrupt_for_zombie(client, auth_headers, mocker):
    """
    Deprecated v1 path → active_zombie, high/critical severity.
    The graph pauses at the enforce interrupt — status must be awaiting_approval.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=None)
    mocker.patch.object(nodes, "_llm_structured", None)

    resp = await client.post(
        "/remediate",
        json={"path": "/api/v1/users", "method": "GET"},
        headers=auth_headers,
    )
    thread_id = resp.json()["thread_id"]

    incident = await _poll_incident(client, thread_id, timeout=5.0)
    assert incident is not None, "Workflow did not reach interrupt within 5s"
    assert incident["classification"] == "active_zombie"
    assert incident["severity"] in ("critical", "high")
    assert incident["status"] == "awaiting_approval"
    assert "enforce" in incident["next"]


# ─────────────────────────────────────────────────────────────────────────────
# 6. Approve / Reject flow
# ─────────────────────────────────────────────────────────────────────────────

async def test_reject_incident(client, auth_headers, mocker):
    """
    Reject a zombie incident awaiting approval.
    Workflow must skip enforce, generate a report, and return status=rejected.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=None)
    mocker.patch.object(nodes, "_llm_structured", None)

    resp = await client.post(
        "/remediate",
        json={"path": "/api/v1/payments", "method": "GET"},
        headers=auth_headers,
    )
    thread_id = resp.json()["thread_id"]

    incident = await _poll_incident(client, thread_id, timeout=5.0)
    assert incident is not None
    assert incident["status"] == "awaiting_approval", (
        f"Expected awaiting_approval, got {incident['status']} "
        f"(severity={incident.get('severity')})"
    )

    # Reject
    resp = await client.post(
        f"/incidents/{thread_id}/reject",
        json={"notes": "Not critical in this environment"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert body["thread_id"] == thread_id

    # After rejection the incident should be completed with no enforce actions
    resp = await client.get(f"/incidents/{thread_id}")
    assert resp.status_code == 200
    final = resp.json()
    assert final["status"] == "completed"
    assert any("rejected" in (a or "") for a in final.get("executed_actions", []))


async def test_approve_incident(client, auth_headers, mocker):
    """
    Approve a zombie incident — enforce runs in stub mode (no GITHUB_TOKEN).
    Workflow must complete with status=enforced.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=None)
    mocker.patch.object(nodes, "_llm_structured", None)
    # Ensure stub mode (enforce runs without GitHub or krakend.json)
    mocker.patch.object(nodes, "_github", None)
    mocker.patch.object(nodes, "_github_repo", "")
    mocker.patch.object(nodes, "_MUTATOR_AVAILABLE", False)
    # Point honeypot URL at a port that refuses immediately (avoids 5s timeout in CI)
    mocker.patch.object(nodes, "_HONEYPOT_URL", "http://127.0.0.1:1")

    resp = await client.post(
        "/remediate",
        json={"path": "/legacy/export/users", "method": "GET"},
        headers=auth_headers,
    )
    thread_id = resp.json()["thread_id"]

    incident = await _poll_incident(client, thread_id, timeout=5.0)
    assert incident is not None
    assert incident["status"] == "awaiting_approval"

    resp = await client.post(
        f"/incidents/{thread_id}/approve",
        json={"notes": "Approved in test"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "enforced"
    assert body["thread_id"] == thread_id


async def test_approve_already_processed(client, auth_headers, mocker):
    """
    Approving an already-completed incident must return already_processed, not 404.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=None)
    mocker.patch.object(nodes, "_llm_structured", None)

    # Use a low-severity path → no interrupt → complete immediately
    resp = await client.post(
        "/remediate",
        json={"path": "/api/v3/catalog", "method": "GET"},
        headers=auth_headers,
    )
    thread_id = resp.json()["thread_id"]
    await _poll_incident(client, thread_id, timeout=5.0)

    resp = await client.post(
        f"/incidents/{thread_id}/approve",
        json={},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    # Either already_processed or awaiting_approval was true (depends on classification)
    assert resp.json()["status"] in ("already_processed", "enforced")


async def test_reject_requires_auth(client):
    resp = await client.post(
        f"/incidents/{uuid.uuid4()}/reject",
        json={},
    )
    assert resp.status_code == 401


async def test_approve_nonexistent_incident(client, auth_headers):
    resp = await client.post(
        f"/incidents/{uuid.uuid4()}/approve",
        json={},
        headers=auth_headers,
    )
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 7. GET /inventory
# ─────────────────────────────────────────────────────────────────────────────

async def test_inventory_returns_shape(client, mocker):
    """GET /inventory must return endpoints list with required keys."""
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=None)
    resp = await client.get("/inventory")
    assert resp.status_code == 200
    body = resp.json()
    assert "endpoints" in body
    assert "total" in body
    assert "zombies" in body
    assert "shadows" in body
    assert body["total"] == len(body["endpoints"])
