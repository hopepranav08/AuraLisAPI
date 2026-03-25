# honeypot-decoy/honeypot_server.py — Dynamic Deception Server (Phase 4)
#
# FastAPI application running on port 8082 alongside OpenCanary (port 8081).
#
# Why FastAPI instead of extending OpenCanary's HTTP module:
#   OpenCanary's HTTP module serves static content and cannot register new paths
#   at runtime without a full daemon restart. This companion server accepts dynamic
#   path registration from the brain, serves realistic fake responses using Faker,
#   and fires async webhook alerts back to the brain — all without container restart.
#
# Architecture:
#   ┌────────────────────────────────────────────────────────┐
#   │  remediation-brain enforce_node                        │
#   │    POST http://honeypot-decoy:8082/admin/register-path │
#   └───────────────────────────┬────────────────────────────┘
#                               │  registers new zombie path + schema
#                               ▼
#   ┌────────────────────────────────────────────────────────┐
#   │  honeypot_server.py  (this file, port 8082)            │
#   │    GET/POST/... /{any_path}  →  fake response          │
#   │    log: src_ip, timestamp, method, path, headers, body │
#   │    POST brain webhook (fire-and-forget)                │
#   └───────────────────────────┬────────────────────────────┘
#                               │  async webhook (never blocks attacker)
#                               ▼
#   ┌────────────────────────────────────────────────────────┐
#   │  remediation-brain POST /webhooks/honeypot-alert       │
#   │    → writes to auralis:honeypot-events Redis stream    │
#   └────────────────────────────────────────────────────────┘
from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import structlog
from faker import Faker
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

log  = structlog.get_logger(__name__)
fake = Faker()

# ── Configuration ─────────────────────────────────────────────────────────────

BRAIN_WEBHOOK_URL = os.getenv(
    "BRAIN_WEBHOOK_URL",
    "http://remediation-brain:8000/webhooks/honeypot-alert",
)
NODE_ID          = os.getenv("HONEYPOT_NODE_ID", "auralis-honeypot-001")
_REGISTRY_FILE   = Path("/app/paths.json")

# In-memory path registry: { "/api/v1/payments": {"schema": {...}, "registered_at": ...} }
_REGISTRY: dict[str, dict[str, Any]] = {}


# ── Registry persistence ───────────────────────────────────────────────────────

def _load_registry() -> None:
    """Load the path registry from disk on startup (survives container restart)."""
    if _REGISTRY_FILE.exists():
        try:
            data = json.loads(_REGISTRY_FILE.read_text(encoding="utf-8"))
            _REGISTRY.update(data)
            log.info("honeypot registry loaded from disk", count=len(_REGISTRY))
        except Exception as exc:
            log.warning("registry load failed — starting empty", error=str(exc))


def _save_registry() -> None:
    """Persist the current registry to disk after every mutation."""
    try:
        _REGISTRY_FILE.write_text(
            json.dumps(_REGISTRY, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning("registry save failed — changes in-memory only", error=str(exc))


# ── Fake response generation ───────────────────────────────────────────────────

def _generate_fake_response(path: str, schema: dict[str, Any]) -> dict[str, Any]:
    """
    Generate a realistic fake API response.

    Priority:
      1. Schema-driven: use the JSON schema properties from the OpenAPI spec.
      2. Path-heuristic: infer response shape from keywords in the URL path.
      3. Generic fallback: return a minimal {id, status} dict.
    """
    props = schema.get("properties", {})

    # ── Schema-driven generation ───────────────────────────────────────────────
    if props:
        result: dict[str, Any] = {}
        for prop_name, prop_def in props.items():
            prop_type = prop_def.get("type", "string")
            fmt       = prop_def.get("format", "")
            name_lc   = prop_name.lower()

            if prop_type == "integer":
                result[prop_name] = fake.random_int(min=1000, max=999999)
            elif prop_type == "number":
                result[prop_name] = round(
                    fake.pyfloat(min_value=0.01, max_value=9999.99, right_digits=2), 2
                )
            elif prop_type == "boolean":
                result[prop_name] = fake.boolean()
            elif prop_type == "array":
                result[prop_name] = []
            elif prop_type == "object":
                result[prop_name] = {}
            else:  # string and fallback
                if fmt == "email" or "email" in name_lc:
                    result[prop_name] = fake.email()
                elif fmt in ("date-time", "date") or "date" in name_lc or "time" in name_lc:
                    result[prop_name] = fake.iso8601()
                elif fmt == "uuid" or name_lc in ("id", "uuid", "guid"):
                    result[prop_name] = str(uuid.uuid4())
                elif "name" in name_lc:
                    result[prop_name] = fake.name()
                elif "phone" in name_lc:
                    result[prop_name] = fake.phone_number()
                elif "address" in name_lc:
                    result[prop_name] = fake.address()
                elif "amount" in name_lc or "price" in name_lc or "balance" in name_lc:
                    result[prop_name] = str(
                        round(fake.pyfloat(min_value=1, max_value=9999, right_digits=2), 2)
                    )
                elif "currency" in name_lc:
                    result[prop_name] = fake.currency_code()
                elif "status" in name_lc:
                    result[prop_name] = fake.random_element(["active", "pending", "inactive"])
                else:
                    result[prop_name] = fake.word()
        return result

    # ── Path-heuristic generation ──────────────────────────────────────────────
    path_lc = path.lower()

    if any(kw in path_lc for kw in ("user", "account", "profile", "member")):
        return {
            "id":         fake.random_int(min=1000, max=99999),
            "name":       fake.name(),
            "email":      fake.email(),
            "phone":      fake.phone_number(),
            "created_at": fake.iso8601(),
            "status":     "active",
        }
    if any(kw in path_lc for kw in ("payment", "transaction", "invoice", "charge")):
        return {
            "transaction_id": f"tx-{fake.random_int(min=10000, max=99999)}",
            "amount":         round(
                fake.pyfloat(min_value=1.0, max_value=10000.0, right_digits=2), 2
            ),
            "currency":       fake.currency_code(),
            "status":         fake.random_element(["completed", "pending", "failed"]),
            "created_at":     fake.iso8601(),
        }
    if any(kw in path_lc for kw in ("product", "item", "catalog", "sku")):
        return {
            "id":          fake.random_int(min=1, max=9999),
            "name":        fake.catch_phrase(),
            "description": fake.sentence(),
            "price":       round(
                fake.pyfloat(min_value=0.99, max_value=999.99, right_digits=2), 2
            ),
            "stock":       fake.random_int(min=0, max=500),
            "sku":         fake.bothify(text="SKU-####-???").upper(),
        }
    if any(kw in path_lc for kw in ("order", "cart", "checkout")):
        return {
            "order_id":   f"ORD-{fake.random_int(min=100000, max=999999)}",
            "items":      [],
            "total":      round(
                fake.pyfloat(min_value=10.0, max_value=5000.0, right_digits=2), 2
            ),
            "status":     fake.random_element(["processing", "shipped", "delivered"]),
            "created_at": fake.iso8601(),
        }
    if any(kw in path_lc for kw in ("auth", "login", "token", "session")):
        return {
            "token":      fake.sha256(),
            "expires_in": 3600,
            "token_type": "Bearer",
        }

    # ── Generic fallback ───────────────────────────────────────────────────────
    return {
        "id":         str(uuid.uuid4()),
        "status":     "ok",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "data":       {},
    }


# ── Async webhook ──────────────────────────────────────────────────────────────

async def _fire_webhook(
    src_ip:  str,
    method:  str,
    path:    str,
    headers: dict[str, str],
    body:    str,
) -> None:
    """
    Fire-and-forget POST to the brain's honeypot webhook endpoint.
    Never blocks the response to the attacker — called via asyncio.create_task().
    """
    payload = {
        "src_ip":    src_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method":    method,
        "path":      path,
        "headers":   headers,
        "body":      body[:4096],   # cap body at 4 KB
        "node_id":   NODE_ID,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            response = await client.post(BRAIN_WEBHOOK_URL, json=payload)
            if response.status_code not in (200, 201, 204):
                log.debug(
                    "webhook returned non-2xx",
                    status=response.status_code,
                    path=path,
                )
    except httpx.ConnectError:
        log.debug("brain not reachable for webhook", path=path)
    except Exception as exc:
        log.warning("webhook delivery failed", error=str(exc), path=path)


# ── FastAPI application ────────────────────────────────────────────────────────

@asynccontextmanager
async def _lifespan(application: FastAPI):
    _load_registry()
    log.info("honeypot server started", node_id=NODE_ID, port=8082)
    yield


app = FastAPI(
    title="AuralisAPI Dynamic Honeypot Server",
    description="Deception layer — serves realistic fake API responses to attackers",
    version="1.0.0",
    lifespan=_lifespan,
)


# ── Admin API (internal — only reachable within the Docker network) ────────────

class RegisterPathRequest(BaseModel):
    path:   str
    schema: dict[str, Any] = {}   # JSON schema for response generation


@app.post("/admin/register-path", tags=["Admin"])
async def register_path(body: RegisterPathRequest):
    """
    Hot-register a new quarantined path without container restart.
    Called by EnforcerNode after a GitHub PR is created.
    """
    _REGISTRY[body.path] = {
        "schema":        body.schema,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_registry()
    log.info("honeypot path registered", path=body.path)
    return {
        "status":      "registered",
        "path":        body.path,
        "total_paths": len(_REGISTRY),
    }


@app.get("/admin/registered-paths", tags=["Admin"])
async def list_registered_paths():
    """List all currently registered deception paths."""
    return {
        "paths": [
            {"path": p, "registered_at": v.get("registered_at")}
            for p, v in _REGISTRY.items()
        ],
        "total": len(_REGISTRY),
    }


@app.delete("/admin/unregister-path", tags=["Admin"])
async def unregister_path(path: str):
    """Remove a path from the deception registry."""
    removed = _REGISTRY.pop(path, None)
    if removed is not None:
        _save_registry()
    return {"status": "unregistered" if removed else "not_found", "path": path}


@app.get("/admin/health", tags=["Admin"])
async def honeypot_health():
    return {"status": "ok", "node_id": NODE_ID, "registered_paths": len(_REGISTRY)}


# ── Deception handler — catches ALL incoming requests ─────────────────────────

@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
async def deception_handler(full_path: str, request: Request):
    """
    Serve realistic fake responses to any attacker probing the honeypot.

    For every request:
      1. Log attacker metadata (IP, method, path, UA, body).
      2. Fire async webhook to brain (never blocks this response).
      3. Look up the registered schema for this path (or use heuristics).
      4. Return a 200 with plausible fake JSON.

    The 200 status code is intentional — attackers who see 404/403 know
    the honeypot isn't real. A 200 with realistic data keeps them engaged
    and gathering intelligence.
    """
    path    = "/" + full_path
    src_ip  = (request.client.host if request.client else "unknown")
    method  = request.method
    headers = dict(request.headers)

    try:
        raw_body = await request.body()
        body     = raw_body.decode("utf-8", errors="replace")
    except Exception:
        body = ""

    log.info(
        "honeypot hit",
        path=path,
        method=method,
        src_ip=src_ip,
        user_agent=headers.get("user-agent", ""),
        body_len=len(body),
    )

    # Fire webhook without awaiting — attacker gets response immediately.
    asyncio.create_task(_fire_webhook(src_ip, method, path, headers, body))

    # Look up schema for this exact path; fall back to prefix match.
    entry  = _REGISTRY.get(path)
    if entry is None:
        # Try prefix match for paths like /api/v1/users/42 against /api/v1/users
        for registered_path in sorted(_REGISTRY.keys(), key=len, reverse=True):
            if path.startswith(registered_path):
                entry = _REGISTRY[registered_path]
                break

    schema      = (entry or {}).get("schema", {})
    fake_data   = _generate_fake_response(path, schema)

    return JSONResponse(content=fake_data, status_code=200)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "honeypot_server:app",
        host="0.0.0.0",
        port=8082,
        workers=1,
        log_level="info",
    )
