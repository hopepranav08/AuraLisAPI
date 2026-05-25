# db/sensors.py — Persistent sensor registry backed by PostgreSQL
#
# SensorRegistry provides a thin layer over a sensors table with a 30-second
# in-memory cache so that /sensor/ingest token validation never hits the DB
# on every request during normal operation.
#
# Fallback: when asyncpg pool is None (brain started without PostgreSQL),
# the registry operates in pure in-memory mode. State is lost on restart
# but the service remains fully operational.
from __future__ import annotations

import time
import uuid
from typing import Any, Optional

import structlog  # type: ignore[import]

log = structlog.get_logger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS sensor_registry (
    sensor_id        TEXT PRIMARY KEY,
    sensor_token     TEXT NOT NULL,
    hostname         TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'live',
    version          TEXT NOT NULL DEFAULT '1.0.0',
    ip               TEXT,
    registered_at    DOUBLE PRECISION NOT NULL,
    last_seen        DOUBLE PRECISION NOT NULL,
    events_forwarded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sensor_token ON sensor_registry (sensor_token);
"""

_CACHE_TTL = 30.0   # seconds before cache is refreshed from DB


class SensorRegistry:
    """
    Dual-backend sensor registry.

    Primary:  PostgreSQL via asyncpg pool — persists across brain restarts.
    Fallback: in-memory dict — used when asyncpg pool is None (dev / no DB).

    Token-to-id cache is rebuilt every 30s from the DB to catch registrations
    from other brain replicas (future horizontal scaling).
    """

    def __init__(self, pool: Any | None) -> None:
        self._pool = pool
        # In-memory structures: always populated (primary or fallback).
        self._by_id:    dict[str, dict] = {}    # sensor_id → row dict
        self._by_token: dict[str, str]  = {}    # sensor_token → sensor_id
        self._cache_ts: float           = 0.0

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def setup(self) -> None:
        """Create the sensors table if it does not exist (idempotent)."""
        if self._pool is None:
            log.info("SensorRegistry: no DB pool — using in-memory mode")
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(_CREATE_TABLE)
            log.info("SensorRegistry: PostgreSQL table ready")
        except Exception as exc:
            log.warning("SensorRegistry: table setup failed — falling back to memory", error=str(exc))
            self._pool = None

    # ── Public API ─────────────────────────────────────────────────────────────

    async def register(
        self,
        sensor_id: str,
        token: str,
        hostname: str,
        mode: str,
        version: str,
        ip: str,
    ) -> None:
        """Upsert a sensor registration (idempotent on sensor_id conflict)."""
        now = time.time()
        row = {
            "sensor_id":        sensor_id,
            "sensor_token":     token,
            "hostname":         hostname,
            "mode":             mode,
            "version":          version,
            "ip":               ip,
            "registered_at":    now,
            "last_seen":        now,
            "events_forwarded": 0,
        }

        if self._pool is not None:
            try:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO sensor_registry
                            (sensor_id, sensor_token, hostname, mode, version,
                             ip, registered_at, last_seen, events_forwarded)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$7,0)
                        ON CONFLICT (sensor_id) DO UPDATE SET
                            sensor_token     = EXCLUDED.sensor_token,
                            hostname         = EXCLUDED.hostname,
                            mode             = EXCLUDED.mode,
                            version          = EXCLUDED.version,
                            ip               = EXCLUDED.ip,
                            last_seen        = EXCLUDED.last_seen
                        """,
                        sensor_id, token, hostname, mode, version, ip, now,
                    )
            except Exception as exc:
                log.warning("SensorRegistry.register: DB write failed", error=str(exc))

        # Always update in-memory cache immediately
        self._by_id[sensor_id]  = row
        self._by_token[token]   = sensor_id
        self._cache_ts = time.time()   # mark cache as fresh

    async def get_sensor_id_for_token(self, token: str) -> Optional[str]:
        """Return sensor_id for a given token, or None if not found."""
        await self._maybe_refresh()
        return self._by_token.get(token)

    async def touch(self, sensor_id: str) -> None:
        """Update last_seen + increment events_forwarded (best-effort)."""
        now = time.time()
        if sensor_id in self._by_id:
            self._by_id[sensor_id]["last_seen"]        = now
            self._by_id[sensor_id]["events_forwarded"] = self._by_id[sensor_id].get("events_forwarded", 0) + 1

        if self._pool is None:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE sensor_registry
                    SET last_seen=$1, events_forwarded=events_forwarded+1
                    WHERE sensor_id=$2
                    """,
                    now, sensor_id,
                )
        except Exception as exc:
            log.debug("SensorRegistry.touch: DB update failed", error=str(exc))

    async def list_all(self) -> list[dict]:
        """Return all registered sensors (public fields only — token excluded)."""
        await self._maybe_refresh()
        now = time.time()
        result = []
        for row in self._by_id.values():
            result.append({
                "sensor_id":        row["sensor_id"],
                "hostname":         row["hostname"],
                "mode":             row["mode"],
                "version":          row["version"],
                "ip":               row["ip"],
                "registered_at":    row["registered_at"],
                "last_seen":        row["last_seen"],
                "events_forwarded": row["events_forwarded"],
                "online":           (now - row["last_seen"]) < 60,
                "last_seen_ago_s":  round(now - row["last_seen"]),
            })
        return result

    # ── Internal cache refresh ─────────────────────────────────────────────────

    async def _maybe_refresh(self) -> None:
        if time.time() - self._cache_ts < _CACHE_TTL:
            return
        if self._pool is None:
            self._cache_ts = time.time()
            return
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM sensor_registry ORDER BY registered_at DESC"
                )
            self._by_id    = {r["sensor_id"]: dict(r) for r in rows}
            self._by_token = {r["sensor_token"]: r["sensor_id"] for r in rows}
            self._cache_ts = time.time()
        except Exception as exc:
            log.warning("SensorRegistry: cache refresh failed", error=str(exc))
            self._cache_ts = time.time()  # back off — don't hammer a broken DB
