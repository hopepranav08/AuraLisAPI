#!/usr/bin/env sh
# honeypot-decoy/start.sh — OpenCanary + Dynamic Honeypot Server entrypoint
#
# Starts two processes:
#   1. honeypot_server.py  — FastAPI deception server (port 8082) in background
#      Accepts path registrations from the brain, serves realistic fake responses,
#      fires async webhooks back to the brain on every attacker hit.
#
#   2. opencanaryd --dev   — OpenCanary honeypot daemon (ports 8081 + 2222) in foreground
#      Low-level HTTP and SSH trap. Logs raw probes to stdout as structured JSON.
#
# OpenCanary's --dev flag runs in foreground (no daemonise) — correct for Docker.
# honeypot_server.py runs as a background process; if it crashes, opencanaryd
# stays alive and the container remains healthy (degraded but not dead).

set -eu

CONFIG_SRC="/etc/opencanary/opencanary.conf"
CONFIG_DST="${HOME}/.opencanary.conf"

echo "[honeypot-decoy] Copying OpenCanary config: ${CONFIG_SRC} -> ${CONFIG_DST}"
cp "${CONFIG_SRC}" "${CONFIG_DST}"

# Remove stale twistd PID file from any previous (crashed) run.
rm -f twistd.pid

# ── Phase 4: Start the dynamic honeypot FastAPI server in background ──────────
echo "[honeypot-decoy] Starting dynamic honeypot server on :8082..."
python /app/honeypot_server.py &
HONEYPOT_PID=$!
echo "[honeypot-decoy] honeypot_server.py started (PID ${HONEYPOT_PID})"

# ── Start OpenCanary in foreground (exec replaces shell — signals forwarded) ──
echo "[honeypot-decoy] Starting OpenCanary in foreground mode..."
exec opencanaryd --dev
