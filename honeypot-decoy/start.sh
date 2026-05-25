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

# ── Phase 4: Start the dynamic honeypot FastAPI server with auto-restart ──────
# Wrapped in a restart loop so a crash during the demo doesn't silently kill
# port 8082. The subshell runs in the background; exec opencanaryd takes PID 1.
echo "[honeypot-decoy] Starting dynamic honeypot server on :8082 (auto-restart enabled)..."
(
    while true; do
        python /app/honeypot_server.py || true
        echo "[honeypot-decoy] honeypot_server.py exited — restarting in 3s..."
        sleep 3
    done
) &
echo "[honeypot-decoy] honeypot_server.py restart-loop started (PID $!)"

# ── Start OpenCanary in foreground (exec replaces shell — signals forwarded) ──
echo "[honeypot-decoy] Starting OpenCanary in foreground mode..."
# BUG FIX #4: opencanaryd searches $CWD/opencanary.conf before $HOME/.opencanary.conf.
# Container CWD is /app (set in Dockerfile WORKDIR), so it always fails and falls back.
# Changing to $HOME (/root) means CWD search hits /root/opencanary.conf — but the config
# was copied to /root/.opencanary.conf (dotfile). The real fix is to symlink it:
ln -sf "${CONFIG_DST}" "${HOME}/opencanary.conf" 2>/dev/null || true
# BUG FIX #6: Suppress Blowfish/CAST5 CryptographyDeprecationWarning from twisted.conch.
# OpenCanary 0.9.3 pins cryptography==38.0.1 and cannot be upgraded without breaking its
# pip resolution — suppressing at the process level is the only viable workaround.
export PYTHONWARNINGS="ignore::CryptographyDeprecationWarning"
exec opencanaryd --dev
