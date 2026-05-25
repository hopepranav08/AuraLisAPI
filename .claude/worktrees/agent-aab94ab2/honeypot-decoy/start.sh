#!/usr/bin/env sh
# honeypot-decoy/start.sh — OpenCanary container entrypoint
#
# OpenCanary looks for its config at $HOME/.opencanary.conf by default.
# We mount the config at /etc/opencanary/opencanary.conf and copy it
# to the expected location before launching the daemon.
#
# NOTE: opencanaryd --dev runs in foreground (no daemonise), which is
# correct for a Docker container. --start would fork to background and
# the container would immediately exit.

set -eu

CONFIG_SRC="/etc/opencanary/opencanary.conf"
CONFIG_DST="${HOME}/.opencanary.conf"

echo "[honeypot-decoy] Copying config: ${CONFIG_SRC} -> ${CONFIG_DST}"
cp "${CONFIG_SRC}" "${CONFIG_DST}"

# Remove stale twistd PID file from any previous (crashed) run.
# Without this, opencanaryd --dev refuses to start if a pid file exists.
rm -f twistd.pid

echo "[honeypot-decoy] Starting OpenCanary in foreground mode..."
exec opencanaryd --dev
