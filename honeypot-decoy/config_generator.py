# honeypot-decoy/config_generator.py — Dynamic OpenCanary config generator (Phase 4)
#
# OpenCanary reads its configuration from ~/.opencanary.conf (JSON format).
# This module regenerates that file whenever new zombie paths are registered,
# embedding the current node_id and logger settings.
#
# OpenCanary's HTTP module is a static content server — it cannot be configured
# to route specific URL paths. What we CAN control via config:
#   - node_id:       appears in all log events (identifies this honeypot instance)
#   - logger:        where events are sent (stdout + rotating file)
#   - http.port:     which port the HTTP trap listens on (8081)
#   - ssh.port/ver:  SSH trap configuration
#
# For path-level fake responses, the companion honeypot_server.py (port 8082)
# handles registration and response generation. OpenCanary (port 8081) acts as
# the low-level trap that logs raw HTTP probes, while honeypot_server.py handles
# intelligent per-path fake responses.
#
# reload_opencanary() sends SIGHUP to the opencanaryd process. OpenCanary does
# NOT actually support SIGHUP-based config reload — it requires a full restart.
# This function is provided for completeness and future compatibility; the
# primary dynamic mechanism is the companion honeypot_server.py on port 8082.
from __future__ import annotations

import json
import os
import signal
import subprocess
from typing import Optional

import structlog

log = structlog.get_logger(__name__)


def generate_opencanary_conf(
    quarantined_paths: list[str],
    node_id: str = "auralis-honeypot-001",
    output_path: str = "/root/.opencanary.conf",
) -> None:
    """
    Write a fresh opencanary.conf JSON file.

    Args:
        quarantined_paths: List of quarantined API paths (used to set node
                           metadata — OpenCanary HTTP module doesn't route by path).
        node_id:           Appears in all OpenCanary log events for traceability.
        output_path:       Destination for the generated config file.
                           OpenCanary reads from $HOME/.opencanary.conf by default.
    """
    # Embed the quarantined path count in node_id for observability.
    effective_node_id = (
        f"{node_id}-{len(quarantined_paths)}paths"
        if quarantined_paths
        else node_id
    )

    conf: dict = {
        "device.node_id": effective_node_id,

        # ── Disabled modules ───────────────────────────────────────────────────
        "git.enabled":    False,
        "ftp.enabled":    False,
        "https.enabled":  False,
        "mysql.enabled":  False,
        "snmp.enabled":   False,
        "ntp.enabled":    False,
        "rdp.enabled":    False,
        "sip.enabled":    False,
        "tftp.enabled":   False,
        "vnc.enabled":    False,

        # ── HTTP trap (port 8081) ──────────────────────────────────────────────
        "http.enabled":   True,
        "http.port":      8081,
        "http.skin":      "basicLogin",
        "http.skin.list": [
            {"desc": "AuralisAPI Deception Layer", "name": "basicLogin"}
        ],

        # ── SSH trap (port 2222) ───────────────────────────────────────────────
        "ssh.enabled":    True,
        "ssh.port":       2222,
        "ssh.version":    "SSH-2.0-OpenSSH_5.1p1 Debian-4",

        # ── Logger: stdout + rotating file ────────────────────────────────────
        "logger": {
            "class":  "PyLogger",
            "kwargs": {
                "formatters": {
                    "plain": {"format": "%(message)s"}
                },
                "handlers": {
                    "console": {
                        "class":  "logging.StreamHandler",
                        "stream": "ext://sys.stdout",
                    },
                    "file": {
                        "class":      "logging.handlers.RotatingFileHandler",
                        "filename":   "/tmp/opencanary.log",
                        "maxBytes":   10_485_760,   # 10 MB
                        "backupCount": 3,
                    },
                },
            },
        },
    }

    conf_str = json.dumps(conf, indent=4)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(conf_str)
        log.info(
            "opencanary.conf generated",
            output_path=output_path,
            node_id=effective_node_id,
            quarantined_path_count=len(quarantined_paths),
        )
    except OSError as exc:
        log.error("failed to write opencanary.conf", error=str(exc), path=output_path)
        raise


def reload_opencanary() -> bool:
    """
    Attempt to send SIGHUP to the opencanaryd process.

    NOTE: OpenCanary does not officially support SIGHUP-based config reload.
    A true reload requires a process restart. This function is a best-effort
    attempt for potential future OpenCanary support and does not raise on failure.

    Returns:
        True if at least one SIGHUP was delivered, False otherwise.
    """
    try:
        result = subprocess.run(
            ["pgrep", "-f", "opencanaryd"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        pids = [p.strip() for p in result.stdout.strip().splitlines() if p.strip()]
        if not pids:
            log.debug("opencanaryd process not found — no SIGHUP sent")
            return False

        delivered = False
        for pid_str in pids:
            try:
                os.kill(int(pid_str), signal.SIGHUP)
                log.info("SIGHUP delivered to opencanaryd", pid=pid_str)
                delivered = True
            except (ProcessLookupError, PermissionError, ValueError) as exc:
                log.warning("SIGHUP failed", pid=pid_str, error=str(exc))
        return delivered

    except FileNotFoundError:
        log.debug("pgrep not available — cannot find opencanaryd PID")
        return False
    except subprocess.TimeoutExpired:
        log.warning("pgrep timed out while searching for opencanaryd")
        return False
    except Exception as exc:
        log.warning("reload_opencanary failed unexpectedly", error=str(exc))
        return False
