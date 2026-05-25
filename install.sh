#!/usr/bin/env bash
# =============================================================================
# AuralisAPI — One-Command Sensor Installer
# =============================================================================
# Usage (company server, Linux):
#   curl -sSL https://auralisapi.dev/install.sh | \
#     BRAIN_URL=https://auralisapi.dev COMPANY_TOKEN=your-token bash
#
# Or with explicit args:
#   bash install.sh --brain-url https://auralisapi.dev --token your-token
#
# What this does:
#   1. Checks for Docker (required)
#   2. Pulls the AuralisAPI sensor image
#   3. Runs it as a privileged container with kernel eBPF access
#   4. Sensor registers with the hosted brain at BRAIN_URL
#   5. Within 60s the dashboard shows your endpoints and any zombie APIs
#
# Supported: Ubuntu 20.04+, Debian 11+, Amazon Linux 2023, RHEL 8+
# Requires:  Docker, Linux kernel >= 5.8, root or sudo
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
BRAIN_URL="${BRAIN_URL:-https://auralisapi.dev}"
COMPANY_TOKEN="${COMPANY_TOKEN:-demo-token-$(hostname | tr -dc 'a-z0-9' | head -c 6)}"
SENSOR_MODE="${SENSOR_MODE:-live}"
IMAGE="ghcr.io/hopepranav08/auralisapi-sensor:latest"
CONTAINER_NAME="auralis-sensor"

# ── Color helpers ─────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[AuralisAPI]${RESET} $*"; }
success() { echo -e "${GREEN}[AuralisAPI] ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}[AuralisAPI] ⚠${RESET} $*"; }
error()   { echo -e "${RED}[AuralisAPI] ✗${RESET} $*" >&2; exit 1; }

# ── Parse CLI args ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --brain-url) BRAIN_URL="$2"; shift 2 ;;
    --token)     COMPANY_TOKEN="$2"; shift 2 ;;
    --mode)      SENSOR_MODE="$2"; shift 2 ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}  ▄▄▄·  ▄• ▄▌▄▄▄   ▄▄▄· ▄▄▌  ▪  .▄▄ ·  ▄▄▄·  ▄▄▄·${RESET}"
echo -e "${CYAN}  ▐█ ▀█ █▪██▌▀▄ █· ▐█ ▀█ ██•  ██ ▐█ ▀. ▐█ ▀█ ▐█ ▄█${RESET}"
echo -e "${CYAN}  ▄█▀▀█ █▌▐█▌▐▀▀▄  ▄█▀▀█ ██▪  ▐█·▄▀▀▀█▄▄█▀▀█  ██▀·${RESET}"
echo ""
echo -e "  ${CYAN}AuralisAPI${RESET} — Autonomous Zero-Trust API Perimeter"
echo -e "  eBPF Sensor Installer v1.0"
echo ""
echo -e "  Brain URL:  ${GREEN}${BRAIN_URL}${RESET}"
echo -e "  Token:      ${GREEN}${COMPANY_TOKEN}${RESET}"
echo -e "  Mode:       ${GREEN}${SENSOR_MODE}${RESET}"
echo -e "  Host:       ${GREEN}$(hostname)${RESET}"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────
info "Running pre-flight checks..."

if ! command -v docker &>/dev/null; then
  error "Docker not found. Install Docker first: https://get.docker.com"
fi
success "Docker found: $(docker --version | cut -d' ' -f3 | tr -d ',')"

if [[ "${SENSOR_MODE}" == "live" ]]; then
  KERNEL=$(uname -r | cut -d. -f1-2 | tr -d '.')
  if [[ "${KERNEL}" -lt 58 ]]; then
    warn "Kernel $(uname -r) < 5.8 — switching to mock mode (eBPF requires 5.8+)"
    SENSOR_MODE="mock"
  else
    success "Kernel $(uname -r) supports eBPF"
  fi
fi

# ── Remove existing container if present ─────────────────────────────────────
if docker inspect "${CONTAINER_NAME}" &>/dev/null 2>&1; then
  info "Stopping existing ${CONTAINER_NAME} container..."
  docker rm -f "${CONTAINER_NAME}" &>/dev/null
fi

# ── Pull image ────────────────────────────────────────────────────────────────
info "Pulling AuralisAPI sensor image..."
docker pull "${IMAGE}" 2>&1 | tail -3
success "Image ready"

# ── Run sensor ────────────────────────────────────────────────────────────────
info "Starting sensor in ${SENSOR_MODE} mode..."

DOCKER_ARGS=(
  "run" "--detach"
  "--name" "${CONTAINER_NAME}"
  "--restart" "unless-stopped"
  "--privileged"
  "--pid" "host"
  "--network" "host"
  "--cap-add" "SYS_ADMIN" "--cap-add" "BPF" "--cap-add" "NET_ADMIN"
  "--cap-add" "SYS_PTRACE" "--cap-add" "PERFMON"
  "--ulimit" "memlock=-1:-1"
  "-v" "/sys/kernel/debug:/sys/kernel/debug:rw"
  "-v" "/sys/fs/bpf:/sys/fs/bpf:rw"
  "-e" "SENSOR_MODE=${SENSOR_MODE}"
  "-e" "BRAIN_URL=${BRAIN_URL}"
  "-e" "COMPANY_TOKEN=${COMPANY_TOKEN}"
  "-e" "SENSOR_ID=sensor-$(hostname | tr -dc 'a-z0-9')"
  "-e" "REDIS_ADDR=127.0.0.1:6379"
  "-e" "METRICS_PORT=9090"
  "${IMAGE}"
)

CONTAINER_ID=$(docker "${DOCKER_ARGS[@]}")
success "Container started: ${CONTAINER_ID:0:12}"

# ── Wait for connection ───────────────────────────────────────────────────────
info "Connecting to brain at ${BRAIN_URL}..."
sleep 3

MAX_WAIT=30
ELAPSED=0
while [[ $ELAPSED -lt $MAX_WAIT ]]; do
  LOGS=$(docker logs "${CONTAINER_NAME}" 2>&1 | tail -20)
  if echo "${LOGS}" | grep -q "sensor registered with brain"; then
    break
  fi
  if echo "${LOGS}" | grep -q "brain register: connection failed"; then
    warn "Could not reach brain at ${BRAIN_URL} (will retry in background)"
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
success "AuralisAPI sensor is running"
echo ""
echo -e "  Sensor ID:   ${CYAN}sensor-$(hostname | tr -dc 'a-z0-9')${RESET}"
echo -e "  Mode:        ${CYAN}${SENSOR_MODE}${RESET}"
echo -e "  Dashboard:   ${CYAN}${BRAIN_URL}/dashboard${RESET}"
echo ""
echo -e "  ${YELLOW}Your endpoints will appear in the dashboard within 30 seconds.${RESET}"
echo -e "  ${YELLOW}Any zombie APIs discovered will trigger an automated incident.${RESET}"
echo ""
echo -e "  Manage sensor:"
echo -e "    docker logs -f ${CONTAINER_NAME}    # stream sensor logs"
echo -e "    docker stop ${CONTAINER_NAME}        # stop sensor"
echo -e "    docker rm   ${CONTAINER_NAME}        # remove sensor"
echo ""
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
