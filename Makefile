# =============================================================================
# AuralisAPI — Root Makefile
# =============================================================================
# Usage:
#   make setup          Copy .env.example → .env (run once before first boot)
#   make build          Build all Docker images
#   make up             Start the full cluster (mock mode, any OS)
#   make start          Build images AND start cluster in one command
#   make down           Stop all containers (preserve volumes)
#   make clean          Stop containers and remove all volumes
#   make logs           Tail logs for all services
#   make logs-brain     Tail logs for the remediation brain
#   make logs-sensor    Tail logs for the eBPF sensor
#   make logs-ui        Tail logs for the intelligence UI
#   make logs-gateway   Tail logs for the API gateway
#   make logs-honeypot  Tail logs for the honeypot decoy
#   make ps             Show cluster status
#   make shell-brain    Open a shell in remediation-brain
#   make shell-sensor   Open a shell in ebpf-sensor
#   make shell-ui       Open a shell in intelligence-ui
#   make lint-gateway   Validate krakend.json syntax
#   make restart SVC=   Restart a specific service
#   make up-live        Linux only — real eBPF kernel injection
# =============================================================================

.PHONY: setup build up start up-live down clean \
        logs logs-brain logs-sensor logs-ui logs-gateway logs-honeypot \
        ps shell-brain shell-sensor shell-ui lint-gateway restart

COMPOSE     := docker compose
SENSOR_MODE ?= mock
LOG_LEVEL   ?= info


# ── First-time setup ──────────────────────────────────────────────────────────

setup:
	@python -c "import os, shutil; shutil.copy('.env.example', '.env') if not os.path.exists('.env') else print('[setup] .env already exists — skipping copy')"
	@echo "[setup] .env ready. Fill in GROQ_API_KEY and GITHUB_TOKEN before running make up."

# ── Build ─────────────────────────────────────────────────────────────────────

build:
	$(COMPOSE) build --parallel

# ── Lifecycle ─────────────────────────────────────────────────────────────────

# start = build + up in one command (most common first-run workflow)
start: build up

up:
	@python -c "import os,sys; sys.exit('[error] .env not found — run: make setup') if not os.path.exists('.env') else None"
	$(COMPOSE) up -d
	@echo ""
	@echo "  AuralisAPI is running (SENSOR_MODE=$(SENSOR_MODE))"
	@echo ""
	@echo "  Dashboard:   http://localhost:3000"
	@echo "  Gateway:     http://localhost:8080"
	@echo "  Brain API:   http://localhost:8000/docs"
	@echo "  Honeypot:    http://localhost:8081"
	@echo "  Drift stats: http://localhost:9090/drift/stats"
	@echo ""
	@echo "  Run 'make ps' to check container health."
	@echo "  Run 'make logs' to tail all logs."
	@echo ""

up-live:
	@python -c "import os,sys; sys.exit('[error] .env not found — run: make setup') if not os.path.exists('.env') else None"
	@echo "[WARNING] SENSOR_MODE=live — eBPF programs will attempt kernel injection."
	@echo "[WARNING] Requires Linux host with kernel >= 5.8 and CAP_BPF."
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	$(COMPOSE) down -v --remove-orphans
	@echo "[clean] All containers and volumes removed."

# ── Logs ──────────────────────────────────────────────────────────────────────

logs:
	$(COMPOSE) logs -f

logs-brain:
	$(COMPOSE) logs -f remediation-brain

logs-sensor:
	$(COMPOSE) logs -f ebpf-sensor

logs-ui:
	$(COMPOSE) logs -f intelligence-ui

logs-gateway:
	$(COMPOSE) logs -f api-gateway

logs-honeypot:
	$(COMPOSE) logs -f honeypot-decoy

# ── Status ────────────────────────────────────────────────────────────────────

ps:
	$(COMPOSE) ps

# ── Developer Shells ──────────────────────────────────────────────────────────

shell-brain:
	$(COMPOSE) exec remediation-brain bash

shell-sensor:
	$(COMPOSE) exec ebpf-sensor sh

shell-ui:
	$(COMPOSE) exec intelligence-ui sh

# ── Service restart ───────────────────────────────────────────────────────────

restart:
	@if [ -z "$(SVC)" ]; then \
		echo "Usage: make restart SVC=<service-name>"; \
		echo "       e.g.  make restart SVC=remediation-brain"; \
		exit 1; \
	fi
	$(COMPOSE) restart $(SVC)

# ── Validation ────────────────────────────────────────────────────────────────

lint-gateway:
	$(COMPOSE) run --rm api-gateway krakend check -d -c /etc/krakend/krakend.json
	@echo "[lint] krakend.json is valid."
