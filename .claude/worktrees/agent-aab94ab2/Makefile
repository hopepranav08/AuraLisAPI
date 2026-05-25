# =============================================================================
# AuralisAPI — Root Makefile
# =============================================================================
# Usage:
#   make setup          Copy .env.example → .env (run once before first boot)
#   make build          Build all Docker images
#   make up             Start the full cluster in mock mode (default, any OS)
#   make up-live        Start cluster with SENSOR_MODE=live (Linux host only)
#   make down           Stop all containers (preserve volumes)
#   make clean          Stop containers and remove all volumes
#   make logs           Tail logs for all services
#   make logs-sensor    Tail logs for the eBPF sensor
#   make logs-brain     Tail logs for the remediation brain
#   make ps             Show cluster status
#   make shell-brain    Open a shell in remediation-brain
#   make shell-sensor   Open a shell in ebpf-sensor
#   make shell-ui       Open a shell in intelligence-ui
#   make lint-gateway   Validate krakend.json syntax
#   make restart SVC=   Restart a specific service (e.g. make restart SVC=remediation-brain)
# =============================================================================

.PHONY: setup build up up-live down clean logs logs-sensor logs-brain ps \
        shell-brain shell-sensor shell-ui lint-gateway restart

COMPOSE     := docker compose
SENSOR_MODE ?= mock
LOG_LEVEL   ?= info

# ── First-time setup ──────────────────────────────────────────────────────────

setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "[setup] .env created from .env.example"; \
		echo "[setup] Edit .env and add your OPENAI_API_KEY before running make up"; \
	else \
		echo "[setup] .env already exists — skipping copy"; \
	fi

# ── Build ─────────────────────────────────────────────────────────────────────

build:
	$(COMPOSE) build --parallel

# ── Lifecycle ─────────────────────────────────────────────────────────────────

up:
	SENSOR_MODE=$(SENSOR_MODE) LOG_LEVEL=$(LOG_LEVEL) $(COMPOSE) up -d
	@echo ""
	@echo "AuralisAPI cluster is up (SENSOR_MODE=$(SENSOR_MODE))"
	@echo "  UI:        http://localhost:3000"
	@echo "  Gateway:   http://localhost:8080"
	@echo "  Brain API: http://localhost:8000/docs"
	@echo "  Honeypot:  http://localhost:8081"
	@echo ""

up-live:
	@echo "[WARNING] SENSOR_MODE=live -- eBPF programs will attempt kernel injection."
	@echo "[WARNING] Requires Linux host with kernel >= 5.8 and CAP_BPF."
	SENSOR_MODE=live LOG_LEVEL=$(LOG_LEVEL) $(COMPOSE) up -d

down:
	$(COMPOSE) down

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	$(COMPOSE) down -v --remove-orphans
	@echo "[clean] All containers and volumes removed."

# ── Observability ─────────────────────────────────────────────────────────────

logs:
	$(COMPOSE) logs -f

logs-sensor:
	$(COMPOSE) logs -f ebpf-sensor

logs-brain:
	$(COMPOSE) logs -f remediation-brain

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
		exit 1; \
	fi
	$(COMPOSE) restart $(SVC)

# ── Validation ────────────────────────────────────────────────────────────────

lint-gateway:
	$(COMPOSE) run --rm api-gateway krakend check -d -c /etc/krakend/krakend.json
	@echo "[lint] krakend.json is valid."
