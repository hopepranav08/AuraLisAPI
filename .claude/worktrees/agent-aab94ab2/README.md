# AuralisAPI

**Autonomous Zero-Trust Perimeter through eBPF-Driven Zombie API Discovery and Agentic Remediation**

AuralisAPI is a comprehensive governance platform that discovers Zombie APIs (deprecated endpoints that remain live and unmonitored) using kernel-level eBPF telemetry, classifies them with drift detection algorithms, and autonomously remediates them via a LangGraph-powered agentic workflow.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Host Kernel                           │
│  eBPF kprobe/tcp_sendmsg ──► ring buffer ──► Redis Stream    │
└────────────────────────────────┬─────────────────────────────┘
                                 │ SENSOR_MODE=live (Linux only)
                    SENSOR_MODE=mock (any OS)
                                 ▼
┌─────────────┐    ┌────────────────────┐    ┌─────────────────┐
│ ebpf-sensor │───►│ remediation-brain  │───►│  api-gateway    │
│  Go 1.21    │    │ FastAPI + LangGraph│    │  KrakenD 2.7    │
│  cilium/ebpf│    │  Python 3.12       │    │  port 8080      │
└─────────────┘    └────────────────────┘    └─────────────────┘
                            │                        │
                   ┌────────┴──────┐       ┌────────┴──────┐
                   │  PostgreSQL   │       │ intelligence-ui│
                   │  Redis 7      │       │  Next.js 15   │
                   └───────────────┘       └───────────────┘
                                                    │
                                           ┌────────┴──────┐
                                           │honeypot-decoy │
                                           │  OpenCanary   │
                                           └───────────────┘
```

| Service | Port | Technology | Purpose |
|---|---|---|---|
| `ebpf-sensor` | — | Go 1.21, cilium/ebpf | Kernel-level HTTP telemetry |
| `remediation-brain` | 8000 | Python 3.12, FastAPI, LangGraph | Agentic incident response |
| `api-gateway` | 8080 | KrakenD 2.7 | Enforcement, 410 Gone routing |
| `honeypot-decoy` | 8081/2222 | OpenCanary | Deception layer |
| `intelligence-ui` | 3000 | Next.js 15, D3.js | Dashboard |
| `redis` | 6379 | Redis 7 | Event streaming |
| `postgres` | 5432 | PostgreSQL 16 | LangGraph checkpointer + app data |

---

## Quick Start

### Prerequisites
- Docker Desktop (Windows/macOS) or Docker Engine (Linux)
- `make` (Git Bash on Windows, native on Linux/macOS)

### First-time setup
```bash
# 1. Clone and enter the repo
git clone https://github.com/your-org/auralisapi
cd auralisapi

# 2. Create your .env from the template
make setup
# Edit .env and add your OPENAI_API_KEY

# 3. Build all Docker images
make build

# 4. Start the cluster (mock mode — works on any OS)
make up
```

Open `http://localhost:3000` for the Intelligence Dashboard.
Open `http://localhost:8000/docs` for the Remediation Brain API.

### Live eBPF mode (Linux hosts only)
```bash
make up-live
```
Requires Linux kernel >= 5.8, `CAP_BPF`, and `CAP_SYS_ADMIN`.

---

## Sensor Modes

| Mode | OS | How it works |
|---|---|---|
| `mock` (default) | Any | Replays `ebpf-sensor/fixtures/events.jsonl` to Redis in a loop |
| `live` | Linux only | Attaches eBPF kprobe to `tcp_sendmsg`, captures real HTTP traffic |

---

## Zombie API Classification

The `remediation-brain` classifies detected endpoints into three categories:

| Class | Definition | Severity |
|---|---|---|
| `active_zombie` | Endpoint in live traffic but marked deprecated (e.g. `/api/v1/*`) | High / Critical (if PII) |
| `shadow` | Endpoint in live traffic but absent from the official OpenAPI spec | Medium / Critical (if PII) |
| `dormant_zombie` | Endpoint in spec but with zero traffic over a defined window | Low |

---

## LangGraph Incident Response Workflow

```
ingest → classify → assess_risk ──► enforce ──► report
                         │              ▲
                         │        [human approval
                         │         required here]
                         └──────────────────────► report
                           (low severity: skip enforce)
```

The `enforce` node is guarded by `interrupt_before` — a human must approve before any gateway configuration is modified.

---

## Makefile Commands

```bash
make setup          # Copy .env.example → .env (run once)
make build          # Build all Docker images
make up             # Start cluster (mock mode)
make up-live        # Start cluster (live eBPF, Linux only)
make down           # Stop containers (preserve data)
make clean          # Stop containers + delete volumes
make logs           # Tail all logs
make logs-sensor    # Tail eBPF sensor logs
make logs-brain     # Tail remediation brain logs
make ps             # Show container status
make shell-brain    # Shell into remediation-brain
make shell-sensor   # Shell into ebpf-sensor
make lint-gateway   # Validate krakend.json
make restart SVC=   # Restart one service
```

---

## Project Structure

```
auralisapi/
├── ebpf-sensor/          # Go — eBPF kernel telemetry sensor
│   ├── bpf/              # C — eBPF program (http_trace.c)
│   ├── sensor/           # Go — live (eBPF) and mock implementations
│   └── fixtures/         # JSONL — mock event data for development
├── remediation-brain/    # Python — FastAPI + LangGraph agent
│   ├── agent/            # LangGraph state, graph, nodes
│   └── api/              # FastAPI routes
├── api-gateway/          # KrakenD configuration
├── honeypot-decoy/       # OpenCanary deception service
├── intelligence-ui/      # Next.js 15 dashboard
├── infra/                # Kubernetes / Terraform (future phases)
├── scripts/              # Developer utilities (future phases)
├── .agent/               # AI agent rules and skills
├── docker-compose.yml
├── Makefile
└── .env.example          # Copy to .env before running
```

---

## OWASP Coverage

| OWASP API 2023 | AuralisAPI Mitigation |
|---|---|
| API9 — Improper Inventory Management | eBPF discovers all endpoints; OpenAPI diff detects undocumented paths |
| API1/API3 — BOLA/BOPLA | Zombie API classification flags deprecated endpoints lacking auth |
| API4 — Unrestricted Resource Consumption | Dormant zombie detection via Page-Hinkley drift test |
| API5 — Broken Function Level Authorization | Shadow API detection catches unauthorised admin paths |

---

## Development Notes

- **Windows + Docker Desktop**: Run in `SENSOR_MODE=mock`. The `network_mode: host` for `ebpf-sensor` maps to the Hyper-V VM on Windows — this is expected and mock mode works transparently.
- **go.sum**: Not committed. Generated automatically by `go mod tidy` inside the Docker build. For local Go development, run `go mod tidy` on a Linux machine or WSL2.
- **OPENAI_API_KEY**: Required for the LangGraph LLM reasoning nodes. The service starts and accepts requests without it, but classification will use heuristics only (no LLM calls).
