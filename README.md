# AuralisAPI

**Autonomous Zero-Trust Perimeter through eBPF-Driven Zombie API Discovery and Agentic Remediation**

AuralisAPI is a comprehensive governance platform that discovers Zombie APIs (deprecated endpoints that remain live and unmonitored) using kernel-level eBPF telemetry, classifies them with drift detection algorithms, and autonomously remediates them via a LangGraph-powered agentic workflow — including dynamic honeypot spin-up and GitOps-style gateway enforcement.

---

## What is a Zombie API?

A Zombie API is a deprecated endpoint that was never decommissioned. It still connects to production databases, retains original access privileges, and operates entirely outside active security monitoring. The 2022 Optus breach exposed 10 million records via exactly this vector.

AuralisAPI detects, classifies, and kills them — automatically.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          Host Kernel                             │
│  kprobe/tcp_sendmsg ──► ring buffer                              │
│  syscall tracepoints ──► ring buffer  ──► Redis Stream           │
│  SSL_write/SSL_read uprobes ──► ring buffer                      │
│  Go crypto/tls uprobes ──► ring buffer                           │
└───────────────────────────────┬──────────────────────────────────┘
                                │  SENSOR_MODE=live (Linux ≥ 5.8)
                   SENSOR_MODE=mock (any OS — fixture replay)
                                ▼
┌─────────────────┐    ┌─────────────────────┐    ┌──────────────────┐
│  ebpf-sensor    │───►│  remediation-brain  │───►│   api-gateway    │
│  Go 1.21        │    │  FastAPI + LangGraph│    │   KrakenD 2.7    │
│  cilium/ebpf    │    │  Python 3.12        │    │   port 8080      │
│  Page-Hinkley   │    │  Groq LLM           │    │   410 Gone       │
│  port 9090      │    │  port 8000          │    └──────────────────┘
└─────────────────┘    └─────────────────────┘
         │                      │                  ┌──────────────────┐
         │                      └─────────────────►│  honeypot-decoy  │
         │                      │                  │  OpenCanary      │
         │              ┌───────┴───────┐          │  dynamic clones  │
         │              │  PostgreSQL   │          │  port 8081/2222  │
         └─────────────►│  Redis 7      │          └──────────────────┘
                        └───────────────┘
                                │
                        ┌───────┴───────┐
                        │intelligence-ui│
                        │  Next.js 15   │
                        │  D3.js graphs │
                        │  port 3000    │
                        └───────────────┘
```

| Service | Port | Technology | Purpose |
|---|---|---|---|
| `ebpf-sensor` | 9090 (metrics) | Go 1.21, cilium/ebpf | Kernel-level HTTP + TLS telemetry, drift detection |
| `remediation-brain` | 8000 | Python 3.12, FastAPI, LangGraph | Agentic incident response + enforcement |
| `api-gateway` | 8080 | KrakenD 2.7 | Enforcement layer, 410 Gone routing |
| `honeypot-decoy` | 8081 / 2222 | OpenCanary + dynamic FastAPI | Deception layer, structural endpoint clones |
| `intelligence-ui` | 3000 | Next.js 15, D3.js | Real-time dashboard |
| `redis` | 6379 | Redis 7 | Event streaming (auralis:events) |
| `postgres` | 5432 | PostgreSQL 16 | LangGraph checkpointer + app state |

---

## Quick Start

### Prerequisites
- Docker Desktop (Windows/macOS) or Docker Engine (Linux)
- `make` (Git Bash on Windows, native on Linux/macOS)

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/hopepranav08/AuraLisAPI
cd AuraLisAPI

# 2. Create your .env from the template
make setup

# 3. Edit .env — add your keys (see Environment Variables below)

# 4. Build all Docker images
make build

# 5. Start the cluster (mock mode — works on any OS)
make up
```

| URL | What it is |
|---|---|
| `http://localhost:3000` | Intelligence Dashboard |
| `http://localhost:8000/docs` | Remediation Brain API (Swagger) |
| `http://localhost:8080` | API Gateway (all client traffic) |
| `http://localhost:8081` | Honeypot HTTP trap |
| `http://localhost:9090/drift/stats` | Live drift detection metrics |

### Live eBPF mode (Linux only)

```bash
make up-live
```

Requires Linux kernel >= 5.8, `CAP_BPF`, and `CAP_SYS_ADMIN`. On Windows/macOS, mock mode provides a full end-to-end pipeline via fixture replay.

---

## Environment Variables

```bash
# Required for LLM reasoning (free tier available)
GROQ_API_KEY=gsk_...          # Get a free key at console.groq.com/keys
GROQ_MODEL=llama-3.3-70b-versatile

# Required for OpenAPI spec diffing and PR generation
GITHUB_TOKEN=ghp_...

# Optional
SENSOR_MODE=mock              # "mock" (default) | "live" (Linux only)
SECRET_KEY=...                # FastAPI session secret
```

The brain starts and processes events without `GROQ_API_KEY` — classification falls back to heuristic rules. LLM is only used for the AI executive summary in incident reports.

---

## Sensor Modes

| Mode | OS | How it works |
|---|---|---|
| `mock` (default) | Any | Replays `ebpf-sensor/fixtures/events.jsonl` to Redis in a loop. Includes a zombie burst after 5 loops to trigger drift alarms. |
| `live` | Linux ≥ 5.8 | Attaches 9 eBPF programs: kprobe on `tcp_sendmsg`, syscall tracepoints for plain HTTP, OpenSSL uprobes for TLS, and Go `crypto/tls` uprobes for Go binaries. |

### eBPF Program Inventory (live mode)

| Source file | Program | Captures |
|---|---|---|
| `http_trace.c` | `kprobe/tcp_sendmsg` | Plain HTTP at TCP layer |
| `sensor.c` | `tracepoint/sys_enter_sendto` | Syscall-level HTTP egress |
| `sensor.c` | `tracepoint/sys_enter/exit_recvfrom` | HTTP ingress + status codes |
| `sensor.c` | `uprobe/SSL_write` | TLS egress plaintext (OpenSSL) |
| `sensor.c` | `uprobe+uretprobe/SSL_read` | TLS ingress plaintext (OpenSSL) |
| `go_tls_trace.c` | 3 uprobes on `crypto/tls` | Go TLS (register ABI, Go 1.17+) |

---

## Zombie API Classification

| Class | Definition | Severity |
|---|---|---|
| `active_zombie` | In live traffic + marked `deprecated: true` in OpenAPI spec | High (Critical if PII detected) |
| `shadow` | In live traffic but absent from the official OpenAPI spec | Medium (Critical if PII detected) |
| `dormant_zombie` | In spec but zero traffic over a defined window (Page-Hinkley) | Low |

**PII detection:** regex matching for email, SSN, credit card, phone, IBAN, DOB, passport, plus Shannon entropy analysis (≥ 4.5 bits/char for values > 20 chars) — auto-escalates severity to Critical.

---

## Drift Detection (Page-Hinkley)

The eBPF sensor runs a Page-Hinkley test on every observed endpoint in 10-second windows.

```
δ = 0.005   (insensitivity — prevents false alarms from small fluctuations)
λ = 25.0    (alarm threshold)
window = 10 seconds
min_dormant_windows = 3  (30s of zero traffic → dormant)
```

| Alarm type | Trigger |
|---|---|
| `resurrection` | Endpoint dormant ≥ 3 windows, now receiving traffic |
| `ph_threshold` | Page-Hinkley score exceeds λ = 25.0 |
| `resurrection+ph_threshold` | Both simultaneously |
| `sustained_attack` | Same endpoint alarmed in 2+ consecutive windows |

Drift alerts are published to Redis as `event_type: "drift_alert"` and routed directly to the brain's enforcement path — bypassing the standard classification pipeline.

Live scores: `GET http://localhost:9090/drift/stats`

---

## LangGraph Incident Response Workflow

```
ingest → analyze → plan ──[interrupt_before enforce]──► enforce → generate_report → END
                    │
                    └── (severity = low/medium) ────────────────► generate_report → END
```

| Node | What it does |
|---|---|
| `ingest` | Parses the Redis event, normalises fields |
| `analyze` | Diffs endpoint against GitHub OpenAPI spec; detects PII; classifies zombie type |
| `plan` | Builds remediation plan: 410 route, PR description, honeypot config |
| `enforce` | Requires human approval. Writes krakend.json PR + spins up dynamic honeypot container |
| `generate_report` | Produces structured incident report; appends AI executive summary (Groq) |

Human approval endpoint: `POST /api/incidents/{thread_id}/approve`

---

## Enforcement Actions

When the `enforce` node fires:

1. **Gateway PR** — generates a GitHub pull request adding a `410 Gone` static route to `krakend.json` for the deprecated path
2. **Dynamic honeypot** — reads the OpenAPI schema for the quarantined endpoint, generates a structural clone with realistic fake data (Faker), and spins it up as a Docker container
3. **Attacker redirection** — honeypot logs every IP, payload, and timing for threat intelligence

---

## Intelligence Dashboard

The Next.js dashboard at `http://localhost:3000` includes:

| Panel | What it shows |
|---|---|
| **Network Graph** (D3.js) | Live API dependency graph, zombie endpoints highlighted |
| **Incident Panel** | Active incidents, severity, classification, approval controls |
| **Drift Table** | Per-endpoint Page-Hinkley scores, alarm states, traffic windows |
| **Honeypot Feed** | Real-time log of attacker interactions with decoy endpoints |

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
make restart SVC=   # Restart one service (e.g. make restart SVC=remediation-brain)
```

---

## Project Structure

```
auralisapi/
├── ebpf-sensor/                  Go — eBPF kernel telemetry + drift engine
│   ├── bpf/
│   │   ├── http_trace.c          kprobe on tcp_sendmsg (Phase 1)
│   │   ├── sensor.c              syscall tracepoints + OpenSSL uprobes (Phase 2.1)
│   │   ├── go_tls_trace.c        Go crypto/tls uprobes (Phase 2.2)
│   │   └── common.h              shared BPF header: structs, macros, helpers
│   ├── sensor/
│   │   ├── live.go               eBPF loader + event publisher (Linux)
│   │   ├── live_stub.go          stub for Windows/macOS compilation
│   │   ├── mock.go               fixture replay + zombie burst injection
│   │   ├── drift.go              Page-Hinkley drift detection engine
│   │   ├── gotls.go              ELF symbol resolver for Go TLS uprobes
│   │   └── sensor.go             Sensor interface
│   ├── fixtures/events.jsonl     15 sample HTTP events for mock mode
│   └── main.go                   entrypoint + /drift/stats + /health (port 9090)
├── remediation-brain/            Python — FastAPI + LangGraph agentic engine
│   ├── agent/
│   │   ├── state.py              TypedDict state + Annotated reducers
│   │   ├── graph.py              LangGraph topology + interrupt config
│   │   ├── nodes.py              ingest/analyze/plan/enforce/report nodes
│   │   └── consumer.py           Redis XREADGROUP consumer
│   ├── api/routes.py             HTTP endpoints + human approval flow
│   ├── enforcement/
│   │   ├── krakend_mutator.py    GitHub PR generator for krakend.json
│   │   └── spec_parser.py        OpenAPI 3.0 spec reader + endpoint extractor
│   └── tests/test_nodes.py       10 pytest cases (mocked GitHub)
├── api-gateway/
│   ├── krakend.json              KrakenD v3 config — 410 routes + proxy rules
│   └── Dockerfile
├── honeypot-decoy/
│   ├── honeypot_server.py        Dynamic honeypot FastAPI server
│   ├── config_generator.py       Structural clone generator from OpenAPI schema
│   ├── opencanary.conf           OpenCanary base config (HTTP + SSH traps)
│   └── start.sh
├── intelligence-ui/              Next.js 15 dashboard
│   └── app/components/
│       ├── NetworkGraph.tsx       D3.js API dependency graph
│       ├── IncidentPanel.tsx      Incident list + approval controls
│       ├── DriftTable.tsx         Page-Hinkley live scores table
│       └── HoneypotFeed.tsx       Attacker interaction log
├── .agent/                       AI agent rules and skills (Claude Code)
│   ├── rules/                    go-ebpf-standards, krakend-gitops, langgraph-state
│   └── skills/                   d3-network-grapher, openapi-to-krakend, tls-uprobe-calculator
├── docker-compose.yml
├── Makefile
└── .env.example                  Copy to .env before running
```

---

## OWASP API Security Coverage

| OWASP API 2023 | AuralisAPI Mitigation |
|---|---|
| API9 — Improper Inventory Management | eBPF discovers all endpoints in real traffic; OpenAPI diff detects undocumented paths |
| API1/API3 — BOLA/BOPLA | Zombie classification flags deprecated endpoints lacking modern auth checks |
| API4 — Unrestricted Resource Consumption | Dormant zombie detection via Page-Hinkley; 410 enforcement cuts routes before abuse |
| API5 — Broken Function Level Authorization | Shadow API detection catches unauthorised admin paths in live traffic |
| API6 — Sensitive Business Flows | PII/PCI entropy analysis escalates severity; honeypot redirects attacker away from real data |

---

## Development Notes

- **Windows + Docker Desktop:** Run in `SENSOR_MODE=mock`. The `network_mode: host` for `ebpf-sensor` maps to the Hyper-V VM on Windows — this is expected and mock mode works transparently.
- **Live eBPF on Windows:** Run the sensor binary natively in WSL2 (`sudo SENSOR_MODE=live ./ebpf-sensor`). WSL2 kernel (~5.15) has eBPF support.
- **No GROQ_API_KEY:** The brain starts and processes events — classification uses heuristic rules only. LLM is used solely for the AI executive summary in reports.
- **No GITHUB_TOKEN:** The `analyze` node falls back to path-prefix heuristics (`/api/v1/` = deprecated) instead of live OpenAPI spec diffing. The `enforce` node skips PR generation.
- **go.sum:** Generated inside Docker by `go mod tidy`. For local Go development outside Docker, run `go mod tidy` on Linux or WSL2.
