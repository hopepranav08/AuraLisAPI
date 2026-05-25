# AuralisAPI — Development Log

This file is a running log of what was built, what was fixed, and what comes next.
It serves as context for every future session so we never lose track of state.

---

## Session 1 — 2026-03-09 (Phase 1: Infrastructure Scaffolding)

### What We Did

Built and fully debugged the entire Phase 1 infrastructure from scratch.
Every Docker image now builds cleanly and all 7 containers run healthy.

### System Overview

AuralisAPI is an autonomous Zombie API detection and remediation platform.
A Zombie API is a deprecated endpoint that was never decommissioned — it still
connects to production data but receives no security updates or monitoring.
Real-world example: the 2022 Optus breach exposed 10M records via exactly this.

**Architecture — 7 containers via Docker Compose:**

```
intelligence-ui   (Next.js 15)          → Dashboard         port 3000
api-gateway       (KrakenD 2.7)         → Traffic cop       port 8080
remediation-brain (FastAPI + LangGraph) → AI brain          port 8000
honeypot-decoy    (OpenCanary)          → Attacker trap     port 8081 / 2222
ebpf-sensor       (Go + cilium/ebpf)    → Kernel spy        (no port)
redis             (Redis 7)             → Event queue       port 6379
postgres          (PostgreSQL 16)       → State storage     port 5432
```

**Data flow:**

```
ebpf-sensor captures HTTP traffic at kernel level
    → pushes events to Redis Stream (auralis:events)
        → remediation-brain consumes events
            → LangGraph workflow: ingest → classify → assess_risk → enforce → generate_report
                → api-gateway enforces 410 Gone on deprecated paths
                    → honeypot-decoy traps attackers who probe quarantined paths
                        → intelligence-ui shows everything on the dashboard
```

---

### Real Bugs Found and Fixed (docker compose build + runtime)

All of these were broken in the original scaffolding and fixed in this session:

| # | File | Bug | Fix Applied |
|---|------|-----|-------------|
| 1 | `honeypot-decoy/requirements.txt` | `requests==2.32.3` conflicts with opencanary 0.9.3 which requires 2.31.0 | Changed to `requests==2.31.0` |
| 2 | `remediation-brain/requirements.txt` | `frouros==0.8.1` does not exist for Python 3.12 (versions jump 0.8.0 → 0.9.0) | Changed to `frouros==0.9.0` |
| 3 | `remediation-brain/requirements.txt` | `numpy==2.2.0` conflicts with frouros 0.9.0 which requires numpy<2.2 | Changed to `numpy==2.1.3` |
| 4 | `ebpf-sensor/Dockerfile` | `go mod tidy` ran before source was copied so it saw no packages and generated nothing | Moved `COPY . .` before `go mod tidy` |
| 5 | `ebpf-sensor/tools.go` | No tool dependency file existed, so bpf2go was invisible to `go mod tidy` | Created `tools.go` with `import _ "github.com/cilium/ebpf/cmd/bpf2go"` under `//go:build tools` |
| 6 | `ebpf-sensor/Dockerfile` | Missing `linux-libc-dev` package — clang couldn't find `asm/types.h` | Added `linux-libc-dev` to apt-get and symlinked `asm/` headers |
| 7 | `ebpf-sensor/bpf/http_trace.c` | Used `struct msghdr` / `struct iov_iter` via incomplete kernel headers — clang rejected them | Rewrote with BPF CO-RE shadow structs using `__attribute__((preserve_access_index))` |
| 8 | `ebpf-sensor/bpf/http_trace.c` | Used `bool` type which does not exist in kernel BPF context | Replaced all `bool` with `__u8` |
| 9 | `ebpf-sensor/bpf/http_trace.c` | `char buf[512]` exceeded the BPF 512-byte stack limit when combined with other locals | Reduced `MAX_BUF_LEN` to 256 and `MAX_PATH_LEN` to 128 |
| 10 | `ebpf-sensor/bpf/http_trace.c` | `PT_REGS_PARM2` / `BPF_KPROBE` required full `struct pt_regs` definition | Added `#include <asm/ptrace.h>` before bpf_tracing.h |
| 11 | `ebpf-sensor/bpf/http_trace.c` | Used classic kprobe with PT_REGS — not arch-aware | Switched to `BPF_KPROBE` macro with `-target amd64 -D__TARGET_ARCH_x86` |
| 12 | `ebpf-sensor/main.go` → `sensor/live.go` | `//go:generate` was in `main` package so bpf2go generated files landed there, not in the `sensor` package that uses them | Moved directive to `sensor/live.go` with corrected relative path `../bpf/http_trace.c` |
| 13 | `ebpf-sensor/sensor/live.go` | Struct `httpEventC` still had `Path [256]byte` and `eventSize = 288` after path length was reduced | Updated to `Path [128]byte`, `eventSize = 160` |
| 14 | `api-gateway/krakend.json` | Wrong extra_config namespace `"proxy": {"static": {...}}` — KrakenD v3 requires flat key | Fixed to `"proxy/static": {...}` |
| 15 | `api-gateway/krakend.json` | `__comment` fields are not valid in KrakenD v3 endpoint definitions | Removed all `__comment` fields |
| 16 | `docker-compose.yml` | Obsolete `version: "3.9"` top-level key causes warnings in modern Docker Compose | Removed the version field |
| 17 | `remediation-brain/agent/graph.py` | Node named `"report"` conflicts with state key `report` — LangGraph raises `ValueError` at startup | Renamed node to `"generate_report"` and updated all edges |
| 18 | `honeypot-decoy/opencanary.conf` | Missing required `"logger"` section — OpenCanary crashes on startup | Added `PyLogger` config block with stdout handler |
| 19 | `honeypot-decoy/start.sh` | Stale `twistd.pid` from a crashed container causes `Another twistd server is running` error on restart | Added `rm -f twistd.pid` before starting opencanaryd |

---

### Current State of Each Service

| Service | Status | Notes |
|---------|--------|-------|
| `ebpf-sensor` | ✅ Running | Mock mode — replays `fixtures/events.jsonl` in a loop. Live eBPF requires native Linux kernel ≥ 5.8 |
| `remediation-brain` | ✅ Running + Healthy | LangGraph falls back to MemorySaver (no persistent checkpoints) when Postgres tables not yet set up — this is expected |
| `api-gateway` | ✅ Running + Healthy | `/api/v1/*` returns static 410-body JSON. KrakenD proxies `/api/inventory`, `/api/incidents`, `/api/remediate` to the brain |
| `honeypot-decoy` | ✅ Running + Healthy | HTTP trap on 8081, SSH trap on 2222. Logs all interactions to stdout as JSON |
| `intelligence-ui` | ✅ Running | Dashboard at localhost:3000. Stats show `—` (placeholder) — real data wiring is Phase 2 |
| `redis` | ✅ Healthy | Sensor publishes to `auralis:events` stream |
| `postgres` | ✅ Healthy | Ready for LangGraph checkpoint tables |

---

### Key Technical Decisions Made

**eBPF struct layout (http_event_t) — current sizes:**
```
__u32 pid           offset  0,   4 bytes
__u32 tid           offset  4,   4 bytes
__u64 timestamp_ns  offset  8,   8 bytes
__u16 status_code   offset 16,   2 bytes
char  method[8]     offset 18,   8 bytes
char  path[128]     offset 26, 128 bytes
tail padding                    6 bytes
sizeof = 160
```

**LangGraph graph topology:**
```
ingest → classify → assess_risk → [interrupt] → enforce → generate_report → END
                                       └──────────────────→ generate_report → END
                                         (if severity is low/medium, skip enforce)
```

**Why two DB connection strings:**
- `DATABASE_URL` = `postgresql+asyncpg://...` — used by SQLAlchemy (Python async ORM)
- `LANGGRAPH_DB_URL` = `postgresql://...` — used by LangGraph's `AsyncPostgresSaver` which requires plain psycopg3, not asyncpg

---

## Session 2 — 2026-03-10 (Phase 2: eBPF Kernel Telemetry + TLS Inspection)

### What We Built

Extended the eBPF sensor layer with a comprehensive second program (`bpf/sensor.c`)
that adds syscall-level plaintext capture and OpenSSL TLS interception alongside
the existing kprobe/tcp_sendmsg from Phase 1.

### New Files

| File | Purpose |
|------|---------|
| `ebpf-sensor/bpf/sensor.c` | 6-program eBPF sensor: 3 syscall tracepoints + 3 SSL uprobes |

### Modified Files

| File | Change |
|------|--------|
| `ebpf-sensor/sensor/live.go` | Added `//go:generate` for sensor.c; added `SensorEvent`, `sensorEventC`, `parseSensorEvent`, `findLibSSL`, `publishSensorEvent`, `runSensorPrograms`; wired goroutine into `Run()` |
| `ebpf-sensor/Dockerfile` | Added `libssl-dev` to builder stage; added `libssl3` to runtime stage |

### sensor.c Program Inventory

| SEC name | C function | Captures |
|----------|-----------|---------|
| `tracepoint/syscalls/sys_enter_sendto` | `tp_sendto` | Plain HTTP sends at syscall boundary (TCP+UDP) |
| `tracepoint/syscalls/sys_enter_recvfrom` | `tp_enter_recvfrom` | Saves recvfrom buf pointer to `recvfrom_args` map |
| `tracepoint/syscalls/sys_exit_recvfrom` | `tp_exit_recvfrom` | Reads kernel-filled buf; extracts HTTP status code |
| `uprobe/SSL_write` | `uprobe_ssl_write` | TLS egress: plaintext before OpenSSL encrypts |
| `uprobe/SSL_read` | `uprobe_ssl_read_enter` | Saves SSL_read buf pointer to `ssl_read_args` map |
| `uretprobe/SSL_read` | `uprobe_ssl_read_exit` | TLS ingress: reads decrypted buf after OpenSSL returns |

### sensor_event_t Layout (sensor.c → sensorEventC in live.go)

```
__u32  pid;           offset  0,  4 bytes
__u32  tid;           offset  4,  4 bytes
__u64  timestamp_ns;  offset  8,  8 bytes
__u16  status_code;   offset 16,  2 bytes
__u8   source;        offset 18,  1 byte  (0=plain, 1=tls)
__u8   direction;     offset 19,  1 byte  (0=egress, 1=ingress)
char   method[8];     offset 20,  8 bytes
char   path[128];     offset 28, 128 bytes
__u8   _pad[4];       offset 156, 4 bytes → sizeof = 160
```

### Memory Safety Decisions

1. **Stack budget per program:** `char buf[256]` (256) + locals (~64) = ~320 bytes < 512-byte BPF limit
2. **bpf_probe_read_user guards:** NULL pointer check + `min(len, MAX_BUF_LEN)` clamp before every read
3. **Ring buffer discipline:** `bpf_ringbuf_reserve` NULL-checked; `bpf_ringbuf_discard` on every error path after a successful reserve — no slots are ever abandoned
4. **Map entry cleanup:** `ssl_read_args` and `recvfrom_args` entries deleted unconditionally in exit probes (before conditional returns) — prevents stale state if a thread is killed between entry and exit
5. **Non-HTTP early exit:** `parse_http_method` called before `bpf_ringbuf_reserve` — discards irrelevant TCP/TLS payloads without touching the ring buffer
6. **Bounded loops:** all loops use `#pragma unroll` with explicit constant bounds — BPF verifier can statically prove termination

### Architecture of Two Parallel Data Paths

```
Linux kernel
├── kprobe/tcp_sendmsg          (http_trace.c, Phase 1)
│   └── HttpEvent → Redis auralis:events
└── tracepoints + SSL uprobes   (sensor.c, Phase 2)
    └── SensorEvent (+ source/direction fields) → Redis auralis:events
```

Both paths publish JSON to the same Redis stream. `remediation-brain` consumes
all events; `source` and `direction` fields allow the brain to distinguish
the data path and apply different classification logic.

### TLS Coverage Notes

- **Covered:** Python requests, curl, Node.js https, Java HttpsURLConnection — all use libssl.so
- **Not covered (future):** Go `crypto/tls` (static binary — requires uprobes on specific Go TLS function offsets, planned for Phase 3 Agentic API Protection)
- **Graceful degradation:** if `libssl.so` is not found at container startup, uprobes are skipped and a warning is logged; tracepoints continue running

### bpf2go Generated Names (sensor.c → Go)

| C function name | bpf2go generates | Used in live.go as |
|-----------------|------------------|--------------------|
| `tp_sendto` | `SensorPrograms.TpSendto` | `sObjs.TpSendto` |
| `tp_enter_recvfrom` | `SensorPrograms.TpEnterRecvfrom` | `sObjs.TpEnterRecvfrom` |
| `tp_exit_recvfrom` | `SensorPrograms.TpExitRecvfrom` | `sObjs.TpExitRecvfrom` |
| `uprobe_ssl_write` (via BPF_UPROBE) | `SensorPrograms.UprobiSslWrite` | `sObjs.UprobiSslWrite` |
| `uprobe_ssl_read_enter` (via BPF_UPROBE) | `SensorPrograms.UprobiSslReadEnter` | `sObjs.UprobiSslReadEnter` |
| `uprobe_ssl_read_exit` (plain fn) | `SensorPrograms.UprobiSslReadExit` | `sObjs.UprobiSslReadExit` |

### Bugs Found and Fixed (post-implementation audit)

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `bpf/sensor.c` | `struct syscall_enter_ctx` had `preserve_access_index` — name doesn't exist in kernel BTF, CO-RE relocation fails at load time | Replaced shadow structs entirely with `tp_read_arg()` / `tp_read_ret()` helpers using `bpf_probe_read_kernel` at ABI-stable byte offsets (offset 16+n×8 for args, offset 16 for ret) |
| 2 | `bpf/sensor.c` | `emit_response_event` never initialised `evt->method` / `evt->path`; `bpf_ringbuf_reserve` does NOT zero memory → garbage bytes in events published to Redis | Added `__builtin_memset(evt, 0, sizeof(*evt))` immediately after the NULL check on the reserved slot |
| 3 | `bpf/sensor.c` | `extract_path`'s `buf[idx]` guard used runtime variable `read_len` — BPF verifier cannot statically prove array access in-bounds | Changed guard to constant `MAX_BUF_LEN` — verifier can now statically prove `idx < 256` |
| 4 | `sensor/live.go` | Three field references `sObjs.UprobiSsl*` (typo: "Urobi" vs "Uprobe") — undefined field, Go compile error | Fixed to `UprobeSslWrite`, `UprobeSslReadEnter`, `UprobeSslReadExit` matching bpf2go CamelCase from `uprobe_ssl_*` |

### Dev Environment: Windows → Linux (Hackathon Deployment)

**Current state:** All development on Windows 11 with Docker Desktop. `SENSOR_MODE=mock` works everywhere — replays `fixtures/events.jsonl` through the full pipeline.

**Live eBPF requires Linux kernel >= 5.8.** Three options for hackathon day:

| Option | Effort | Notes |
|--------|--------|-------|
| **Mock mode** (default) | Zero | Works now. Full pipeline is live — only packet capture is simulated. Sufficient for 90% of judges. |
| **WSL2 live mode** | Low | Run sensor binary natively in WSL2 (`sudo SENSOR_MODE=live ./ebpf-sensor`). WSL2 kernel (~5.15) has eBPF. Tracepoints more reliable than kprobes in this env. Test with: `wsl -- sudo cat /proc/config.gz \| gunzip \| grep CONFIG_BPF` |
| **Cloud VM** | Medium | Spin up Ubuntu 22.04 EC2/GCP, `docker compose up`, run sensor with `SENSOR_MODE=live`. Full live kernel capture for the "wow moment" |

**Recommended:** Lead demo in mock mode (guaranteed), have cloud VM as backup for live eBPF demonstration.

---

## Session 3 — 2026-03-12 (Phase 2.2: Go Orchestrator + Drift Detection)

### What We Built

Extended the eBPF sensor with Go crypto/tls uprobes and a full mathematical
drift detection engine. 10 files created/modified.

### New Files

| File | Purpose |
|------|---------|
| `ebpf-sensor/bpf/common.h` | Shared BPF header: all constants, GO_ARG_* macros, sensor_event_t struct, HTTP helpers. sensor.c and go_tls_trace.c both include it. |
| `ebpf-sensor/bpf/go_tls_trace.c` | 3 BPF programs for Go crypto/tls. Uses GO_ARG_BX/CX macros for Go 1.17+ register ABI (NOT C SysV). go_read_args hash map for entry/exit correlation. |
| `ebpf-sensor/sensor/drift.go` | Page-Hinkley drift engine. Welford online mean, PH cumulative sum, resurrection detection, sustained_attack escalation. Lock-free Observe() via atomic.Int64 + RWMutex. |
| `ebpf-sensor/sensor/gotls.go` | tls-uprobe-calculator skill in pure Go. Uses debug/elf to parse ELF symbol table. Validates .gopclntab section (Go binary check). Walks /proc/*/exe to auto-discover target. |

### Modified Files

| File | Change |
|------|--------|
| `bpf/sensor.c` | Replaced inline includes/constants/struct/helpers with `#include "common.h"`. Logic unchanged. |
| `sensor/live.go` | Added GoTls go:generate, drift *DriftEngine, publishDriftAlert, DriftStats, RunGoTLSPrograms goroutine, sourceString("go_tls"), atomic processedCount (logs every 1000 events). |
| `sensor/mock.go` | Added drift engine, loopCount, replayFile drift.Observe(), zombie burst injection after 5 loops (20 events, 50ms/event, randomised GET/POST, 3 path variants). |
| `sensor/sensor.go` | Added DriftStats() []EndpointStats to Sensor interface. |
| `main.go` | Added /drift/stats + /health HTTP server on METRICS_PORT (default :9090). |
| `fixtures/events.jsonl` | Added 6 events: 3x /api/v2/payments, 2x /api/v1/webhook, 1x /api/v1/admin/users. /api/v1/legacy-payments intentionally absent (injected by zombie burst). |

### Page-Hinkley Parameters (mathematically validated)

```
δ = 0.005  (insensitivity — prevents false alarms from tiny fluctuations)
λ = 25.0   (alarm threshold)
window = 10 seconds
min_dormant_windows = 3 (30s of zero traffic → dormant)
```

**Verified scenario:** 5 zero-traffic windows on /api/v1/legacy-payments, then
burst of 20 requests → resurrection alarm fires immediately in window 6.
If attacker continues, PH threshold alarm fires ~3 windows later (alarm_type
escalates to "sustained_attack" after 2 consecutive alarm windows).

### Three Alarm Types

| alarm_type | Trigger |
|-----------|---------|
| `resurrection` | Endpoint was dormant ≥3 windows, now has traffic |
| `ph_threshold` | PH score Uₜ - min(Uᵢ) > 25.0 |
| `resurrection+ph_threshold` | Both simultaneously |
| `sustained_attack` | Same endpoint alarmed 2+ consecutive windows |

### DriftAlert Redis Schema

```json
{
  "event_type": "drift_alert",
  "endpoint": "/api/v1/legacy-payments",
  "window_count": 20,
  "running_mean": 0.48,
  "ph_score": 18.3,
  "threshold": 25.0,
  "window_duration_sec": 10,
  "resurrected": true,
  "dormant_windows": 5,
  "alarm_type": "resurrection",
  "timestamp_ns": 1741777200000000000
}
```

### Metrics HTTP Server (NEW)

`GET http://localhost:9090/drift/stats` — JSON array of EndpointStats for all
observed endpoints. Intelligence-ui can poll this for real-time drift scores.

`GET http://localhost:9090/health` — liveness probe (supplements --health-check flag).

### Go TLS Coverage (what gotls.go instruments)

- **Covered:** Any Go binary in the container that uses crypto/tls (e.g., KrakenD api-gateway)
- **Discovery:** Auto-walks /proc/*/exe, validates .gopclntab, checks symbol table
- **Override:** GOTLS_BINARY_PATH env var for explicit target
- **Graceful degradation:** If no Go binary found, logs warning and continues

### Key Technical Decisions

1. **common.h extraction:** Removed ~180 lines of duplication from sensor.c. Single source of truth for struct layout and helpers.
2. **Go ABI macros:** GO_ARG_AX/BX/CX/DI — NOT PT_REGS_PARM* (those are C SysV ABI). Critical distinction.
3. **Lock-free Observe():** Uses RLock for registered paths (hot path), promotes to Lock only for new endpoints. Atomic counter drain with Swap(0) in tick.
4. **Zombie burst timing:** 5 loops × ~21 events × 100ms = ~105 seconds = ~10 drift windows of zero for /api/v1/legacy-payments before burst fires.

---

## Planned: Phase 2 — Self-Synchronizing Honeypot (Option 3)

### The Problem with Static Honeypots

The current honeypot (OpenCanary) is completely static. It always shows the same
Apache 2.2 banner and the same empty pages. A sophisticated attacker will notice
immediately that it doesn't behave like your real API.

### The Innovation

When the remediation brain quarantines a Zombie API, it automatically generates
a honeypot that is a **structural clone of the real endpoint**. Same URL paths,
same request/response JSON schema, same auth headers — but the backend returns
realistic-looking **fake data** and logs every move the attacker makes.

**Example flow:**
```
1. Brain detects /api/v1/users is a Zombie API (deprecated, still receiving traffic)
2. Brain classifies severity = HIGH (active zombie)
3. enforce_node fires:
   a. Generates a GitHub PR → adds 410 route to krakend.json for real traffic
   b. NEW: Reads the OpenAPI spec for /api/v1/users
   c. NEW: Generates a Docker Compose fragment for a cloned honeypot service
   d. NEW: Spins up the clone — same paths, fake data responses
   e. NEW: Routes attacker traffic to the clone instead of the real backend
4. Attacker hits /api/v1/users → gets fake user data → thinks they succeeded
5. Every request is logged with IP, timing, payload, user-agent
```

### What Needs to Be Built

**In `remediation-brain/agent/nodes.py` — `enforce_node`:**
- Pull OpenAPI spec from GitHub repo (using `GITHUB_TOKEN`)
- Extract path definitions for the deprecated endpoint
- Generate a Pydantic model from the schema
- Create a minimal FastAPI app that serves realistic fake data (using `faker` library)
- Write it to a temp directory and build/run as a Docker container via the Docker SDK

**New file: `remediation-brain/honeypot_generator/`**
```
honeypot_generator/
├── spec_reader.py       # pulls OpenAPI spec from GitHub, extracts endpoint schemas
├── fake_data_gen.py     # uses faker to generate realistic response data
├── app_builder.py       # generates a minimal FastAPI app string from the schema
└── docker_launcher.py   # uses docker-py to build and run the generated app
```

**In `api-gateway/` — dynamic config:**
- KrakenD's config is currently static JSON
- Need to use KrakenD's Flexible Config (template system) or switch to a dynamic
  routing solution that can add/remove routes at runtime without restart
- Alternative: use Traefik instead of KrakenD for the honeypot routing layer
  (Traefik supports dynamic config via labels, no restart required)

**New dependencies for `remediation-brain/requirements.txt`:**
```
faker==33.1.0          # realistic fake data generation
docker==7.1.0          # Docker SDK for Python — spin up honeypot containers
jinja2==3.1.4          # already available via langchain; templating for generated app
PyGithub==2.5.0        # GitHub API for pulling OpenAPI specs
```

### Demo Script (what it looks like to a judge)

```
1. Run: curl http://localhost:8080/api/v1/users  (sensor sees this)
2. Brain classifies it as active_zombie, severity=HIGH
3. Judge watches the dashboard — new incident appears
4. Within ~10 seconds: a new honeypot container spins up
5. Run: curl http://localhost:8081/api/v1/users
   → Returns: {"id": 4821, "name": "Sarah Mitchell", "email": "smitchell@example.com", ...}
   → Looks completely real
6. Show the honeypot log: attacker's IP, timestamp, every field they queried
```

---

## Planned: Phase 3 — Agentic API Protection (Option 4)

### The New Attack Surface Nobody is Talking About

In 2025-2026, every engineering team uses AI agents — Claude Code, GitHub Copilot,
Cursor. These agents autonomously make API calls. The problem: **an AI agent can
accidentally call a Zombie API**, reviving it and creating a false signal that the
endpoint is "in use" — which prevents decommissioning. Worse, a compromised prompt
(prompt injection) could deliberately route an agent to a deprecated endpoint.

### The Innovation

AuralisAPI becomes the **first platform to treat AI agents as a distinct traffic
class** and enforce API lifecycle policies against them in real time.

**Mechanism:**
```
AI agent makes API call to /api/v1/users
    ↓
eBPF sensor detects the outbound call
    ↓
Checks the process name against known AI agent patterns
(claude, node, python with langchain/openai imports)
    ↓
Looks up /api/v1/users in the zombie registry
    ↓
If deprecated → intercepts and returns a structured error:
{
  "error": "DeprecatedEndpointBlocked",
  "endpoint": "/api/v1/users",
  "replacement": "/api/v3/users",
  "migration_docs": "https://github.com/your-org/api/blob/main/MIGRATION.md",
  "blocked_by": "AuralisAPI Scoped Consent Enforcement"
}
    ↓
The AI agent reads this structured error and automatically retries
with the correct /api/v3/users endpoint
```

### What Needs to Be Built

**In `ebpf-sensor/bpf/` — new probe:**
- New eBPF program: `agent_trace.c` that tracks process names alongside HTTP calls
- Identify AI agent processes by cmdline patterns
- Tag events in Redis with `source_type: "ai_agent" | "human" | "service"`

**New dashboard panel in `intelligence-ui`:**
- "AI Agent Traffic" tab showing which agents called which endpoints
- Highlight cases where an agent attempted a deprecated endpoint
- Show the intervention log: "Claude Code blocked from /api/v1/users at 14:32:11"

**New API endpoint in `remediation-brain/api/routes.py`:**
- `GET /agent-activity` — returns AI agent traffic summary
- `POST /consent` — allows operators to grant scoped consent for an agent to
  temporarily access a deprecated endpoint (with expiry time)

**The Pitch Framing:**

> "Every security tool protects your APIs from human attackers. AuralisAPI is the
> first platform that also protects them from your own AI agents — which now write
> code, make API calls, and can be prompt-injected just like humans can be
> social-engineered."

---

## Session 4 — 2026-03-12 (Phase 2.2 Verification + Full Error Audit)

### What We Did

Context was resumed after Session 3 hit the context limit mid-audit. This session
completed the verification pass and confirmed all Phase 2.2 work is solid.

### Verification Checklist — All Passed

| File | Verified |
|------|---------|
| `ebpf-sensor/sensor/drift.go` | `lastStats` snapshot map present; `Stats()` reads only from snapshot, never directly from `phState` — data race fully resolved |
| `ebpf-sensor/sensor/sensor.go` | `DriftStats() []EndpointStats` present in `Sensor` interface |
| `ebpf-sensor/sensor/mock.go` | `drift *DriftEngine` field; zombie burst injection after `loopCount >= 5` |
| `ebpf-sensor/main.go` | `METRICS_PORT` env var read; `/drift/stats` + `/health` handlers registered |
| `docker-compose.yml` | `METRICS_PORT: "9090"` in ebpf-sensor environment block |
| `remediation-brain/agent/consumer.py` | XREADGROUP consumer group, XACK after processing, BUSYGROUP ignored |
| `remediation-brain/main.py` | `_start_consumer()` wired into FastAPI lifespan for both postgres + fallback paths |
| `remediation-brain/agent/nodes.py` | `drift_alert` branching in `classify_node` and `assess_risk_node`; `sustained_attack` → critical unconditionally |
| `intelligence-ui/app/page.tsx` | `"use client"`, `useEffect` polling `/drift/stats` every 10s, live stat cards + PH table |
| `ebpf-sensor/bpf/common.h` | Shared BPF header with `GO_ARG_AX/BX/CX/DI` macros, `SOURCE_GO_TLS = 2` |
| `ebpf-sensor/bpf/go_tls_trace.c` | 3 BPF programs using Go 1.17+ register ABI (NOT C SysV), `go_read_args` map cleanup before conditional returns |
| `ebpf-sensor/sensor/gotls.go` | ELF symbol resolver, `.gopclntab` Go binary check, `/proc/*/exe` auto-discovery |

### Current State of Each Service

| Service | Status |
|---------|--------|
| `ebpf-sensor` | Complete. Mock mode: fixture replay + drift engine + zombie burst demo. Live mode: 6 eBPF programs (http_trace.c + sensor.c) + 3 Go TLS probes. |
| `remediation-brain` | Complete. LangGraph workflow fully wired: ingest → classify → assess_risk → [interrupt] → enforce → generate_report. Redis consumer active. drift_alert routing implemented. |
| `api-gateway` | Complete from Phase 1. Static 410 routes for /api/v1/*. |
| `honeypot-decoy` | Complete from Phase 1. HTTP trap on 8081, SSH on 2222. |
| `intelligence-ui` | Complete. Live polling dashboard with drift stats table, PH score highlighting. |
| `redis` | Infrastructure only. |
| `postgres` | Infrastructure only. |

### No New Bugs Found

The audit pass found all code consistent with Session 3 implementation. No
additional fixes were required this session.

### Phase Status Summary

| Phase | Status |
|-------|--------|
| Phase 1 — Infrastructure Scaffolding | COMPLETE |
| Phase 2.1 — eBPF TLS Sensor (sensor.c + OpenSSL uprobes) | COMPLETE |
| Phase 2.2 — Go Orchestrator + Drift Detection | COMPLETE |
| Phase 2 — Self-Synchronizing Honeypot | PLANNED (see below) |
| Phase 3 — Agentic API Protection | PLANNED (see below) |

---

## Session 5 — 2026-03-16 (GitHub Setup + LLM Swap + Full Codebase Audit)

### What We Did

Three distinct workstreams this session: version control setup, LLM provider
swap from OpenAI to Groq, and a full read-every-file bug audit of the codebase.

---

### Part 1 — GitHub Repository Setup

- Installed GitHub CLI (`winget install GitHub.cli`)
- Authenticated via `gh auth login` (account: hopepranav08)
- Created public repo: https://github.com/hopepranav08/AuraLisAPI
- Initialized git locally, wired remote origin
- Made first commit: project scaffold (25 files — all Dockerfiles, docker-compose,
  Makefile, gateway config, honeypot config, Go module, requirements, env templates)
- Established phased commit strategy: one commit per phase, small config fixes
  folded into previous commits via amend to keep history clean

**New tracking files created (local only, not committed):**
- `COMMIT_TRACKER.md` — tracks what is committed vs pending, with suggested messages
- `ENV_SETUP_GUIDE.md` — complete guide for every env var, free alternatives to OpenAI

---

### Part 2 — LLM Swap: OpenAI → Groq

OpenAI has no free tier. Groq provides a free API (llama-3.3-70b-versatile,
15 req/min, 1M tokens/day) — sufficient for hackathon demo and local dev.

**Files changed:**

| File | Change |
|------|--------|
| `remediation-brain/requirements.txt` | `langchain-openai==0.2.14` → `langchain-groq==0.2.4` |
| `.env.example` | `OPENAI_API_KEY` / `OPENAI_MODEL` → `GROQ_API_KEY` / `GROQ_MODEL` |
| `remediation-brain/.env.example` | Same swap |
| `remediation-brain/agent/nodes.py` | Added Groq LLM init at module load; wired into `report_node` for AI executive summary generation; graceful fallback to heuristic-only if key absent |

**LLM integration pattern in nodes.py:**
```python
_llm = None
_groq_key = os.getenv("GROQ_API_KEY", "")
if _groq_key:
    from langchain_groq import ChatGroq
    _llm = ChatGroq(model=..., groq_api_key=_groq_key, temperature=0)
```
`report_node` appends an "Executive Summary (AI-Generated)" section when `_llm`
is available, falls back to structured markdown only when it is not.

---

### Part 3 — Full Codebase Audit: Bugs Found and Fixed

Read every implementation file (Go sensor, Python brain, Next.js UI, all
Dockerfiles, docker-compose) and identified 6 bugs across the codebase.

| # | File | Bug | Severity | Fix |
|---|------|-----|----------|-----|
| 1 | `docker-compose.yml` | `OPENAI_API_KEY`/`OPENAI_MODEL` still injected into brain container after LLM swap — `GROQ_API_KEY` never reached the container, LLM silently disabled | **Critical** | Replaced with `GROQ_API_KEY` / `GROQ_MODEL` |
| 2 | `intelligence-ui/app/page.tsx` | `rgba(var(--color-warning-rgb, 255 165 0) / 0.08)` — invalid CSS; `rgba()` does not support `/` opacity shorthand syntax; row highlighting broken in all browsers | **Medium** | Replaced with valid `rgba(249, 115, 22, 0.08)` and `rgba(239, 68, 68, 0.08)` |
| 3 | `remediation-brain/agent/nodes.py` | `ChatGroq(api_key=...)` — wrong Pydantic field name; correct field is `groq_api_key` | **Minor** | Changed to `groq_api_key=_groq_key` |
| 4 | `ebpf-sensor/Dockerfile` | `go build -o ebpf-sensor ./main.go` compiles explicit file instead of full package — any future root-package file would be silently excluded | **Minor** | Changed to `go build -o ebpf-sensor .` |
| 5 | `ebpf-sensor/sensor/live.go` | Missing `//go:build linux` — bpf2go-generated types (`HttpTraceObjects`, `SensorObjects`) don't exist on Windows; gopls red lines, package fails to compile on non-Linux | **Medium** | Added `//go:build linux` build constraint |
| 6 | `ebpf-sensor/sensor/gotls.go` | Same issue — `GoTlsObjects` is Linux/bpf2go-generated; no build constraint | **Medium** | Added `//go:build linux` build constraint |

**New file created:**
- `ebpf-sensor/sensor/live_stub.go` (`//go:build !linux`) — provides `newLiveSensor`
  on Windows/macOS returning a clear error message; allows the full module to compile
  cleanly on all platforms without the bpf2go-generated files present

**Verified clean compilation:**
```bash
GOOS=windows go build ./...   # zero errors
```

---

### Quick Reference Updates

**LLM key (Groq — free):**
```
GROQ_API_KEY=gsk_your-key-here     # from console.groq.com/keys
GROQ_MODEL=llama-3.3-70b-versatile
```

**GitHub:**
```
git remote: https://github.com/hopepranav08/AuraLisAPI
Commit 1 hash: 834b379
```

---

## Quick Reference

### Running the Stack

```bash
# First time setup
cp .env.example .env      # fill in GROQ_API_KEY + GITHUB_TOKEN + SECRET_KEY
make up                   # starts everything in mock mode

# Useful commands
make logs-brain           # watch the AI brain process events
make logs-sensor          # watch the eBPF sensor publish events
docker compose ps         # check all container health

# URLs
http://localhost:3000     # Dashboard
http://localhost:8000     # Brain API (direct)
http://localhost:8080     # Gateway (all client traffic goes here)
http://localhost:8081     # Honeypot HTTP trap
```

### Environment Variables That Matter

```
GROQ_API_KEY      → enables real LLM reasoning in report_node (AI executive summary)
                    free key at console.groq.com/keys; heuristic rules work without it
GROQ_MODEL        → default: llama-3.3-70b-versatile
GITHUB_TOKEN      → needed for Phase 2 spec-pulling and PR generation
SENSOR_MODE       → "mock" (default, works everywhere) | "live" (Linux only)
```

### File Structure

```
auralisapi/
├── ebpf-sensor/          Go — kernel-level HTTP telemetry
│   ├── bpf/              eBPF C programs (compiled by bpf2go at build time)
│   ├── sensor/           Go packages: live.go (eBPF) + mock.go (fixture replay)
│   └── fixtures/         events.jsonl — 15 sample HTTP events for mock mode
├── remediation-brain/    Python — FastAPI + LangGraph agentic engine
│   ├── agent/            state.py, graph.py, nodes.py — the LangGraph workflow
│   └── api/              routes.py — HTTP endpoints
├── api-gateway/          KrakenD config + Dockerfile
├── honeypot-decoy/       OpenCanary config + start script
├── intelligence-ui/      Next.js 15 dashboard
├── docker-compose.yml    Orchestrates all 7 services
└── Makefile              Convenience commands
```

---

## Session 6 — 2026-03-16 (Phase 3: LangGraph Agentic Remediation Engine)

### What We Built

Upgraded the `remediation-brain` from Phase 1/2 stubs to a fully-wired agentic
reasoning engine. 7 files modified, 1 new directory + 2 new files.

### Modified Files

| File | Change |
|------|--------|
| `agent/state.py` | Added `is_pii_exposed: bool`, `spec_diff: Optional[dict]`, `github_pr_url: Optional[str]` |
| `agent/nodes.py` | Complete rewrite: classify+assess_risk → `analyze_node`; new `plan_node`; production `enforce_node` |
| `agent/graph.py` | New topology: `ingest → analyze → plan → [interrupt] → enforce → report` |
| `agent/consumer.py` | Added 3 new Phase 3 fields to initial_state dict |
| `api/routes.py` | Full rewrite — real human-approval endpoints replace all stubs |
| `requirements.txt` | Added `PyGithub==2.5.0`, `faker==33.1.0` |

### New Files

| File | Purpose |
|------|---------|
| `tests/test_nodes.py` | 10 pytest cases (mocked GitHub) — full node coverage |
| `tests/__init__.py` | Makes tests/ a Python package |

### New Graph Topology

```
ingest → analyze → plan → [interrupt_before enforce] → enforce → generate_report → END
                    └── (severity=low/medium) ──────────────────→ generate_report → END
```

### AnalyzerNode Logic

1. Fetch OpenAPI 3.0 spec from GitHub (`openapi.yaml` in repo root) via PyGithub
2. Diff: in spec + deprecated:true → `active_zombie`, in traffic + not in spec → `shadow`
3. Graceful fallback to path-prefix heuristics when `GITHUB_TOKEN` is absent
4. Enhanced PII/PCI detection: email, SSN, credit card, phone, IBAN, DOB, passport + entropy analysis (Shannon entropy ≥ 4.5 bits/char for values >20 chars)

### PlannerNode Logic

- `critical/high`: quarantine_gateway + krakend_block + spin_up_honeypot (+ escalate_to_ciso if PII)
- `medium` (shadow): document_endpoint + add_to_inventory
- `low`: log_only
- Produces human-readable action plan for reviewer BEFORE the interrupt

### EnforcerNode Logic

**Real mode** (GITHUB_TOKEN set):
1. Fetch `api-gateway/krakend.json` from GitHub
2. Inject 410 Gone endpoint block for the deprecated path
3. Create branch `auralis/quarantine/{incident_id[:8]}`
4. Open GitHub PR with incident report as PR body

**Stub mode** (no token): logs intended action, returns `github_pr_url=None`

### Human Approval API

| Endpoint | Action |
|----------|--------|
| `GET /incidents` | List all incidents from LangGraph checkpoint store |
| `GET /incidents/{id}` | Full state snapshot (see planned_actions, severity, spec_diff) |
| `POST /incidents/{id}/approve` | ✅ Resumes graph past interrupt → runs EnforcerNode |
| `POST /incidents/{id}/reject` | ❌ Skips enforce → runs generate_report only |
| `POST /remediate` | Manual trigger for any path |

### Phase Status Summary

| Phase | Status |
|-------|--------|
| Phase 1 — Infrastructure Scaffolding | COMPLETE |
| Phase 2.1 — eBPF TLS Sensor | COMPLETE |
| Phase 2.2 — Go Orchestrator + Drift Detection | COMPLETE |
| Phase 3 — LangGraph Agentic Remediation Engine | COMPLETE |
| Phase 4 — GitOps Enforcement + Dynamic Deception | **COMPLETE** |
| Phase 3b — Agentic API Protection | PLANNED |

---

## Session 7 — 2026-03-16 (Phase 4: GitOps Enforcement + Dynamic Deception)

### What We Built

Two enforcement planes wired together: an atomic KrakenD mutation engine for
instant local gateway enforcement, and a dynamic FastAPI deception server that
hot-registers quarantined paths without container restarts.

5 new files, 5 modified files.

### New Files

| File | Purpose |
|------|---------|
| `remediation-brain/enforcement/__init__.py` | Package marker |
| `remediation-brain/enforcement/krakend_mutator.py` | Atomic KrakenD config mutation: idempotency guard → structural validation → `os.replace()` atomic write → `KrakendMutationResult`. Also exposes `read_gateway_state()` for the `/gateway/config` API |
| `remediation-brain/enforcement/spec_parser.py` | `extract_deprecated_paths()`, `extract_schema_for_path()`, `diff_traffic_vs_spec()`, `openapi_to_krakend_via_cli()` (KrakenD binary wrapper) |
| `honeypot-decoy/honeypot_server.py` | FastAPI deception server on port 8082. Admin API for hot path-registration. Catch-all handler: schema-driven + path-heuristic Faker responses. Fire-and-forget async webhook to brain on every attacker hit |
| `honeypot-decoy/config_generator.py` | `generate_opencanary_conf()` — regenerates `~/.opencanary.conf` JSON. `reload_opencanary()` — SIGHUP best-effort (OpenCanary doesn't truly support live reload but included for future compatibility) |

### Modified Files

| File | Change |
|------|--------|
| `honeypot-decoy/requirements.txt` | Added `fastapi`, `uvicorn`, `pydantic`, `faker`, `httpx`, `structlog`, `anyio` |
| `honeypot-decoy/Dockerfile` | Copies `honeypot_server.py` + `config_generator.py` into `/app/`; `EXPOSE 8081 2222 8082` |
| `honeypot-decoy/start.sh` | Starts `python /app/honeypot_server.py &` before `exec opencanaryd --dev` |
| `docker-compose.yml` | Brain gets `./api-gateway/krakend.json:/app/krakend.json` volume + `KRAKEND_CONFIG_PATH=/app/krakend.json` env; honeypot-decoy adds `8082:8082` port |
| `remediation-brain/agent/nodes.py` | `enforce_node` restructured to single return path (stub + live both continue to Phase 4). Phase 4A: `mutate_krakend()` for instant local enforcement. Phase 4B: `httpx` POST to honeypot `/admin/register-path`. Added `httpx` import + graceful `enforcement` package import |
| `remediation-brain/api/routes.py` | Added `GET /gateway/config`, `POST /gateway/quarantine`, `POST /webhooks/honeypot-alert`. Added `json`, `os`, `uuid`, `aioredis` imports; `enforcement.krakend_mutator` import |

### Enforcement Architecture (Phase 4)

```
Human approves incident via POST /incidents/{id}/approve
    ↓
enforce_node runs (LangGraph)
    ├── [optional] GitHub PR: inject 410 block into krakend.json in remote repo
    ├── Phase 4A: mutate_krakend() → local /app/krakend.json mutated atomically
    │                                  (instant effect, no PR merge wait)
    └── Phase 4B: POST honeypot-decoy:8082/admin/register-path
                    → deception server hot-registers quarantined path

Attacker probes quarantined path after enforcement:
    ├── :8081 (OpenCanary)      → raw HTTP probe logged to stdout/file
    └── :8082 (honeypot_server) → realistic fake 200 response served
              ↓  (async fire-and-forget, never blocks response)
          POST brain:8000/webhooks/honeypot-alert
              ↓
          Redis XADD auralis:honeypot-events
              ↓
          intelligence-ui dashboard (threat intel panel)
```

### krakend_mutator.py — Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Injects ALL 5 methods (GET/POST/PUT/DELETE/PATCH) | A quarantine that only blocks GET leaves POST open for exfiltration |
| Idempotency guard: checks (endpoint, method) pairs | Calling mutate_krakend twice for the same path is a no-op — safe for retries |
| Atomic write via `tempfile` + `os.replace()` | Power-cut during write leaves the old valid config in place, not a corrupt half-file |
| Structural validation before write | Catches bugs before they corrupt the live gateway config |
| Returns `KrakendMutationResult` dataclass | Caller can log `mutation.to_dict()` or surface `diff_preview` in the PR body |

### honeypot_server.py — Fake Response Priority

1. **Schema-driven**: uses JSON schema properties from the OpenAPI spec (passed by `enforce_node` via `spec_diff["schema"]`)
2. **Path-heuristic**: keyword matching on path segments (`user`, `payment`, `product`, `order`, `auth`) → appropriate fake field sets
3. **Generic fallback**: `{id: uuid, status: "ok", timestamp: ...}`

Prefix matching also works: attacker hitting `/api/v1/users/42` matches the registered `/api/v1/users` entry.

### New API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /gateway/config` | Live krakend.json state — quarantined vs active endpoint lists |
| `POST /gateway/quarantine` | Manual/dashboard-triggered quarantine: runs mutator + honeypot registration |
| `POST /webhooks/honeypot-alert` | Receives deception hits from `honeypot_server.py`, publishes to `auralis:honeypot-events` Redis stream |

### Phase 4 Bugs Fixed (audit during implementation)

| # | Bug | Fix |
|---|-----|-----|
| 1 | `enforce_node` had an early `return` in stub mode — Phase 4 local mutation and honeypot calls would never run in stub/demo mode | Restructured to single return: stub mode appends to `executed` list and falls through to Phase 4A/4B |
| 2 | `routes.py` `trigger_quarantine` and `receive_honeypot_alert` declared `request: Request` parameter but never used it — FastAPI still injects the full Request object unnecessarily | Removed unused `request` parameter from both handlers |
| 3 | `__import__("json")` used inline in `receive_honeypot_alert` to avoid import conflict | Added `import json` to the top of `routes.py` and replaced inline import |

### Phase Status Summary

| Phase | Status |
|-------|--------|
| Phase 1 — Infrastructure Scaffolding | COMPLETE |
| Phase 2.1 — eBPF TLS Sensor | COMPLETE |
| Phase 2.2 — Go Orchestrator + Drift Detection | COMPLETE |
| Phase 3 — LangGraph Agentic Remediation Engine | COMPLETE |
| Phase 4 — GitOps Enforcement + Dynamic Deception | **COMPLETE** |
| Phase 3b — Agentic API Protection | PLANNED |


---

## Session 8 — 2026-03-20 (Phase 4 Bug Audit + Fixes)

### What We Fixed

Full audit of all Phase 4 files. 4 bugs found and fixed.

### Bugs Fixed

| # | File | Bug | Severity | Fix |
|---|------|-----|----------|-----|
| 1 | `remediation-brain/Dockerfile` | `enforcement/` package never copied into image — `from enforcement.krakend_mutator import ...` would crash container at startup | **Critical** | Added `COPY enforcement/ ./enforcement/` |
| 2 | `remediation-brain/api/routes.py` | Module-level enforcement import with no try/except — if it fails, FastAPI won't start | **Critical** | Wrapped in try/except + `_MUTATOR_AVAILABLE` flag + 503 guards on gateway routes |
| 3 | `honeypot-decoy/honeypot_server.py` | `@app.on_event("startup")` deprecated since FastAPI 0.93 (using 0.115.6) | **High** | Replaced with `@asynccontextmanager` lifespan pattern |
| 4 | `remediation-brain/api/routes.py` | `import httpx` inside function body; redundant `import uuid` inside function (both already module-level) | **Low** | Moved to module level; removed redundant inline imports |

### Files Changed

| File | Change |
|------|--------|
| `remediation-brain/Dockerfile` | `COPY enforcement/ ./enforcement/` added |
| `remediation-brain/api/routes.py` | try/except enforcement import; module-level httpx; 503 guards; removed inline imports |
| `honeypot-decoy/honeypot_server.py` | lifespan context manager replacing deprecated `@app.on_event` |

---

## Session 9 — 2026-03-20 (Phase 5: Interactive Intelligence Dashboard)

### What We Built

Full Phase 5 Intelligence Dashboard — complete D3.js force-directed network graph,
real-time visualizations, human-in-the-loop approval UI, and honeypot threat intel
feed. 10 files created or modified.

### New Files

| File | Lines | Purpose |
|------|-------|---------|
| `intelligence-ui/app/components/NetworkGraph.tsx` | ~487 | D3 v7 force-directed network graph. D3 owns SVG DOM via `useRef<SVGSVGElement>`. Node visual encoding: gateway (amber, large), active_zombie critical (red pulsing ring), shadow (dashed border), dormant (grey). SVG defs: radial gradients, feGaussianBlur glow filters. Drag, zoom/pan, ResizeObserver, tooltip |
| `intelligence-ui/app/components/IncidentPanel.tsx` | ~233 | Human-in-the-loop approval panel. Props: `incidents, onApprove, onReject, loadingId, selectedEndpoint`. Awaiting-approval incidents sorted first. APPROVE (green) / REJECT (red) buttons with loading spinner. PR URL link for completed incidents |
| `intelligence-ui/app/components/DriftTable.tsx` | ~190 | Page-Hinkley drift scores table. Sorted by PH score descending. Inline `PhBar` mini progress bar (green/orange/red). Status badges: ZOMBIE / DORMANT / RESURRECT / OK / WATCH. Live dot in header |
| `intelligence-ui/app/components/HoneypotFeed.tsx` | ~219 | Real-time threat intel feed. Newest-first, per-method color borders, relative timestamps, animated radar-sweep empty state |

### Modified Files

| File | Change |
|------|--------|
| `intelligence-ui/app/page.tsx` | Full rewrite — polls 5 data sources every 5s. `useMemo` derives `graphNodes` from inventory + drift overlay. Service health dots in header, stat cards, approve/reject handlers. Dynamic imports for D3 components (SSR-safe) |
| `intelligence-ui/app/globals.css` | Full replacement. Added keyframe animations: `zombie-pulse-critical`, `zombie-pulse-warning`, `radar-sweep`, `live-blink`, `feed-entry-in`, `dot-pulse`. App shell layout, graph panel with scanline grid, incident card, drift table row highlighting, honeypot feed, D3 tooltip styles |
| `intelligence-ui/app/layout.tsx` | Updated server component — renders `<html><body class="app-shell">` |
| `intelligence-ui/next.config.ts` | Added `/brain/:path*` rewrite → `BRAIN_INTERNAL_URL ?? "http://remediation-brain:8000"` so browser-side fetches work through Next.js server (resolves Docker internal hostname) |
| `docker-compose.yml` | Added `BRAIN_INTERNAL_URL: "http://remediation-brain:8000"` to intelligence-ui environment |
| `remediation-brain/api/routes.py` | Added `GET /honeypot/events` endpoint reading from `auralis:honeypot-events` Redis stream via `xrevrange` for the live threat intel feed |

### Architecture Decisions

**D3 + React boundary**: React renders only the `<svg ref={svgRef}>` container element.
D3 imperatively mutates ALL SVG contents inside `useEffect`. Cleanup: `simulation.stop()`
+ `selectAll("*").remove()` on every re-render. This avoids React/D3 DOM conflicts.

**Browser → brain routing**: Intelligence-UI can reach `remediation-brain:8000` by Docker
DNS, but the browser cannot. Solution: add `/brain/:path*` rewrite in `next.config.ts`
so client components fetch `/brain/incidents` → Next.js server proxies to brain internally.

**Data sources polled every 5s:**
- `/brain/incidents` → human approval queue
- `/brain/inventory` → endpoint list (graph nodes)
- `/brain/drift/stats` via direct localhost:9090 → PH scores
- `/brain/honeypot/events` → threat intel feed
- `/brain/gateway/config` → quarantined paths

### D3 Force Simulation Parameters

```
forceLink:      distance=90 (edges)
forceManyBody:  strength=-250 (repulsion)
forceCenter:    cx, cy (gravitational center)
forceCollide:   radius=node.r+8 (no overlap)
forceX/Y:       strength=0.05 (soft centering)
```

### Phase Status Summary

| Phase | Status |
|-------|--------|
| Phase 1 — Infrastructure Scaffolding | COMPLETE |
| Phase 2.1 — eBPF TLS Sensor | COMPLETE |
| Phase 2.2 — Go Orchestrator + Drift Detection | COMPLETE |
| Phase 3 — LangGraph Agentic Remediation Engine | COMPLETE |
| Phase 4 — GitOps Enforcement + Dynamic Deception | COMPLETE |
| Phase 5 — Interactive Intelligence Dashboard | **COMPLETE** |
| Phase 3b — Agentic API Protection | PLANNED |

### Pending for Next Session

1. **Commit 3** — `ebpf-sensor/bpf/http_trace.c`, `ebpf-sensor/bpf/sensor.c`
2. **Commit 4** — `bpf/common.h`, `bpf/go_tls_trace.c`, `sensor/drift.go`, `sensor/gotls.go`
3. **Commit 5** — all Phase 3+4+5 files (see COMMIT_TRACKER.md)
4. **Phase 3b** — Agentic API Protection (AI agent traffic class + scoped consent enforcement)

---

## Session 10 — 2026-03-21 (Phase 5 Bug Audit + Fixes)

### What We Did

Full read-every-file audit of Phase 5 (intelligence dashboard). 4 bugs found and fixed.

### Bugs Fixed

| # | File | Bug | Severity | Fix |
|---|------|-----|----------|-----|
| 1 | `intelligence-ui/app/components/NetworkGraph.tsx` | `select("circle")` and `select("circle:nth-child(1)")` in mouseover/mouseout handlers select the **pulse ring** (first `<circle>` child in zombie nodes) instead of the main fill circle — hover stroke-width highlight applied to wrong element | **High** | Added class `node-fill` to the main fill circle; changed selectors to `select("circle.node-fill")` |
| 2 | `intelligence-ui/app/components/IncidentPanel.tsx` | `hoveredBtn` useState declared and set on mouse enter/leave but only consumed via `{condition && null}` expressions that always render nothing — dead code causing unnecessary re-renders on button hover | **Medium** | Removed `useState` import, `hoveredBtn` state, `onMouseEnter`/`onMouseLeave` handlers, and dead JSX expressions |
| 3 | `remediation-brain/api/routes.py` | `client.xadd(stream, ...)` missing `maxlen=1000, approximate=True` — docstring says stream uses MAXLEN ~1000 but the actual call enforced no cap; stream grows unboundedly in production | **Medium** | Added `maxlen=1000, approximate=True` to the `xadd` call in `receive_honeypot_alert` |
| 4 | `docker-compose.yml` | `NEXT_PUBLIC_API_URL: "http://localhost:8080"` used as server-side rewrite destination in `next.config.ts` — from inside the intelligence-ui container, `localhost:8080` doesn't resolve to the api-gateway; should be the Docker-internal hostname | **Low** | Changed to `NEXT_PUBLIC_API_URL: "http://api-gateway:8080"` |

### Files Changed

| File | Change |
|------|--------|
| `intelligence-ui/app/components/NetworkGraph.tsx` | Added `class="node-fill"` to main fill circle; fixed hover selectors |
| `intelligence-ui/app/components/IncidentPanel.tsx` | Removed dead `hoveredBtn` state and related handlers |
| `remediation-brain/api/routes.py` | Added `maxlen=1000, approximate=True` to Redis stream write |
| `docker-compose.yml` | Fixed `NEXT_PUBLIC_API_URL` for Docker-internal routing |

### Phase Status Summary

| Phase | Status |
|-------|--------|
| Phase 1 — Infrastructure Scaffolding | COMPLETE |
| Phase 2.1 — eBPF TLS Sensor | COMPLETE |
| Phase 2.2 — Go Orchestrator + Drift Detection | COMPLETE |
| Phase 3 — LangGraph Agentic Remediation Engine | COMPLETE |
| Phase 4 — GitOps Enforcement + Dynamic Deception | COMPLETE |
| Phase 5 — Interactive Intelligence Dashboard | **COMPLETE + AUDITED** |
| Phase 3b — Agentic API Protection | PLANNED |

---

## Session 11 — 2026-03-21 (Mega Final Audit: All 5 Phases)

### What We Did

Complete end-to-end audit of every file across all 5 phases — read every Go, Python,
TypeScript, C, JSON, YAML, and shell file in the codebase. Goal: verify correctness,
connectivity, and Docker compatibility before Phase 3b.

### Files Audited (Full Coverage)

**ebpf-sensor:** `main.go`, `sensor/sensor.go`, `sensor/live.go`, `sensor/mock.go`,
`sensor/drift.go`, `sensor/gotls.go`, `sensor/live_stub.go`, `go.mod`, `Dockerfile`,
`bpf/http_trace.c`, `bpf/sensor.c`, `bpf/common.h`, `bpf/go_tls_trace.c`

**remediation-brain:** `main.py`, `agent/state.py`, `agent/graph.py`, `agent/nodes.py`,
`agent/consumer.py`, `enforcement/krakend_mutator.py`, `enforcement/spec_parser.py`,
`api/routes.py`, `tests/test_nodes.py`, `pytest.ini`, `Dockerfile`, `requirements.txt`

**honeypot-decoy:** `Dockerfile`, `requirements.txt`, `start.sh`, `honeypot_server.py`,
`config_generator.py`, `opencanary.conf`

**api-gateway:** `krakend.json`

**intelligence-ui:** `app/page.tsx`, `app/globals.css`, `app/layout.tsx`, `next.config.ts`,
`app/components/NetworkGraph.tsx`, `app/components/IncidentPanel.tsx`,
`app/components/DriftTable.tsx`, `app/components/HoneypotFeed.tsx`

**Root:** `docker-compose.yml`, `Makefile`, `.env.example`

### Bugs Found and Fixed

| # | File | Bug | Severity | Fix |
|---|------|-----|----------|-----|
| 1 | `Makefile` | Line 34: `add your OPENAI_API_KEY` — stale reference after LLM swap to Groq in Session 5 | **Low** | Changed to `GROQ_API_KEY` |
| 2 | `ebpf-sensor/bpf/http_trace.c` | Comment on `http_event_t` said `sizeof = 288` — stale from when MAX_PATH_LEN was 256; current layout with MAX_PATH_LEN=128 gives sizeof=160, matching the Go `const eventSize = 160` | **Low** | Fixed comment to `sizeof = 160` |

### Everything Else Verified Clean

| Component | Verdict |
|-----------|---------|
| `ebpf-sensor` struct layouts | `httpEventC` (160B) and `sensorEventC` (160B) match C structs byte-for-byte; offsets verified against `common.h` |
| `ebpf-sensor` BPF C programs | 6 programs in `sensor.c`, 3 in `go_tls_trace.c`, 1 in `http_trace.c`; all map cleanups on exit paths correct |
| `drift.go` Page-Hinkley | `lastStats` snapshot pattern prevents data races; `Stats()` reads only from snapshot, never from `phState` |
| `sensor.go` interface | `DriftStats() []EndpointStats` present; routes to `live` or `mock` correctly |
| `mock.go` zombie burst | Injects after `loopCount >= 5`, fires exactly once, 50ms inter-event delay |
| `gotls.go` ELF parser | `.gopclntab` check before symbol lookup; `/proc/*/exe` walker; self-probe excluded |
| `live_stub.go` | `//go:build !linux` — clean non-Linux compilation path |
| `remediation-brain/main.py` | `async with checkpointer:` lifespan pattern; consumer task started in both postgres + fallback paths |
| LangGraph graph | `interrupt_before=["enforce"]`; `should_enforce` conditional edge; correct topology |
| `consumer.py` | XREADGROUP + XACK pattern; BUSYGROUP silently ignored; drift_alert normalization |
| `nodes.py` | `analyze_node` → `plan_node` → `enforce_node` → `generate_report_node`; Phase 4A+4B in enforce_node both fire in stub mode |
| `krakend_mutator.py` | Idempotency guard; atomic `tempfile` + `os.replace()` write; all 5 HTTP methods quarantined |
| `honeypot_server.py` | `asynccontextmanager` lifespan; fire-and-forget async webhook; schema/heuristic/generic fallback priority |
| `start.sh` | `rm -f twistd.pid` before `opencanaryd --dev`; `honeypot_server.py &` in background |
| `opencanary.conf` | Valid JSON; HTTP on 8081, SSH on 2222; all unused protocols disabled |
| `krakend.json` | `$schema: v3.json`, `version: 3`; no self-referencing `__health`; correct `proxy/static` 410 blocks |
| `intelligence-ui/next.config.ts` | `output: standalone`; `/api/:path*` → api-gateway; `/brain/:path*` → remediation-brain (both correct Docker-internal URLs) |
| `intelligence-ui/page.tsx` | `DRIFT_STATS_URL = "http://localhost:9090/drift/stats"` — correct (browser-side fetch to sensor's host-mode port); all brain fetches via `/brain/` rewrite |
| `DriftTable.tsx` | No TypeScript issues; `PH_ALARM_THRESHOLD=25` matches drift engine λ=25.0 |
| `HoneypotFeed.tsx` | `// @ts-ignore` for CSS custom property is appropriate; auto-scroll on events.length change |
| `.env.example` | Correctly references `GROQ_API_KEY`, `GITHUB_TOKEN`, `SECRET_KEY`, `SENSOR_MODE` |
| `docker-compose.yml` | All 4 previous session fixes confirmed in place (NEXT_PUBLIC_API_URL, BRAIN_INTERNAL_URL, krakend.json volume mount, Redis port exposure) |

### Data Flow — End-to-End Confirmed

```
eBPF sensor (SENSOR_MODE=mock)
  → fixture replay + zombie burst (after 5 loops)
  → drift engine (Page-Hinkley per-endpoint)
  → Redis XADD auralis:events (JSON events + drift_alert events)
  → /drift/stats HTTP endpoint on :9090 (sensor metrics server)

Redis auralis:events
  → remediation-brain XREADGROUP consumer
  → LangGraph: ingest → analyze → plan → [interrupt] → enforce → report
  → PostgreSQL checkpoint store (async psycopg3)
  → interrupt: POST /incidents/{id}/approve → resume graph
  → enforce_node: Phase 4A (krakend.json mutation) + Phase 4B (honeypot registration)
  → GitHub PR (if GITHUB_TOKEN set)

honeypot-decoy (port 8082)
  → attacker probe hits quarantined path
  → fake 200 response served
  → async fire-and-forget → POST brain:8000/webhooks/honeypot-alert
  → Redis XADD auralis:honeypot-events
  → GET /honeypot/events served to dashboard

intelligence-ui (Next.js, port 3000)
  → polls every 5s: /brain/incidents, /brain/inventory, /brain/gateway/config, /brain/honeypot/events
  → browser direct: http://localhost:9090/drift/stats
  → /brain/* rewrites: Next.js server proxies to remediation-brain:8000
  → D3 force graph, IncidentPanel approve/reject, DriftTable, HoneypotFeed
```

### Phase Status Summary

| Phase | Status |
|-------|--------|
| Phase 1 — Infrastructure Scaffolding | COMPLETE |
| Phase 2.1 — eBPF TLS Sensor | COMPLETE |
| Phase 2.2 — Go Orchestrator + Drift Detection | COMPLETE |
| Phase 3 — LangGraph Agentic Remediation Engine | COMPLETE |
| Phase 4 — GitOps Enforcement + Dynamic Deception | COMPLETE |
| Phase 5 — Interactive Intelligence Dashboard | COMPLETE |
| **All 5 Phases (Mega Audit)** | **FULLY AUDITED — 2 minor bugs fixed** |
| Phase 3b — Agentic API Protection | NEXT |

### Next Session

Phase 3b — Agentic API Protection:
- New BPF program `agent_trace.c` — detect AI agent processes by cmdline patterns, tag events with `source_type: "ai_agent" | "human" | "service"`
- New `remediation-brain/api` endpoints: `GET /agent-activity`, `POST /consent` (scoped consent with expiry)
- New dashboard panel: "AI Agent Traffic" tab showing agent-endpoint interaction log

---

## Session 10 — 2026-03-22 (Full Audit + Bug Fixes + Groq Structured Output)

### What We Did

Complete cross-service audit of all 35+ implementation files, fixed 8 bugs found during the audit, then implemented Groq structured output for the incident report pipeline.

---

### Bug Fixes (Audit Session)

| # | Severity | File | Bug | Fix |
|---|----------|------|-----|-----|
| 1 | Critical | `intelligence-ui/app/page.tsx` | `DRIFT_STATS_URL = "http://localhost:9090/drift/stats"` — direct browser fetch fails on any remote host | Changed to relative `/drift/stats` (proxied through Next.js server) |
| 2 | Medium | `intelligence-ui/next.config.ts` | Missing `/drift/:path*` rewrite — relative drift URL had no proxy target | Added `{ source: "/drift/:path*", destination: "${sensorUrl}/:path*" }` using new `SENSOR_METRICS_URL` env var |
| 3 | Medium | `docker-compose.yml` | `intelligence-ui` missing `extra_hosts: host.docker.internal:host-gateway` — on Linux Docker, `host.docker.internal` doesn't resolve without this | Added `extra_hosts` + `SENSOR_METRICS_URL: "http://host.docker.internal:9090"` to the service |
| 4 | Medium | `intelligence-ui/app/globals.css:273` | `rgba(var(--stat-accent-rgb, 255,255,255), 0.04)` — `--stat-accent-rgb` never defined, stat card glow was always white | Replaced with `color-mix(in srgb, var(--stat-accent, transparent) 4%, transparent)` |
| 5 | Medium | `intelligence-ui/app/page.tsx` | `handleApprove`/`handleReject` fetch calls had no `Content-Type` header or body — FastAPI could return 422 | Added `headers: { "Content-Type": "application/json" }, body: "{}"` to both handlers |
| 6 | Low | `remediation-brain/agent/nodes.py` | `enforce_node` returned `"reasoning_trace": executed` (same list as `executed_actions`) — duplicate content in final reports | Fixed to `"reasoning_trace": [action_msg]` — single high-level summary string |
| 7 | Low | `remediation-brain/` | No test requirements file — `pytest`, `pytest-asyncio`, `pytest-mock` were missing | Created `requirements-test.txt` with pinned versions |
| 8 | Low | `api-gateway/krakend.json` | `/api/v1/{endpoint}` wildcard only matches single path segment — `/api/v1/legacy-payments/charge` would pass through unenforced | Added GET+POST endpoints for `/api/v1/{endpoint}/{sub}` (two-segment paths) |

---

### Improvement — Groq Structured Output for Incident Reports

**Problem:** `report_node` called `_llm.ainvoke(prompt)` and received a raw string, then embedded it as a markdown blob. The UI had no way to extract individual fields — it rendered the whole string as unstructured text.

**Solution:** Replaced raw string invocation with `.with_structured_output(IncidentReport)`.

**Files changed:**

**`remediation-brain/agent/nodes.py`**
- Added `IncidentReport` Pydantic model with 4 typed fields:
  - `executive_summary` — 3-4 sentence stakeholder summary
  - `risk_level` — `Literal["critical", "high", "medium", "low"]`
  - `recommended_action` — single concrete next step
  - `technical_detail` — technical explanation for the security team
- `_llm_structured = _llm.with_structured_output(IncidentReport)` — Groq returns a validated object, not a raw string
- `report_node` now returns `{"report": dict}` with all fields accessible by key
- Heuristic fallback (no `GROQ_API_KEY`) uses the same dict shape — UI never needs to branch
- Structured LLM failure falls back gracefully to heuristic values with a warning log

**`remediation-brain/agent/state.py`**
- `report: Optional[str]` → `report: Optional[dict[str, Any]]`

**`remediation-brain/api/routes.py`**
- `GET /incidents` list endpoint: extracts `report_summary` (3 keys: `executive_summary`, `risk_level`, `recommended_action`) from already-loaded checkpoint state — zero extra DB hits
- `report_preview` in approve/reject responses now reads `report["executive_summary"][:300]` instead of truncating a markdown string

**`intelligence-ui/app/components/IncidentPanel.tsx`**
- Added `IncidentReportSummary` interface and `report_summary` field to `Incident`
- Completed incident cards now render an inline report block: executive summary paragraph + highlighted "Next step" line

**`intelligence-ui/app/globals.css`**
- Added `.incident-report-summary` CSS block with `__text`, `__action`, `__action-label`, `__action-text` sub-elements matching the glassmorphism theme

---

### Architecture Notes

**Drift stats proxy chain (complete end-to-end):**
```
Browser → GET /drift/stats (relative URL)
  → Next.js server rewrite (next.config.ts)
    → SENSOR_METRICS_URL = http://host.docker.internal:9090
      → eBPF sensor metrics server (network_mode: host, port 9090)
```
Previously the browser fetched `http://localhost:9090` directly — broken on any remote host.

**Report pipeline (before → after):**
```
Before:
  report_node → _llm.ainvoke(prompt) → raw string → markdown blob stored in state
  UI: renders monolithic text, no field access

After:
  report_node → _llm_structured.ainvoke(prompt) → IncidentReport(validated) → typed dict
  UI: executive_summary + recommended_action rendered as structured card sections
  Fallback: same dict shape, heuristic values — UI always works regardless of LLM config
```

### Phase Status Summary

| Phase | Status |
|-------|--------|
| Phase 1 — Infrastructure Scaffolding | COMPLETE |
| Phase 2.1 — eBPF TLS Sensor | COMPLETE |
| Phase 2.2 — Go Orchestrator + Drift Detection | COMPLETE |
| Phase 3 — LangGraph Agentic Remediation Engine | COMPLETE |
| Phase 4 — GitOps Enforcement + Dynamic Deception | COMPLETE |
| Phase 5 — Interactive Intelligence Dashboard | COMPLETE |
| **Session 10 — Full Audit + 8 Bug Fixes + Structured Output** | **COMPLETE** |
| Phase 3b — Agentic API Protection | NEXT |

### Next Session

Potential improvements identified but not yet implemented (in priority order):
1. **SSE push** — replace 5s polling with Server-Sent Events from brain `/events` endpoint
2. **Incident deduplication** — deduplicate by `(path, classification)` with 5-minute window before creating a new LangGraph thread
3. **`make up-live` bug** — `$(COMPOSE) up -d` never sets `SENSOR_MODE=live` — needs `SENSOR_MODE=live $(COMPOSE) up -d`
4. **Page-Hinkley params as env vars** — `DRIFT_DELTA`, `DRIFT_LAMBDA`, `DRIFT_WINDOW_S` instead of hardcoded constants
5. **LangGraph retry edge** — `enforce → enforce` loop (max 3) for GitHub API / honeypot failures
6. **KrakenD 3+ segment paths** — current wildcard only handles 1-2 segments, true catch-all needs router-level solution
7. **Redis auth** — add `--requirepass` and thread `REDIS_PASSWORD` through all connection URLs
8. **`intelligence-ui` startup ordering** — add `remediation-brain` to `depends_on` to prevent 502s on first load
