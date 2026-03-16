# AuralisAPI Agent Boundaries

This repository uses strict domain isolation for AI agents.

Developer Alpha Agents
Allowed Directories:
- /ebpf-sensor
- /remediation-brain
- /infra
- /scripts

Responsibilities:
- eBPF telemetry sensors
- Go orchestrator
- Drift detection algorithms
- Redis streaming pipeline
- LangGraph reasoning engine

Technologies:
Go, Python, eBPF, LangGraph, Redis, PostgreSQL

---

Developer Beta Agents
Allowed Directories:
- /api-gateway
- /honeypot-decoy
- /intelligence-ui

Responsibilities:
- KrakenD enforcement layer
- API gateway configuration
- OpenCanary honeypots
- Next.js intelligence dashboard
- D3.js visualization

Technologies:
Next.js, React, D3.js, KrakenD, Docker, OpenCanary

---

Rules:
Agents MUST NOT modify directories outside their assigned domain.

All merges require human review.