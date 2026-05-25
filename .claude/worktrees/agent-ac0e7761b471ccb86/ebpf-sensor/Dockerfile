# syntax=docker/dockerfile:1
# =============================================================================
# ebpf-sensor — Multi-stage Build
#
# Stage 1 (builder): installs clang/llvm, runs bpf2go to compile http_trace.c
#                    into a Go-embeddable eBPF object, then builds the binary.
# Stage 2 (runtime): minimal Debian image with only runtime libs.
#
# Notes:
#   - go.sum must be committed to the repo. Run `go mod tidy` locally on Linux
#     to generate it; the Docker build uses `go mod download` (read-only).
#   - Debug symbols are intentionally retained (per go-ebpf-standards.md).
#   - The binary runs as root; eBPF requires root or CAP_BPF.
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM golang:1.24-bookworm AS builder

# clang + llvm: required by bpf2go to compile the eBPF C program
# libbpf-dev + libelf-dev + zlib1g-dev: required for eBPF linking
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    linux-libc-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

WORKDIR /build

# Download dependencies first — separate layer so Docker caches it.
# go.sum must be present in the repo; `go mod download` fetches all declared
# modules (including github.com/cilium/ebpf which contains bpf2go) without
# modifying go.mod or go.sum. Do NOT use `go mod tidy` in Docker — it tries
# to modify go.sum and fails if checksums don't match the build environment.
COPY go.mod go.sum ./
RUN go mod download

# Copy source after deps are cached.
COPY . .

# Run bpf2go: compiles bpf/http_trace.c → Go bindings (http_trace_bpfel.go etc.)
# This requires clang to be in PATH (installed above).
RUN go generate ./...

# Build the sensor binary.
# CGO_ENABLED=0 produces a fully static binary for the slim runtime image.
# Debug symbols retained per project standards (no -s -w).
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o ebpf-sensor .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# libelf1 + zlib1g: runtime dependencies for loading eBPF ELF objects
# curl: used by Docker HEALTHCHECK
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    zlib1g \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/ebpf-sensor ./ebpf-sensor
# Mock fixture data for SENSOR_MODE=mock (works on any OS)
COPY --from=builder /build/fixtures/ ./fixtures/

# eBPF requires root or CAP_BPF; capabilities are granted via docker-compose.
USER root

ENTRYPOINT ["/app/ebpf-sensor"]
