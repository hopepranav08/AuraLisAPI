# syntax=docker/dockerfile:1
# =============================================================================
# remediation-brain — Python 3.12 FastAPI + LangGraph
#
# Stage 1 (builder): install all Python deps including compiled C extensions
# Stage 2 (runtime): minimal image with only runtime libs
#
# Key dependencies and their system requirements:
#   asyncpg       — C extension; needs gcc but bundles its own libpq
#   psycopg[binary] — binary wheel; bundles its own libpq, no system libpq needed
#   frouros       — pure Python
#   scikit-learn  — needs gcc + BLAS at build time
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Isolated virtual environment for clean layer separation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# libpq5: runtime dep for asyncpg (SQLAlchemy driver)
# curl: used by Docker HEALTHCHECK
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy all Python source (agent/, api/, main.py)
# Note: .env files are NOT copied — secrets injected via docker-compose environment
COPY agent/ ./agent/
COPY api/ ./api/
COPY main.py .

EXPOSE 8000

# Single worker for LangGraph state consistency.
# Increase workers only after confirming thread-safe checkpointer usage.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
