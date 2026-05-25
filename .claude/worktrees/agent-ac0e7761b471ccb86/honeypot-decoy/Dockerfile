# syntax=docker/dockerfile:1
# honeypot-decoy — OpenCanary HTTP + SSH honeypot
#
# Runs opencanaryd in --dev (foreground) mode so the container stays alive.
# Config is bind-mounted from the host at runtime via docker-compose.yml.

FROM python:3.12-slim

# Build deps for cryptography (OpenCanary dependency) and curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    libssl-dev \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY start.sh /start.sh
RUN chmod +x /start.sh

# Phase 4: dynamic honeypot server and config generator
COPY honeypot_server.py /app/honeypot_server.py
COPY config_generator.py /app/config_generator.py

# 8081 = OpenCanary HTTP honeypot
# 2222 = OpenCanary SSH honeypot
# 8082 = Dynamic honeypot FastAPI server (Phase 4)
EXPOSE 8081 2222 8082

ENTRYPOINT ["/start.sh"]
