# =============================================================================
# AegisKube-SecOps — Dockerfile
# =============================================================================
#
# Multi-stage build: produces a lean, security-hardened Python runtime image
# for running the AegisKube-SecOps security sentinel.
#
# Build:
#   docker build -t ghcr.io/hey-nawazsharif/aegiskube-secops:1.0.0 .
#
# Run (demo):
#   docker run --rm ghcr.io/hey-nawazsharif/aegiskube-secops:1.0.0 --demo
#
# Run (live — Linux only, requires elevated privileges):
#   docker run --rm --privileged --pid=host \
#     -v /etc:/host/etc:ro -v /var/log:/host/var/log:ro \
#     ghcr.io/hey-nawazsharif/aegiskube-secops:1.0.0 --full
#
# Author : Nawaz Sharif <contact@nawazsharif.in>
# License: Apache-2.0
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Security: don't run pip as root in final image
WORKDIR /build

# Copy and install dependencies first (layer caching)
COPY requirements.txt ./
RUN pip install --upgrade pip --no-cache-dir && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="AegisKube-SecOps"
LABEL org.opencontainers.image.description="High-Performance Linux & Kubernetes Cybersecurity Sentinel"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="Nawaz Sharif <contact@nawazsharif.in>"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/hey-nawazsharif/aegiskube-secops"
LABEL maintainer="Nawaz Sharif <contact@nawazsharif.in>"

# System packages needed for runtime inspection (iproute2 = ss, procps = ps)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        procps \
        net-tools \
        kmod \
        util-linux \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# ── Application ───────────────────────────────────────────────────────────────

# Create non-privileged user (used when host access is not required)
RUN groupadd -r aegiskube && \
    useradd -r -g aegiskube -d /app -s /sbin/nologin -c "AegisKube daemon" aegiskube

WORKDIR /app

# Copy source
COPY src/ ./src/
COPY scripts/ ./scripts/

# Make hardening script executable
RUN chmod +x scripts/kernel_hardening.sh

# Create data directory for ledger persistence
RUN mkdir -p /data && chown aegiskube:aegiskube /data

# Environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV AEGISKUBE_VERSION=1.0.0

# Health check: verify Python modules import cleanly
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "from src.linux_hardening_audit import run_audit; from src.ai_threat_detector import run_detection; from src.blockchain_audit_ledger import BlockchainAuditLedger; print('OK')"

# Expose metrics port (future Prometheus integration)
EXPOSE 9090

# Default: run demo mode (safe, no host access required)
# Override with --full for live system scanning
ENTRYPOINT ["python3", "src/main.py"]
CMD ["--demo"]
