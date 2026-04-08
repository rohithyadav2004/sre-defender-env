# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

ARG BASE_IMAGE=ghcr.io/meta-pytorch/openenv-base:latest
FROM ${BASE_IMAGE} AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

ARG BUILD_MODE=in-repo
ARG ENV_NAME=sre_defender_env

COPY . /app/env
WORKDIR /app/env

RUN if ! command -v uv >/dev/null 2>&1; then \
        curl -LsSf https://astral.sh/uv/install.sh | sh && \
        mv /root/.local/bin/uv /usr/local/bin/uv && \
        mv /root/.local/bin/uvx /usr/local/bin/uvx; \
    fi

RUN --mount=type=cache,target=/root/.cache/uv \
    if [ -f uv.lock ]; then \
        uv sync --frozen --no-install-project --no-editable; \
    else \
        uv sync --no-install-project --no-editable; \
    fi

RUN --mount=type=cache,target=/root/.cache/uv \
    if [ -f uv.lock ]; then \
        uv sync --frozen --no-editable; \
    else \
        uv sync --no-editable; \
    fi

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM ${BASE_IMAGE}

WORKDIR /app

# Install nginx, supervisor, curl
RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx supervisor curl && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js 24 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Create all writable directories owned by UID 1000 (HF Spaces user)
RUN mkdir -p /app/logs /app/config /app/sandbox/node && \
    chown -R 1000:1000 /app

# Copy Python venv and project code from builder
COPY --from=builder /app/env/.venv /app/.venv
COPY --from=builder /app/env /app/env

# Copy runtime configs (build context root = sre_defender_env/)
COPY config/nginx.conf /app/config/nginx.conf
COPY config/agent_rules.conf /app/config/agent_rules.conf
COPY sandbox/node/ /app/sandbox/node/
COPY supervisord.conf /app/supervisord.conf

# Install Node.js dependencies
RUN cd /app/sandbox/node && npm install

# Create read-only backup of original app.js for reset() restore
RUN cp /app/sandbox/node/app.js /app/sandbox/node/app.js.orig

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env:$PYTHONPATH"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# supervisord -n keeps it in the foreground (required for Docker PID 1)
CMD ["supervisord", "-c", "/app/supervisord.conf", "-n"]
