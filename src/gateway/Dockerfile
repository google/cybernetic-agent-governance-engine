# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Two-stage build. The builder stage holds the C toolchain needed by wheels
# without a manylinux build; the runtime stage starts again from the base and
# receives only the finished /app tree, so no compiler, kernel headers or uv
# ship in the image.

# Base image: Wolfi (glibc, apk) pinned by digest. Wolfi ships no util-linux,
# perl or ncurses in the base layer and rebuilds packages as upstream fixes land,
# which python:3.12-slim-bookworm could not offer (POAM-2026-101). glibc keeps
# manylinux wheels working unchanged. `python-3.12` pins the interpreter minor
# version to match pyproject.toml (requires-python <3.13).
# To bump the base: resolve the new digest of cgr.dev/chainguard/wolfi-base:latest
# and update WOLFI_BASE in all four Python Dockerfiles together (including
# deployment/docker/Dockerfile.nemo).
ARG WOLFI_BASE=cgr.dev/chainguard/wolfi-base@sha256:f15fea2f49cb14dceaea491fcbde0d35e0c190126a744ac05a9838440d47d994
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85

# ---------------------------------------------------------------------------
# Stage 0 — digest-pinned uv binary source (BuildKit rejects --from=${ARG})
# ---------------------------------------------------------------------------
FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE} AS builder

WORKDIR /app

# Interpreter, its headers, and the build toolchain (builder only).
RUN apk add --no-cache python-3.12 python-3.12-dev build-base

# Install uv for dependency management (builder only — pinned by immutable OCI index digest)
COPY --from=uv /uv /bin/uv

# Use the system interpreter so the venv's python symlink
# (/usr/bin/python3.12) resolves identically in the runtime stage.
ENV UV_PYTHON=/usr/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

# Copy dependency definitions — both files required for uv sync --frozen
COPY pyproject.toml uv.lock ./

# Create virtual env for the gateway using the system interpreter
RUN uv venv --python /usr/bin/python3.12 /app/.venv
ENV VIRTUAL_ENV=/app/.venv \
    UV_PYTHON=/app/.venv/bin/python \
    PATH="/app/.venv/bin:$PATH"

# Install locked dependencies exactly as resolved by uv lock.
# --frozen enforces the lockfile; --no-dev skips test/lint extras.
# --no-install-project installs only deps before the source tree is copied.
# No model client, runtime or LLM framework is installed (POAM-2026-168);
# scripts/check_model_free_install.py checks the closure of these extras.
# The advisor extra is not installed: nothing in this image imports
# src/governed_financial_advisor (an earlier comment here said the gateway did).
# The opt-in nemo (CAGE_NEMO_ENABLED) and inference
# (CAGE_CONSENSUS_CRITICS_ENABLED) extras are not installed either; enabling
# either switch needs an image built with that extra.
# --extra compliance pulls dowhy (Tier 6 causal gatekeeper, No-Direct-Bind Gap 4)
# --extra langfuse: every gateway manifest selects CAGE_TELEMETRY_PROVIDER=remote,
#   whose adapter (src/integrations/telemetry_langfuse) imports langfuse at startup.
RUN uv sync --frozen --no-dev --extra gateway --extra compliance --extra langfuse --no-install-project

# Download and cryptographically verify spaCy en_core_web_lg 3.8.0 wheel via --require-hashes.
RUN printf '%s\n' \
    'en-core-web-lg @ https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl --hash=sha256:293e9547a655b25499198ab15a525b05b9407a75f10255e405e8c3854329ab63' \
    > /tmp/spacy-model.requirements.txt \
    && uv pip install --python /app/.venv --no-cache --no-deps --require-hashes -r /tmp/spacy-model.requirements.txt \
    && rm -f /tmp/spacy-model.requirements.txt

# Copy Source Code
COPY src/__init__.py /app/src/__init__.py
COPY src/cybernetic_governance_engine /app/src/cybernetic_governance_engine
COPY src/gateway /app/src/gateway
COPY src/cage_finance /app/src/cage_finance
COPY src/cage_healthcare /app/src/cage_healthcare
COPY src/cage_physical_ai /app/src/cage_physical_ai
COPY src/compliance_bridge /app/src/compliance_bridge
COPY src/integrations /app/src/integrations
COPY config /app/config
COPY README.md /app/README.md

# Install the project itself into the venv so entry-point metadata exists in the image.
RUN uv pip install --python /app/.venv --no-deps .

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE}

WORKDIR /app

# Runtime interpreter plus the C++ runtime that native wheels link against.
# `apk upgrade` picks up fixes published since the base digest was cut.
# M-24: Run as non-root user (UID 1000) to satisfy PSA restricted policy.
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates-bundle python-3.12 libstdc++ libgcc tzdata \
    && adduser -D -H -u 1000 -s /bin/false appuser

# Keep /app root-owned (root:root) so runtime appuser (UID 1000) cannot mutate code or venv.
COPY --from=builder /app /app

# Environment Variables
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TMPDIR=/tmp
ENV HOME=/tmp
ENV PYTHONPATH=/app:/app/src

USER appuser

# Expose port (default 8080; override via --build-arg PORT=<n>)
ARG PORT=8080
ENV PORT=$PORT
EXPOSE $PORT

# Run the Hybrid Gateway server
CMD ["python", "src/gateway/server/hybrid_server.py"]
