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


# Governed financial advisor image (the GKE `governed-financial-advisor`
# workload; the gateway and compliance-bridge images live under src/).
#
# Two-stage build. The builder stage holds the C toolchain and uv; the runtime
# stage starts again from the base and receives only the locked venv and the
# source tree, so no compiler, kernel headers or uv ship in the image.

# Base image: Wolfi (glibc, apk) pinned by digest. Wolfi ships no util-linux,
# perl or ncurses in the base layer and rebuilds packages as upstream fixes land,
# which python:3.12-slim-bookworm could not offer (POAM-2026-101). glibc keeps
# manylinux wheels working unchanged. `python-3.12` pins the interpreter minor
# version to match pyproject.toml (requires-python <3.13).
# To bump the base: resolve the new digest of cgr.dev/chainguard/wolfi-base:latest
# and update WOLFI_BASE in all four Python Dockerfiles together (including
# deployment/docker/Dockerfile.nemo).
ARG WOLFI_BASE=cgr.dev/chainguard/wolfi-base@sha256:9c2092b053779e14c82fb50f77b37bcc38b7d2c83972352d5813280f9d035b03

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE} AS builder

WORKDIR /app

# Interpreter, its headers, and the build toolchain (builder only).
# git is not installed: uv.lock has no git sources.
RUN apk add --no-cache python-3.12 python-3.12-dev build-base

# Install uv for dependency management (builder only — not shipped at runtime).
# Pinned for reproducible builds, matching src/gateway/Dockerfile.
COPY --from=ghcr.io/astral-sh/uv:0.12.2 /uv /bin/uv

# Use the system interpreter so the venv's python symlink
# (/usr/bin/python3.12) resolves identically in the runtime stage.
ENV UV_PYTHON=/usr/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

# Create a virtual environment — uv sync always uses one
RUN uv venv /app/.venv
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Copy dependency definitions — both files required for uv sync --frozen
COPY pyproject.toml uv.lock ./

# Install locked dependencies exactly as resolved by uv lock.
# --frozen enforces the lockfile; --no-dev skips test/lint extras.
# --no-install-project installs only deps (not the project itself) so the
# source tree doesn't need to exist yet — keeping this as a cacheable layer.
# --extra advisor pulls langgraph, langchain, yfinance, google-adk,
#                  opentelemetry-exporter-gcp-trace etc.
# --extra langfuse pulls the langfuse SDK and observability helpers.
# --extra compliance pulls dowhy (Tier 6 causal gatekeeper, No-Direct-Bind Gap 4)
RUN uv sync --frozen --no-dev --extra advisor --extra langfuse --extra gateway --extra compliance --no-install-project

# Install spaCy large model via direct wheel URL (avoids CDN redirect failures).
# `uv pip install` targets the venv; a bare `pip` here used to resolve to the
# base image's system pip and install the model outside the venv.
RUN uv pip install --no-cache \
    "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE}

WORKDIR /app

# Runtime interpreter plus the C++ runtime that native wheels link against.
# `apk upgrade` picks up fixes published since the base digest was cut.
# Non-root user matching runAsUser: 1000 in deployment/k8s/financial-advisor.yaml.
# Application files stay root-owned, so the process cannot modify its own code.
RUN apk upgrade --no-cache \
    && apk add --no-cache python-3.12 libstdc++ libgcc tzdata \
    && adduser -D -H -u 1000 -s /bin/false appuser

COPY --from=builder /app/.venv /app/.venv

# Application source — an explicit allowlist rather than `COPY . .`, which
# shipped whatever the build context held (UI sources, local node_modules,
# third_party checkouts) and put it in the CVE scan surface.
COPY src/__init__.py /app/src/__init__.py
COPY src/cybernetic_governance_engine /app/src/cybernetic_governance_engine
COPY src/governed_financial_advisor /app/src/governed_financial_advisor
COPY src/gateway /app/src/gateway
COPY src/cage_finance /app/src/cage_finance
COPY src/cage_healthcare /app/src/cage_healthcare
COPY src/cage_physical_ai /app/src/cage_physical_ai
COPY src/compliance_bridge /app/src/compliance_bridge
COPY src/integrations /app/src/integrations
COPY config /app/config
COPY compliance /app/compliance
COPY README.md /app/README.md

ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH=/app:/app/src

USER appuser

# Expose the port (default 8080; override via --build-arg PORT=<n>)
ARG PORT=8080
ENV PORT=$PORT
EXPOSE $PORT

# Run the server
CMD ["python", "-m", "src.governed_financial_advisor.server"]
