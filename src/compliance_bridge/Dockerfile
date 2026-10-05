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


# Two-stage build. The builder stage holds uv and resolves the locked venv;
# the runtime stage starts again from the base and receives only the venv and
# the source tree, so neither uv nor any build tooling ships in the image.
# No C toolchain is installed at all: `uv sync --no-build` below refuses
# source builds, so a compiler could never be used.

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

RUN apk add --no-cache python-3.12

# Install uv for dependency management (builder only — not shipped at runtime).
# Pin to a specific version to guarantee reproducible builds — never use :latest,
# which can silently introduce breaking changes between Cloud Build runs.
# To upgrade: bump the version here, run `uv lock` locally, and commit both files.
# Bumped from 0.10.9: that build statically links quinn-proto 0.11.12 and
# rustls-webpki 0.103.8, both with fixed-version CVEs (CVE-2026-31812,
# GHSA-4w2j-m93h-cj5j, GHSA-82j2-j2ch-gfr8) flagged by the SBOM/CVE Trivy scan.
COPY --from=ghcr.io/astral-sh/uv:0.12.2 /uv /usr/local/bin/uv

# Use the system interpreter so the venv's python symlink
# (/usr/bin/python3.12) resolves identically in the runtime stage.
ENV UV_PYTHON=/usr/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

# Copy dependency definitions — both files required for uv sync --frozen.
# Build context must be the monorepo root so pyproject.toml and uv.lock are reachable.
COPY pyproject.toml uv.lock ./

# Install locked dependencies exactly as resolved by uv lock.
# --frozen enforces the lockfile; --no-dev skips test/lint extras.
# --no-install-project skips building the project package itself (we import
#   source directly via PYTHONPATH=/app, not as an installed package).
# --no-build prevents falling back to source compilation if a pre-built wheel
#   is unavailable (e.g. CDN propagation lag after a fresh PyPI release).
#   A missing wheel produces a clear error rather than a silent C-compile failure.
# --extra compliance pulls google-cloud-storage (native GCS SDK, ADC/Workload Identity),
#   boto3 (S3-compat fallback for non-GCP targets, activated via STORAGE_BACKEND=s3),
#   and PyYAML (?format=yaml support)
# --extra langfuse pulls the langfuse SDK
RUN uv sync --frozen --no-dev --no-install-project --no-build --extra compliance --extra langfuse

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE}

WORKDIR /app

# Runtime interpreter plus the C++ runtime that native wheels link against.
# `apk upgrade` picks up fixes published since the base digest was cut.
# Non-root user for security (mirrors GKE best practices).
RUN apk upgrade --no-cache \
    && apk add --no-cache python-3.12 libstdc++ libgcc tzdata \
    && adduser -D -H -u 1000 -s /bin/false appuser

# Locked virtual environment from the builder stage. Copied before the source
# so this heavy layer is cached across source changes.
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv

# Copy application source — all directories needed by the compliance-bridge.
# src/__init__.py and src/integrations/ are required because
# src/gateway/governance/evidence/factory.py, src/gateway/governance/signer_factory.py,
# and src/compliance_bridge/main.py lazy-import G3-allowlisted seams under
# src.integrations.*, and since #325 EvidenceCustodian.from_env() runs at startup.
# Keep the whole-package copy: a curated sub-list is a hidden coupling that drifts
# each time a provider is added.
COPY --chown=appuser:appuser src/__init__.py        /app/src/__init__.py
COPY --chown=appuser:appuser src/compliance_bridge /app/compliance_bridge/
COPY --chown=appuser:appuser src/compliance_bridge /app/src/compliance_bridge/
COPY --chown=appuser:appuser src/gateway            /app/src/gateway/
COPY --chown=appuser:appuser src/integrations       /app/src/integrations/
COPY --chown=appuser:appuser config                 /app/config/
COPY --chown=appuser:appuser compliance             /app/compliance/
COPY --chown=appuser:appuser README.md              /app/README.md

# PYTHONPATH=/app allows both:
#   - "compliance_bridge.main" (module at /app/compliance_bridge/)
#   - "src.gateway.governance.defer_queue" (module at /app/src/gateway/)
ENV PYTHONPATH=/app

# Add the uv-managed venv to PATH so uvicorn is found without `uv run`.
# Invoking uvicorn directly (not via `uv run`) avoids the project-install
# step that `uv run` triggers and which fails because src/cybernetic_governance_engine/
# is not present in the image.
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

USER appuser

# Expose port (default 3001; override via --build-arg PORT=<n>)
ARG PORT=3001
ENV PORT=$PORT
EXPOSE $PORT

# Invoke uvicorn directly from the venv — NOT via `uv run` to avoid the
# project-package re-install step that `uv run` triggers at container startup.
CMD ["sh", "-c", "uvicorn compliance_bridge.main:app --host 0.0.0.0 --port $PORT --timeout-keep-alive 120"]
