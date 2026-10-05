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
# without a manylinux build; the runtime stage starts again from the slim base
# and receives only the finished /app tree. gcc/g++ pull libc6-dev and
# linux-libc-dev (kernel headers), which carried ~40 HIGH kernel CVEs in the
# SBOM/CVE Trivy scan while serving no purpose at runtime.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

# Build toolchain only. python3-dev is not installed: it ships headers for
# Debian's python3.11, not for the /usr/local python3.12 this image runs, and
# dragged libpython3.11 (CVE-2025-13462) into the image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install uv for dependency management (builder only — not shipped at runtime)
COPY --from=ghcr.io/astral-sh/uv:0.12.2 /uv /bin/uv

# Use the base image's interpreter so the venv's python symlink
# (/usr/local/bin/python3.12) resolves identically in the runtime stage.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

# Copy dependency definitions — both files required for uv sync --frozen
COPY pyproject.toml uv.lock ./

# Create virtual env for the gateway
RUN uv venv
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Install locked dependencies exactly as resolved by uv lock.
# --frozen enforces the lockfile; --no-dev skips test/lint extras.
# --no-install-project installs only deps before the source tree is copied.
# Install both gateway AND advisor extras (gateway imports from governed_financial_advisor)
# --extra compliance pulls dowhy (Tier 6 causal gatekeeper, No-Direct-Bind Gap 4)
# --extra langfuse: every gateway manifest selects CAGE_TELEMETRY_PROVIDER=remote,
#   whose adapter (src/integrations/telemetry_langfuse) imports langfuse at startup.
RUN uv sync --frozen --no-dev --extra gateway --extra advisor --extra compliance --extra langfuse --no-install-project

# Download spaCy large model via direct wheel URL (avoids CDN redirect failures).
# Use uv pip install so the package lands in the uv-managed venv — never bypass
# uv with a bare 'pip' call inside a uv-managed container.
RUN uv pip install --no-cache \
    "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"

# Copy Source Code
COPY src/__init__.py /app/src/__init__.py
COPY src/cybernetic_governance_engine /app/src/cybernetic_governance_engine
COPY src/gateway /app/src/gateway
COPY src/cage_finance /app/src/cage_finance
COPY src/cage_healthcare /app/src/cage_healthcare
COPY src/governed_financial_advisor /app/src/governed_financial_advisor
COPY src/compliance_bridge /app/src/compliance_bridge
COPY src/integrations /app/src/integrations
COPY config /app/config
COPY README.md /app/README.md

# Install the project itself so entry-point metadata exists in the image.
RUN uv pip install --no-deps .

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

WORKDIR /app

# Pick up any Debian security fixes published since the base image was cut.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# M-24: Run as non-root user (UID 1000) to satisfy PSA restricted policy.
RUN useradd --no-create-home --shell /bin/false --uid 1000 appuser

COPY --from=builder --chown=appuser:appuser /app /app

# Environment Variables
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/src

USER appuser

# Expose port (default 8080; override via --build-arg PORT=<n>)
ARG PORT=8080
ENV PORT=$PORT
EXPOSE $PORT

# Run the Hybrid Gateway server
CMD ["python", "src/gateway/server/hybrid_server.py"]
