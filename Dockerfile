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
# stage starts again from the slim base and receives only the locked venv and
# the source tree. build-essential pulls libc6-dev and linux-libc-dev (kernel
# headers), which carried ~40 HIGH kernel CVEs in the SBOM/CVE Trivy scan while
# serving no purpose at runtime.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

# Build toolchain only. git is not installed: uv.lock has no git sources.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install uv for dependency management (builder only — not shipped at runtime).
# Pinned for reproducible builds, matching src/gateway/Dockerfile.
COPY --from=ghcr.io/astral-sh/uv:0.12.2 /uv /bin/uv

# Use the base image's interpreter so the venv's python symlink
# (/usr/local/bin/python3.12) resolves identically in the runtime stage.
ENV UV_PYTHON_DOWNLOADS=never \
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
# `uv pip install` targets the venv; a bare `pip` here resolved to the base
# image's /usr/local pip and installed the model outside the venv.
RUN uv pip install --no-cache \
    "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

WORKDIR /app

# Pick up any Debian security fixes published since the base image was cut.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Non-root user matching runAsUser: 1000 in deployment/k8s/financial-advisor.yaml.
# Application files stay root-owned, so the process cannot modify its own code.
RUN useradd --no-create-home --shell /bin/false --uid 1000 appuser

COPY --from=builder /app/.venv /app/.venv

# Copy project files
COPY . .

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
