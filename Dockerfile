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

FROM python:3.12-slim

# Set working directory
# Set working directory
WORKDIR /app
ENV PYTHONPATH=/app

# Install system dependencies
# git is often needed for installing dependencies from git
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv (pip install avoids GHCR connectivity issues in Cloud Build)
RUN pip install --no-cache-dir uv

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

# Install spaCy large model via direct wheel URL (avoids CDN redirect failures)
RUN pip install --no-cache-dir \
    "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"

# Copy project files
COPY . .

# Project files copied above. We run explicitly via python -m so no package installation is needed.

# Expose the port (default 8080; override via --build-arg PORT=<n>)
ARG PORT=8080
ENV PORT=$PORT
EXPOSE $PORT

# DEBUG: Check file content
RUN ls -R src && ls -R config

# Run the server
CMD ["python", "-m", "src.governed_financial_advisor.server"]
