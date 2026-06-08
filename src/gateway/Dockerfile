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

FROM python:3.12-slim-bookworm

WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

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
RUN uv sync --frozen --no-dev --extra gateway --extra advisor --no-install-project

# Download spaCy large model via direct wheel URL (avoids CDN redirect failures).
# Use uv pip install so the package lands in the uv-managed venv — never bypass
# uv with a bare 'pip' call inside a uv-managed container.
RUN uv pip install --no-cache \
    "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"

# Copy Source Code
COPY src/gateway /app/src/gateway
COPY src/governed_financial_advisor /app/src/governed_financial_advisor
COPY config /app/config

# Environment Variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose port (default 8080; override via --build-arg PORT=<n>)
ARG PORT=8080
ENV PORT=$PORT
EXPOSE $PORT

# Run the Hybrid Gateway server
CMD ["python", "src/gateway/server/hybrid_server.py"]
