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

WORKDIR /app

# Install system dependencies (needed for some C-extension wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency definitions — both files required for uv sync --frozen.
# Build context must be the monorepo root so pyproject.toml and uv.lock are reachable.
COPY pyproject.toml uv.lock ./

# Install locked dependencies exactly as resolved by uv lock.
# --frozen enforces the lockfile; --no-dev skips test/lint extras.
# --no-install-project skips building the project package itself (we import
#   source directly via PYTHONPATH=/app, not as an installed package).
# --extra compliance pulls google-cloud-storage (native GCS SDK, ADC/Workload Identity),
#   boto3 (S3-compat fallback for non-GCP targets, activated via STORAGE_BACKEND=s3),
#   and PyYAML (?format=yaml support)
# --extra langfuse pulls the langfuse SDK
# Done BEFORE copying source so this heavy layer is cached across source changes.
RUN uv sync --frozen --no-dev --no-install-project --extra compliance --extra langfuse

# Copy application source — all directories needed by the compliance-bridge.
# Placed AFTER uv sync to maximise Docker layer cache reuse.
COPY src/compliance_bridge /app/compliance_bridge/
COPY src/gateway            /app/src/gateway/
COPY config                 /app/config/
COPY compliance             /app/compliance/
COPY README.md              /app/README.md

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

# Non-root user for security (mirrors GKE best practices)
RUN useradd --no-create-home --shell /bin/false appuser

# Grant appuser ownership of workspace
RUN chown -R appuser:appuser /app

USER appuser

# Expose port (default 3001; override via --build-arg PORT=<n>)
ARG PORT=3001
ENV PORT=$PORT
EXPOSE $PORT

# Invoke uvicorn directly from the venv — NOT via `uv run` to avoid the
# project-package re-install step that `uv run` triggers at container startup.
CMD ["sh", "-c", "uvicorn compliance_bridge.main:app --host 0.0.0.0 --port $PORT"]
