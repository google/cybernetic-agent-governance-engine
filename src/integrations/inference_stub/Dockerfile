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

# Deterministic CPU OpenAI-compatible E2E inference stub (POAM-2026-191).
# Two-stage Wolfi build matching src/gateway/Dockerfile (non-root UID 1000,
# zero model SDKs or LLM runtimes).

ARG WOLFI_BASE=cgr.dev/chainguard/wolfi-base@sha256:f15fea2f49cb14dceaea491fcbde0d35e0c190126a744ac05a9838440d47d994

FROM ${WOLFI_BASE} AS builder

WORKDIR /app

RUN apk add --no-cache python-3.12 python-3.12-dev build-base
COPY --from=ghcr.io/astral-sh/uv:0.12.2 /uv /bin/uv

ENV UV_PYTHON=/usr/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./
RUN uv venv --python /usr/bin/python3.12 /app/.venv
ENV VIRTUAL_ENV=/app/.venv \
    UV_PYTHON=/app/.venv/bin/python \
    PATH="/app/.venv/bin:$PATH"

RUN uv sync --frozen --no-dev --extra gateway --no-install-project

COPY src/__init__.py /app/src/__init__.py
COPY src/integrations/__init__.py /app/src/integrations/__init__.py
COPY src/integrations/inference_stub /app/src/integrations/inference_stub

FROM ${WOLFI_BASE}

WORKDIR /app

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates-bundle python-3.12 libstdc++ libgcc tzdata \
    && adduser -D -H -u 1000 -s /bin/false appuser

COPY --from=builder --chown=appuser:appuser /app /app

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app:/app/src \
    INFERENCE_STUB_HOST=0.0.0.0 \
    INFERENCE_STUB_PORT=8000

USER appuser

EXPOSE 8000

CMD ["python", "-m", "src.integrations.inference_stub.server"]
