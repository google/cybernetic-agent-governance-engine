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

ARG WOLFI_BASE=cgr.dev/chainguard/wolfi-base@sha256:f15fea2f49cb14dceaea491fcbde0d35e0c190126a744ac05a9838440d47d994
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85

FROM ${UV_IMAGE} AS uv

FROM ${WOLFI_BASE} AS builder
WORKDIR /app
RUN apk upgrade --no-cache && apk add --no-cache python-3.12
COPY --from=uv /uv /bin/uv
ENV UV_PYTHON=/usr/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy
RUN uv venv --python /usr/bin/python3.12 /app/.venv
COPY dist/ /dist/
RUN uv pip install --python /app/.venv --no-cache --no-deps /dist/*.whl

FROM ${WOLFI_BASE}
LABEL org.opencontainers.image.title="cage-conformance"
LABEL org.opencontainers.image.description="Standalone Conformance Verifier for CAGE Governance Traces, Evidence Streams, and Partner Endpoints"
LABEL org.opencontainers.image.source="https://github.com/google/cybernetic-agent-governance-engine"
LABEL org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates-bundle python-3.12 \
    && (grep -q '^nonroot:' /etc/group || addgroup -g 65532 nonroot) \
    && (grep -q '^nonroot:' /etc/passwd || adduser -D -H -u 65532 -G nonroot -s /sbin/nologin nonroot)
COPY --from=builder /app/.venv /app/.venv
ARG CONF_VERSION=dev
ARG COMMIT_SHA=unknown
LABEL org.opencontainers.image.version="${CONF_VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT_SHA}"
ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
ENTRYPOINT ["cage-conformance"]
