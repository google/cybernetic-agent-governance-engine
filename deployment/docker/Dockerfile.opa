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

# ─── Stage 1: Policy Builder ─────────────────────────────────────────────────
FROM openpolicyagent/opa:0.70.0-static AS policy-builder

WORKDIR /build

# Copy all policy files from both locations
COPY config/opa/ /build/config/opa/
COPY src/cage_finance/opa/ /build/src/cage_finance/opa/

# Validate all policies at build time (fail-closed)
RUN opa check /build/config/opa/*.rego /build/src/cage_finance/opa/*.rego

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM openpolicyagent/opa:0.70.0-static

# Install envsubst for runtime configuration templating
USER root
RUN apk add --no-cache gettext

# Create non-root user (UID 65534 = nobody)
USER 65534

WORKDIR /policies

# Copy validated policies from builder stage
COPY --from=policy-builder /build/config/opa/*.rego /policies/
COPY --from=policy-builder /build/src/cage_finance/opa/*.rego /policies/

# Copy OPA runtime configuration template
COPY deployment/docker/opa_config.yaml /config/opa_config.yaml

# Copy entrypoint wrapper
COPY deployment/docker/opa-entrypoint.sh /usr/local/bin/opa-entrypoint.sh

# Ensure entrypoint is executable
USER root
RUN chmod +x /usr/local/bin/opa-entrypoint.sh
USER 65534

# Fail-closed entrypoint: resolve environment variables, then start OPA
ENTRYPOINT ["/usr/local/bin/opa-entrypoint.sh"]
CMD ["run", "--server", "--config-file=/config/opa_config.yaml", "/policies"]
