#!/bin/sh
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

set -euo pipefail

# Resolve environment variables in OPA configuration template
# Substitutes ${CAGE_COMPLIANCE_BRIDGE_URL} and ${CAGE_DEPLOYMENT_REGION}
envsubst < /config/opa_config.yaml > /tmp/opa_config_resolved.yaml

# Execute OPA with resolved configuration
exec opa "$@" --config-file=/tmp/opa_config_resolved.yaml
