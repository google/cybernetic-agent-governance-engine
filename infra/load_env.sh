#!/usr/bin/env bash
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

# Sourced helper: never enable `set -e` (which mutates the caller's interactive
# shell) and use `return 1` when sourced (`exit 1` only if executed directly).
_cage_load_env() {
    local env_file="${1:-.env}"
    local script_path="${BASH_SOURCE[0]:-${(%):-%x}}" # bash + macOS zsh support
    local project_root
    project_root="$(cd "$(dirname "$script_path")/.." && pwd)"

    if [ ! -f "$project_root/$env_file" ]; then
        echo "❌ Error: $env_file not found in $project_root" >&2
        echo "💡 Copy .env.example to .env and fill in your values:" >&2
        echo "   cp .env.example .env" >&2
        return 1
    fi

    echo "🔧 Loading Terraform variables from $env_file (selective TF_VAR_* export)..."

    local line var_name var_value
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty/whitespace lines
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]] || [[ "$line" =~ ^[[:space:]]*$ ]]; then
            continue
        fi

        if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
            var_name="${BASH_REMATCH[1]}"
            var_value="${BASH_REMATCH[2]}"

            # Strip surrounding quotes without spawning external subprocesses
            var_value="${var_value%\"}"
            var_value="${var_value#\"}"
            var_value="${var_value%\'}"
            var_value="${var_value#\'}"

            # Selective export (IC-07 / POAM-2026-184): never export raw .env secrets
            # into child process environments; only keys mapped in the case statement
            # below are exported with a TF_VAR_ prefix.
            case "$var_name" in
                AWS_ACCESS_KEY_ID)
                    export TF_VAR_aws_access_key="$var_value"
                    ;;
                AWS_SECRET_ACCESS_KEY)
                    export TF_VAR_aws_secret_key="$var_value"
                    ;;
                MODEL_REASONING)
                    if [[ "$var_value" == gs://* ]]; then
                        export TF_VAR_model_reasoning="$var_value"
                    else
                        export TF_VAR_served_model_reasoning="$var_value"
                    fi
                    ;;
                MODEL_FAST)
                    if [[ "$var_value" == gs://* ]]; then
                        export TF_VAR_model_fast="$var_value"
                    else
                        export TF_VAR_served_model_fast="$var_value"
                    fi
                    ;;
                MODEL_CONSENSUS)
                    export TF_VAR_model_consensus="$var_value"
                    ;;
                LANGFUSE_HOST)
                    export TF_VAR_langfuse_host="$var_value"
                    ;;
                LANGFUSE_PUBLIC_KEY)
                    export TF_VAR_langfuse_public_key="$var_value"
                    ;;
                LANGFUSE_SECRET_KEY)
                    export TF_VAR_langfuse_secret_key="$var_value"
                    ;;
                LANGFUSE_COMPLIANCE_PUBLIC_KEY)
                    export TF_VAR_langfuse_compliance_public_key="$var_value"
                    ;;
                LANGFUSE_COMPLIANCE_SECRET_KEY)
                    export TF_VAR_langfuse_compliance_secret_key="$var_value"
                    ;;
                GATEWAY_LANGFUSE_PUBLIC_KEY)
                    export TF_VAR_gateway_langfuse_public_key="$var_value"
                    ;;
                GATEWAY_LANGFUSE_SECRET_KEY)
                    export TF_VAR_gateway_langfuse_secret_key="$var_value"
                    ;;
                OPERATOR_OIDC_ISSUER|CAGE_OPERATOR_OIDC_ISSUER)
                    export TF_VAR_operator_oidc_issuer="$var_value"
                    ;;
                OPERATOR_OIDC_AUDIENCE|CAGE_OPERATOR_OIDC_AUDIENCE)
                    export TF_VAR_operator_oidc_audience="$var_value"
                    ;;
                OPERATOR_JWKS_URI|CAGE_OPERATOR_JWKS_URI)
                    export TF_VAR_operator_jwks_uri="$var_value"
                    ;;
                REGISTRY_URL)
                    export TF_VAR_registry_url="$var_value"
                    ;;
                K8S_NAMESPACE)
                    export TF_VAR_namespace="$var_value"
                    ;;
                ENVIRONMENT)
                    export TF_VAR_environment="$var_value"
                    ;;
                CAGE_DEPLOYMENT_REGION)
                    export TF_VAR_cage_deployment_region="$var_value"
                    ;;
                GOVERNANCE_SALT)
                    export TF_VAR_governance_salt="$var_value"
                    ;;
                STORAGE_BACKEND)
                    export TF_VAR_storage_backend="$var_value"
                    ;;
                COLD_TIER_BUCKET)
                    export TF_VAR_cold_tier_bucket="$var_value"
                    ;;
                REDIS_URL)
                    export TF_VAR_redis_url="$var_value"
                    ;;
                GOOGLE_CLOUD_PROJECT)
                    export TF_VAR_project_id="$var_value"
                    ;;
                GOOGLE_CLOUD_LOCATION)
                    export TF_VAR_region="$var_value"
                    ;;
                EVIDENCE_PREVIOUS_CHAIN_HEAD_HASH)
                    export TF_VAR_evidence_previous_chain_head_hash="$var_value"
                    ;;
                EVIDENCE_PREVIOUS_BATCH_ATTESTATION_DIGEST)
                    export TF_VAR_evidence_previous_batch_attestation_digest="$var_value"
                    ;;
                INFRA_EVIDENCE_PREVIOUS_CHAIN_HEAD_HASH)
                    export TF_VAR_infra_evidence_previous_chain_head_hash="$var_value"
                    ;;
                INFRA_EVIDENCE_PREVIOUS_BATCH_ATTESTATION_DIGEST)
                    export TF_VAR_infra_evidence_previous_batch_attestation_digest="$var_value"
                    ;;
            esac
        fi
    done < "$project_root/$env_file"

    echo "✅ Terraform TF_VAR_* variables loaded successfully"
    echo ""
    echo "📋 Key Terraform variables set:"
    echo "   TF_VAR_environment=${TF_VAR_environment:-<not set>}"
    echo "   TF_VAR_namespace=${TF_VAR_namespace:-<not set>}"
    echo "   TF_VAR_registry_url=${TF_VAR_registry_url:-<not set>}"
    echo "   TF_VAR_storage_backend=${TF_VAR_storage_backend:-<not set>}"
    echo ""
}

_cage_load_env "${1:-.env}" || {
    unset -f _cage_load_env
    return 1 2>/dev/null || exit 1
}
unset -f _cage_load_env
