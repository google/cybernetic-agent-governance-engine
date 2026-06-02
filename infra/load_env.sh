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

set -e

# Default to .env in project root
ENV_FILE="${1:-.env}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "$PROJECT_ROOT/$ENV_FILE" ]; then
    echo "❌ Error: $ENV_FILE not found in $PROJECT_ROOT"
    echo "💡 Copy .env.example to .env and fill in your values:"
    echo "   cp .env.example .env"
    exit 1
fi

echo "🔧 Loading environment variables from $ENV_FILE..."

# Read .env and export as TF_VAR_* variables
# This allows Terraform to automatically pick them up
while IFS= read -r line || [ -n "$line" ]; do
    # Skip comments and empty lines
    if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]]; then
        continue
    fi
    
    # Skip lines that are just whitespace
    if [[ "$line" =~ ^[[:space:]]*$ ]]; then
        continue
    fi
    
    # Extract variable name and value
    if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
        var_name="${BASH_REMATCH[1]}"
        var_value="${BASH_REMATCH[2]}"
        
        # Remove surrounding quotes if present
        var_value=$(echo "$var_value" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
        
        # Export as both the original name and TF_VAR_ prefixed version
        export "$var_name=$var_value"
        
        # Map common .env variables to Terraform variables
        case "$var_name" in
            # AWS/S3 credentials
            AWS_ACCESS_KEY_ID)
                export TF_VAR_aws_access_key="$var_value"
                ;;
            AWS_SECRET_ACCESS_KEY)
                export TF_VAR_aws_secret_key="$var_value"
                ;;
            
            # MinIO configuration
            S3_ENDPOINT_URL)
                export TF_VAR_minio_endpoint="$var_value"
                ;;
            S3_BUCKET_NAME)
                export TF_VAR_minio_bucket="$var_value"
                ;;
            
            # Model configuration
            MODEL_REASONING)
                export TF_VAR_model_reasoning="$var_value"
                ;;
            MODEL_FAST)
                export TF_VAR_model_fast="$var_value"
                ;;
            MODEL_CONSENSUS)
                export TF_VAR_model_consensus="$var_value"
                ;;
            
            # vLLM configuration
            VLLM_REASONING_API_BASE)
                export TF_VAR_vllm_reasoning_url="$var_value"
                ;;
            VLLM_FAST_API_BASE)
                export TF_VAR_vllm_fast_url="$var_value"
                ;;
            VLLM_GATEWAY_URL)
                export TF_VAR_vllm_gateway_url="$var_value"
                ;;
            
            # Langfuse configuration
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
            
            # Container registry
            REGISTRY_URL)
                export TF_VAR_registry_url="$var_value"
                ;;
            
            # Hugging Face
            HUGGING_FACE_HUB_TOKEN)
                export TF_VAR_hf_token="$var_value"
                ;;
            
            # Kubernetes configuration
            K8S_CLUSTER_NAME)
                export TF_VAR_cluster_name="$var_value"
                ;;
            K8S_NAMESPACE)
                export TF_VAR_namespace="$var_value"
                ;;
            
            # Environment
            ENVIRONMENT)
                export TF_VAR_environment="$var_value"
                ;;
            
            # Governance
            GOVERNANCE_SALT)
                export TF_VAR_governance_salt="$var_value"
                ;;
            CAGE_ROUTING_SEAL_SECRET)
                export TF_VAR_routing_seal_secret="$var_value"
                ;;
            
            # Storage backend
            STORAGE_BACKEND)
                export TF_VAR_storage_backend="$var_value"
                ;;
            COLD_TIER_BUCKET)
                export TF_VAR_cold_tier_bucket="$var_value"
                ;;
            
            # OPA
            OPA_URL)
                export TF_VAR_opa_url="$var_value"
                ;;
            
            # Redis
            REDIS_URL)
                export TF_VAR_redis_url="$var_value"
                ;;
        esac
    fi
done < "$PROJECT_ROOT/$ENV_FILE"

echo "✅ Environment variables loaded successfully"
echo ""
echo "📋 Key variables set:"
echo "   ENVIRONMENT=${ENVIRONMENT:-<not set>}"
echo "   K8S_NAMESPACE=${K8S_NAMESPACE:-<not set>}"
echo "   REGISTRY_URL=${REGISTRY_URL:-<not set>}"
echo "   STORAGE_BACKEND=${STORAGE_BACKEND:-<not set>}"
echo ""
echo "💡 Usage with Terraform:"
echo "   cd infra/targets/gcp-gke  # or infra/targets/agnostic"
echo "   terraform plan"
echo "   terraform apply"
echo ""
