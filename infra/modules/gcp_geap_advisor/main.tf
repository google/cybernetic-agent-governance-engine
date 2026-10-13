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

# ============================================================================
# GCP GEAP Agent Runtime (Vertex AI Agent Engine) — Governed Financial Advisor
# ============================================================================
# Deploys the Governed Financial Advisor orchestration layer onto Google Cloud
# GEAP Agent Runtime (Vertex AI ReasoningEngine) for GCP deployments only, while
# the CAGE Hybrid Gateway, OPA, vLLM GPU pools, Reconciliation Worker, and
# Compliance Bridge remain on GKE.
#
# Security & Compliance Invariants:
#   - POAM-2026-079: Zero signing authority. No KMS key, routing secret, or
#     governance salt is ever injected into the GEAP runtime environment.
#   - POAM-2026-080: GEAP Agent Identity (ID-2) principal is exported so the
#     GKE Hybrid Gateway can enforce two-layer caller authentication (Linkerd
#     mTLS proxy identity + kid-verified GEAP ID-2 OIDC JWT).
#   - SC-7: Direct VPC Egress (`ALL_TRAFFIC`) routes all outbound traffic
#     through the GKE VPC (`cage-vpc`) to reach internal Gateway, vLLM, and
#     Memorystore App endpoints without public internet exposure.
#   - DEP-10: Regional data residency precondition enforces deployment only in
#     approved sovereign regions (`us-central1`, `europe-west1`, `asia-southeast1`).
# ============================================================================

locals {
  approved_sovereign_regions = toset([
    "us-central1",
    "europe-west1",
    "asia-southeast1",
  ])

  # Official GEAP reserved environment variables that must NEVER be set by user
  # deployment configs (scale/runtime/deploy-an-agent#environment-variables).
  geap_reserved_env_vars = toset([
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "PORT",
    "K_SERVICE",
    "K_REVISION",
    "K_CONFIGURATION",
    "GOOGLE_APPLICATION_CREDENTIALS",
  ])

  geap_agent_principal = "principal://agents.global.org-${var.organization_id}/${var.agent_id}"

  runtime_env_vars = {
    CAGE_ADVISOR_RUNTIME       = "geap"
    CAGE_ENV                   = var.cage_env
    ENABLE_LOGGING             = var.enable_logging
    ENABLE_TRACING             = "true"
    LANGSMITH_TRACING          = "false"
    LANGCHAIN_TRACING_V2       = "false"
    GATEWAY_URL                = var.gateway_url
    OPA_URL                    = var.opa_url
    VLLM_BASE_URL              = var.vllm_base_url
    VLLM_FAST_API_BASE         = var.vllm_fast_api_base
    VLLM_REASONING_API_BASE    = var.vllm_reasoning_api_base
    MODEL_FAST                 = var.model_fast
    MODEL_REASONING            = var.model_reasoning
    MODEL_CONSENSUS            = var.model_consensus
    REDIS_HOST                 = var.redis_host
    REDIS_PORT                 = var.redis_port
    REDIS_URL                  = "redis://${var.redis_host}:${var.redis_port}"
    LANGFUSE_HOST              = var.langfuse_host
    OTEL_EXPORTER_OTLP_HEADERS = var.otel_exporter_otlp_headers
  }

  class_methods = [
    {
      name        = "query"
      api_mode    = ""
      description = "Synchronous governed financial advisor query."
    },
    {
      name        = "async_query"
      api_mode    = "async"
      description = "Asynchronous governed financial advisor query."
    },
    {
      name        = "stream_query"
      api_mode    = "stream"
      description = "Synchronous streaming governed financial advisor query."
    },
    {
      name        = "async_stream_query"
      api_mode    = "async_stream"
      description = "Asynchronous streaming governed financial advisor query."
    },
    {
      name        = "resume_approval"
      api_mode    = "async"
      description = "Resume a paused HITL approval graph checkpoint on GEAP Agent Runtime."
    },
  ]
}

resource "terraform_data" "geap_reasoning_engine" {
  triggers_replace = [
    var.project_id,
    var.region,
    var.agent_id,
    var.image,
    var.vpc_network,
    var.vpc_subnetwork,
    var.kms_key_name,
    sha256(jsonencode(local.runtime_env_vars)),
  ]

  input = {
    project_id            = var.project_id
    region                = var.region
    agent_id              = var.agent_id
    agent_framework       = "langgraph"
    identity_type         = "AGENT_IDENTITY"
    entrypoint_module     = "src.governed_financial_advisor.geap_app"
    entrypoint_object     = "GovernedFinancialAdvisorGeapApp"
    image                 = var.image
    geap_agent_principal  = local.geap_agent_principal
    vpc_egress_setting    = "ALL_TRAFFIC"
    vpc_network           = var.vpc_network
    vpc_subnetwork        = var.vpc_subnetwork
    encryption_kms_key    = var.kms_key_name
    encryption_spec = {
      kms_key_name = var.kms_key_name
    }
    psc_interface_config = {
      network_attachment  = var.psc_network_attachment
      dns_peering_configs = var.dns_peering_configs
    }
    min_instances         = var.min_instances
    max_instances         = var.max_instances
    resource_limits = {
      cpu    = var.cpu_limit
      memory = var.memory_limit
    }
    container_concurrency  = var.container_concurrency
    class_methods          = local.class_methods
    memory_bank_guard_mode = "STRICT"
    env                    = local.runtime_env_vars
  }

  provisioner "local-exec" {
    working_dir = "${path.module}/../../.."
    command     = <<-EOT
      uv run python scripts/deploy_geap_runtime.py \
        --project-id "${self.input.project_id}" \
        --region "${self.input.region}" \
        --agent-id "${self.input.agent_id}" \
        --entrypoint-module "${self.input.entrypoint_module}" \
        --entrypoint-object "${self.input.entrypoint_object}" \
        --cpu-limit "${self.input.resource_limits.cpu}" \
        --memory-limit "${self.input.resource_limits.memory}" \
        --min-instances "${self.input.min_instances}" \
        --max-instances "${self.input.max_instances}" \
        --container-concurrency "${self.input.container_concurrency}" \
        --env-json "$GEAP_ENV_JSON"
    EOT
    environment = {
      GEAP_ENV_JSON = jsonencode(self.input.env)
    }
  }

  provisioner "local-exec" {
    when        = destroy
    working_dir = "${path.module}/../../.."
    command     = <<-EOT
      uv run python scripts/deploy_geap_runtime.py \
        --project-id "${self.output.project_id}" \
        --region "${self.output.region}" \
        --agent-id "${self.output.agent_id}" \
        --delete
    EOT
  }

  lifecycle {
    precondition {
      condition     = contains(local.approved_sovereign_regions, var.region)
      error_message = "DEP-10 Violation: GEAP Agent Runtime region '${var.region}' is not in the approved sovereign region set (us-central1, europe-west1, asia-southeast1)."
    }

    precondition {
      condition     = length(setintersection(keys(local.runtime_env_vars), local.geap_reserved_env_vars)) == 0
      error_message = "GEAP Runtime Contract Violation: runtime_env_vars must not set reserved GEAP environment variables (GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_QUOTA_PROJECT, GOOGLE_CLOUD_LOCATION, PORT, K_SERVICE, K_REVISION, K_CONFIGURATION, GOOGLE_APPLICATION_CREDENTIALS)."
    }
  }
}


