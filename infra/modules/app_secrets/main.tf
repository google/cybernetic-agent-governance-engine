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

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

# DEP-11: Derive AWS_REGION from cage_deployment_region.
# Previously hardcoded to "us-east-1" for all deployments. For EU_ECB deployments,
# any S3-compatible client reading this secret would route to us-east-1, violating
# GDPR Art. 44. For APAC_MAS, it would violate MAS TRM §4.2.
# R-3, R-4: data residency must be enforced at the infrastructure layer.
locals {
  # Map CAGE_DEPLOYMENT_REGION to the appropriate AWS/S3-compatible region.
  # EU_ECB → eu-west-1 (Ireland, EEA) for S3-compatible clients
  # APAC_MAS → ap-southeast-1 (Singapore) for S3-compatible clients
  # US_FED → us-east-1 (US East) for S3-compatible clients
  aws_region_for_jurisdiction = {
    "US_FED"   = "us-east-1"
    "EU_ECB"   = "eu-west-1"
    "APAC_MAS" = "ap-southeast-1"
  }
  resolved_aws_region = lookup(local.aws_region_for_jurisdiction, var.cage_deployment_region, "us-east-1")
}

resource "kubernetes_secret" "advisor_secrets" {
  metadata {
    name      = "advisor-secrets"
    namespace = var.namespace
  }

  # Least-privilege secret for the untrusted governed-financial-advisor plane
  # (POAM-2026-079). Never include GOVERNANCE_SALT, ClickHouse admin credentials,
  # or compliance-bridge internal tokens here.
  data = {
    "SALT"                       = var.salt
    "ALPHAVANTAGE_API_KEY"       = var.alphavantage_api_key
    "OPENAI_API_KEY"             = var.openai_api_key
    "LANGFUSE_PUBLIC_KEY"        = var.langfuse_public_key
    "LANGFUSE_SECRET_KEY"        = var.langfuse_secret_key
    "LANGFUSE_HOST"              = var.langfuse_host
    "CAGE_API_KEY"               = var.cage_api_key
    "CAGE_INTERNAL_TOKEN"        = var.cage_internal_token
    "OTEL_EXPORTER_OTLP_HEADERS" = var.otel_exporter_otlp_headers
    "LANGFUSE_BASIC_AUTH_B64"    = var.otel_exporter_otlp_headers
    "REDIS_PASSWORD"             = var.redis_password
  }
}

resource "kubernetes_secret" "gateway_secrets" {
  metadata {
    name      = "gateway-secrets"
    namespace = var.namespace
  }

  data = {
    "GOVERNANCE_SALT"         = var.governance_salt
    "EVIDENCE_STREAM_ENABLED" = "true"
  }
}

resource "kubernetes_secret" "compliance_bridge_secrets" {
  metadata {
    name      = "compliance-bridge-secrets"
    namespace = var.namespace
  }

  data = {
    "CAGE_INTERNAL_TOKEN"              = var.cage_internal_token
    "COMPLIANCE_BRIDGE_INTERNAL_TOKEN" = var.cage_internal_token
    "EVIDENCE_STREAM_ENABLED"          = "true"
  }
}

resource "kubernetes_secret" "compliance_secrets" {
  metadata {
    name      = "langfuse-compliance-secrets"
    namespace = var.namespace
  }

  data = {
    "LANGFUSE_COMPLIANCE_PUBLIC_KEY" = var.langfuse_compliance_public_key
    "LANGFUSE_COMPLIANCE_SECRET_KEY" = var.langfuse_compliance_secret_key
    "public-key"                     = var.langfuse_compliance_public_key
    "secret-key"                     = var.langfuse_compliance_secret_key
    "LANGFUSE_HOST"                  = var.langfuse_host
  }
}

resource "kubernetes_secret" "oscal_artifacts" {
  metadata {
    name      = "oscal-artifact-secrets"
    namespace = var.namespace
  }

  data = {
    "hmac-access-key" = var.aws_access_key_id
    "hmac-secret-key" = var.aws_secret_access_key
    "bucket-name"     = var.s3_bucket_name
  }
}



resource "kubernetes_secret" "gcs_credentials" {
  metadata {
    name      = "gcs-credentials-secret"
    namespace = var.namespace
  }

  data = {
    "AWS_ACCESS_KEY_ID"     = var.aws_access_key_id
    "AWS_SECRET_ACCESS_KEY" = var.aws_secret_access_key
    # DEP-11: AWS_REGION is now derived from cage_deployment_region via locals.
    # Previously hardcoded to "us-east-1", which caused S3-compatible clients in
    # EU_ECB and APAC_MAS deployments to route to the wrong region (GDPR Art. 44 /
    # MAS TRM §4.2 violation). Now: EU_ECB → eu-west-1, APAC_MAS → ap-southeast-1,
    # US_FED → us-east-1.
    "AWS_REGION"       = local.resolved_aws_region
    "AWS_ENDPOINT_URL" = ""
  }
}


resource "kubernetes_secret" "compliance_alerts" {
  metadata {
    name      = "compliance-alert-secrets"
    namespace = var.namespace
  }

  data = {
    "webhook-url" = ""
  }
}

resource "kubernetes_secret" "compliance_alert_channel" {
  metadata {
    name      = "compliance-alert-channel"
    namespace = var.namespace
  }

  data = {
    "channel" = "console"
  }
}

resource "kubernetes_config_map" "advisor_config" {
  metadata {
    name      = "advisor-config"
    namespace = var.namespace
  }

  data = {
    "MODEL_FAST"           = var.model_fast
    "MODEL_REASONING"      = var.model_reasoning
    "MODEL_CONSENSUS"      = var.model_reasoning
    "MODEL_FAST_PATH"      = "s3://${var.s3_bucket_name}/models/${var.model_fast}"
    "MODEL_REASONING_PATH" = "s3://${var.s3_bucket_name}/models/${var.model_reasoning}"
  }
}

resource "kubernetes_secret" "opa_configuration" {
  metadata {
    name      = "opa-configuration"
    namespace = var.namespace
  }

  data = {
    "opa_config.yaml" = <<-EOT
services:
  default_service:
    url: \${var.opa_url}
EOT
  }
}
