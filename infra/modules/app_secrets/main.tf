terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

resource "kubernetes_secret" "advisor_secrets" {
  metadata {
    name      = "advisor-secrets"
    namespace = var.namespace
  }

  data = {
    "SALT"                     = var.salt
    "ALPHAVANTAGE_API_KEY"     = var.alphavantage_api_key
    "OPENAI_API_KEY"           = var.openai_api_key
    "LANGFUSE_PUBLIC_KEY"      = var.langfuse_public_key
    "LANGFUSE_SECRET_KEY"      = var.langfuse_secret_key
    "LANGFUSE_HOST"            = var.langfuse_host
    "CLICKHOUSE_URL"           = var.clickhouse_url
    "CLICKHOUSE_MIGRATION_URL" = var.clickhouse_migration_url
    "CLICKHOUSE_USER"          = var.clickhouse_user
    "CLICKHOUSE_PASSWORD"      = var.clickhouse_password
    "DATABASE_URL"             = var.database_url
    "NEXTAUTH_SECRET"          = var.nextauth_secret
    "NEXTAUTH_URL"             = var.nextauth_url
    "CAGE_DEPLOYMENT_REGION"   = var.cage_deployment_region
  }
}

resource "kubernetes_secret" "hf_token" {
  metadata {
    name      = "hf-token-secret"
    namespace = var.namespace
  }

  data = {
    "token" = var.hf_token
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
    "AWS_REGION"            = "us-east-1"
    "AWS_ENDPOINT_URL"      = ""
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

resource "kubernetes_secret" "finance_policy_rego" {
  metadata {
    name      = "finance-policy-rego"
    namespace = var.namespace
  }

  data = {
    "finance_policy.rego" = <<-EOT
# Default empty policy created by Terraform
package governance.policy.finance

default allow = true
EOT
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
