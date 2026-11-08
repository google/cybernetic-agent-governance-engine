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

variable "namespace" {
  description = "Kubernetes namespace"
  type        = string
}

variable "image" {
  description = "Container image for the gateway"
  type        = string
}

variable "opa_image" {
  description = "Digest-pinned OPA static container image for the in-pod UDS sidecar (F-19, D-195-3)"
  type        = string

  validation {
    condition = (
      !can(regex(":latest(@|$)", var.opa_image)) &&
      can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.opa_image))
    )
    error_message = "opa_image must be pinned by @sha256:<64-hex> digest and must not use :latest."
  }
}

variable "replicas" {
  description = "Number of pod replicas"
  type        = number
  default     = 1
}

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "enable_logging" {
  type    = string
  default = "true"
}

variable "otel_python_excluded_urls" {
  type    = string
  default = "healthz,readiness,liveness,metrics,huggingface.co/api/resolve"
}

variable "redis_host" {
  type = string
}

variable "redis_port" {
  type    = string
  default = "6379"
}

variable "redis_password" {
  type      = string
  default   = ""
  sensitive = true
}

variable "cage_inference_backend" {
  description = "CAGE_INFERENCE_BACKEND for the gateway: \"none\", \"external\" or \"vllm\". Targets may narrow this; gcp-gke refuses \"external\"."
  type        = string

  validation {
    condition     = contains(["none", "external", "vllm"], var.cage_inference_backend)
    error_message = "cage_inference_backend must be \"none\", \"external\" or \"vllm\"."
  }
}

variable "vllm_base_url" {
  type = string
}

variable "vllm_api_key" {
  description = "VLLM_API_KEY as a plain env value: a placeholder for in-cluster vLLM, which runs without --api-key, never a credential. The gateway's startup check requires it whenever a backend is set. A real key belongs in a Kubernetes Secret."
  type        = string
  default     = ""
}

variable "vllm_gateway_url" {
  type    = string
  default = ""
}

variable "vllm_reasoning_api_base" {
  type = string
}

variable "vllm_fast_api_base" {
  type = string
}

variable "guardrails_model_name" {
  type = string
}

variable "cage_env" {
  description = "Runtime environment for the gateway (development, staging, production)"
  type        = string
  default     = "production"
}

variable "opa_url" {
  description = "OPA sidecar Unix-socket URL (http+unix://<urlencoded-socket-path>; D-195-3)"
  type        = string
  default     = "http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock"

  validation {
    condition     = startswith(var.opa_url, "http+unix://")
    error_message = "opa_url must use an in-pod Unix domain socket (http+unix://...); network TCP OPA endpoints are retired (D-195-3)."
  }
}

variable "opa_policies_config_map_name" {
  description = "Read-only domain Rego policies ConfigMap mounted into the OPA sidecar"
  type        = string
  default     = "opa-policies"
}

variable "opa_system_authz_config_map_name" {
  description = "Read-only system.authz ConfigMap locking the OPA policy/data store at runtime (R-15)"
  type        = string
  default     = "opa-system-authz"
}

variable "opa_config_config_map_name" {
  description = "Read-only OPA runtime configuration ConfigMap (decision_logs.console = true, F-102)"
  type        = string
  default     = "opa-config"
}

variable "opa_bundle_sha256" {
  description = "SHA-256 digest of OPA policy/authz/config ConfigMaps to trigger pod rollout on policy updates"
  type        = string
  default     = ""
}

variable "opa_policy_files" {
  description = "Map of domain Rego policy filenames mounted into the OPA sidecar ConfigMap (POAM-2026-198)"
  type        = map(string)
  default     = {}
}

variable "opa_cpu_request" {
  description = "CPU request for the OPA UDS sidecar container"
  type        = string
  default     = "100m"
}

variable "opa_cpu_limit" {
  description = "CPU limit for the OPA UDS sidecar container"
  type        = string
  default     = "500m"
}

variable "opa_memory_request" {
  description = "Memory request for the OPA UDS sidecar container"
  type        = string
  default     = "128Mi"
}

variable "opa_memory_limit" {
  description = "Memory limit for the OPA UDS sidecar container"
  type        = string
  default     = "256Mi"
}

variable "governance_salt" {
  description = "Salt value for governance HMAC operations"
  type        = string
  sensitive   = true
}

variable "langfuse_host" {
  description = "Langfuse host URL (e.g. http://langfuse-web.<namespace>.svc.cluster.local:3000)"
  type        = string
  default     = ""
}

variable "otel_exporter_otlp_headers" {
  description = "HTTP Basic Auth header for Langfuse OTLP ingestion (Authorization=Basic <b64>)"
  type        = string
  default     = ""
  sensitive   = true
}

# POAM-2026-080: callers are authenticated by Linkerd mTLS workload identity,
# not by a shared HMAC secret. The gateway refuses every non-open path unless
# l5d-client-id is one of these identities.
variable "trusted_client_identities" {
  description = "Linkerd workload identities (l5d-client-id format: <sa>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>) allowed to call the gateway's gated routes. Rendered into CAGE_TRUSTED_CLIENT_IDENTITIES and the mesh AuthorizationPolicy."
  type        = list(string)

  validation {
    condition = length(var.trusted_client_identities) > 0 && alltrue([
      for id in var.trusted_client_identities :
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.serviceaccount\\.identity\\.linkerd\\.[a-z0-9]([-a-z0-9.]*[a-z0-9])?$", id))
    ])
    error_message = "trusted_client_identities must be a non-empty list of Linkerd identities (<sa>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>), not spiffe:// URIs."
  }
}

variable "enable_mesh_policy" {
  description = "Install the gateway's Linkerd Server/HTTPRoute/AuthorizationPolicy set. Requires the Linkerd CRDs (infra/modules/service_mesh)."
  type        = bool
  default     = true
}

variable "reconciliation_provider" {
  description = "RECONCILIATION_PROVIDER label for the startup posture check (must not be \"stub\" in production). The reconciler always runs the simulated Tier 2 provider."
  type        = string
  default     = "simulated"
}

variable "kms_governance_key" {
  description = "Cloud KMS governance key version resource name"
  type        = string
  default     = ""
}

variable "cage_kms_provider" {
  description = "KMS provider implementation (gcp, aws, stub)"
  type        = string
  default     = "gcp"
}

variable "service_account_name" {
  description = "Kubernetes ServiceAccount the pods run as. Must be this workload's own KSA, bound 1:1 to its own GSA (POAM-2026-079). No default: a missing identity fails the plan."
  type        = string

  validation {
    condition     = var.service_account_name != "" && var.service_account_name != "financial-advisor-sa"
    error_message = "service_account_name must name the workload's own KSA; the shared financial-advisor-sa is retired (POAM-2026-079)."
  }
}

variable "reconciler_kms_key" {
  description = "Cloud KMS key version of the reconciler-snapshot key (RECONCILER_KMS_KEY). The governor trusts ground-truth snapshots only from this key (G8); the startup posture check refuses an unset value or one equal to KMS_GOVERNANCE_KEY."
  type        = string
}

# ─── Track 6b Posture & Memorystore Invariants (§1.2, §2.1) ─────────────────

variable "cbf_strict_mode" {
  description = "CAGE_CBF_STRICT_MODE: false in dev, true in staging/prod (§1.2)"
  type        = bool
  default     = null
}

variable "strict_replication" {
  description = "CAGE_STRICT_REPLICATION: false in dev, true in staging/prod (§1.2)"
  type        = bool
  default     = null
}

variable "redis_synchronous_replication" {
  description = "CAGE_REDIS_SYNCHRONOUS_REPLICATION: true across all environments (§1.2)"
  type        = bool
  default     = true
}

variable "redis_wait_replicas" {
  description = "CAGE_REDIS_WAIT_REPLICAS: 0 in dev (no replica), 1 in staging/prod (§1.2)"
  type        = number
  default     = null
}

variable "redis_wait_timeout_ms" {
  description = "CAGE_REDIS_WAIT_TIMEOUT_MS: 100 in staging/prod (§1.2)"
  type        = number
  default     = 100
}

variable "reconciliation_replay_defense" {
  description = "CAGE_RECONCILIATION_REPLAY_DEFENSE: true across all environments (§1.2)"
  type        = bool
  default     = true
}

variable "governance_redis_replica_count" {
  description = "Replica count of the governance Memorystore instance, used for the §1.2 wait-replica invariant check"
  type        = number
  default     = 0
}

variable "enable_redis_tls" {
  description = "Enable TLS for Redis connections (REDIS_TLS)"
  type        = bool
  default     = false
}

variable "redis_ca_pem" {
  description = "PEM-encoded CA certificate bundle for Redis TLS server certificate pinning. When non-empty, mounted into the pod via a module-owned ConfigMap at /etc/cage/tls/redis/ca.pem and exported as REDIS_CA_CERT_PATH (public trust material, not a secret)."
  type        = string
  default     = ""
}

variable "redis_auth_mode" {
  description = "Redis authentication mode ('iam', 'password', 'none')"
  type        = string
  default     = ""
}

variable "network_policy_hash" {
  description = "SHA-256 digest of active NetworkPolicy/FQDNNetworkPolicy specs; changing this triggers a pod rollout so pre-change connections do not survive (§5.3, §7)"
  type        = string
  default     = ""
}

variable "cage_domain" {
  description = "CAGE domain configuration (e.g. 'finance')"
  type        = string
  default     = "finance"
}

# ─── Evidence stream producer (custody lives in the compliance bridge) ───────
# The gateway only appends unsigned, hash-chained records to a Redis Stream on
# the governance Memorystore instance. The compliance bridge's EvidenceCustodian
# reads the same stream, so URL, db and key are passed explicitly to BOTH
# modules from one set of locals in the target and can never drift.

variable "evidence_stream_redis_url" {
  description = "Redis URL of the governance Memorystore instance that holds the evidence stream (EVIDENCE_STREAM_REDIS_URL). Must be the same value passed to the compliance_bridge module."
  type        = string

  validation {
    condition     = can(regex("^rediss?://", var.evidence_stream_redis_url))
    error_message = "evidence_stream_redis_url must be a redis:// or rediss:// URL."
  }
}

variable "evidence_stream_redis_db" {
  description = "Redis logical database for the evidence stream (EVIDENCE_STREAM_REDIS_DB). Must match the compliance_bridge module."
  type        = number
}

variable "evidence_stream_key" {
  description = "Redis Stream key for the evidence chain (EVIDENCE_STREAM_KEY). Must match the compliance_bridge module."
  type        = string

  validation {
    condition     = var.evidence_stream_key != ""
    error_message = "evidence_stream_key must not be empty."
  }
}

# Name of the cage-deployment ConfigMap (modules/deployment_config). Passing
# it (rather than hardcoding the name) makes the dependency explicit.
variable "deployment_config_map_name" {
  description = "ConfigMap holding CAGE_DEPLOYMENT_REGION (output of modules/deployment_config)."
  type        = string
}


variable "enable_autoscaling" {
  description = "Enable HorizontalPodAutoscaler (autoscaling/v2) keyed on GMP pod metric prometheus.googleapis.com|cage_event_loop_lag_seconds|gauge when replicas >= 2."
  type        = bool
  default     = false
}

variable "max_replicas" {
  description = "Maximum gateway replicas when enable_autoscaling is true."
  type        = number
  default     = 5
}

variable "autoscaling_target_loop_lag" {
  description = "Target average value for prometheus.googleapis.com|cage_event_loop_lag_seconds|gauge (e.g. '50m' = 50ms)."
  type        = string
  default     = "50m"
}

variable "enable_pod_monitoring" {
  description = "Deploy GKE Managed Prometheus PodMonitoring/gateway-metrics via the local metrics-monitors chart (R-6, F-91, NIST AU-12)."
  type        = bool
  default     = true
}

variable "enable_service_monitor" {
  description = "Deploy Prometheus Operator ServiceMonitor/stera-gateway-monitor alongside PodMonitoring when monitoring.coreos.com/v1 CRDs are installed (R-6, F-91)."
  type        = bool
  default     = false
}

variable "gateway_secret_name" {
  description = "Kubernetes Secret supplying gateway-scoped credentials (GOVERNANCE_SALT, TELEMETRY_PUBLIC_KEY, TELEMETRY_SECRET_KEY, OTEL_EXPORTER_OTLP_HEADERS, REDIS_PASSWORD). Must never be shared with advisor-secrets (F-84, F-92, R-2)."
  type        = string
  default     = "gateway-secrets"
}

variable "telemetry_secret_name" {
  description = "Optional override Kubernetes Secret supplying TELEMETRY_PUBLIC_KEY and TELEMETRY_SECRET_KEY (defaults to gateway_secret_name when empty). Must never be \"advisor-secrets\" in enforcing postures or when causal_tier_enabled = true (F-92)."
  type        = string
  default     = ""
}

variable "gateway_telemetry_public_key" {
  description = "Optional gateway plane TELEMETRY_PUBLIC_KEY value for plan-time collision checks against advisor_telemetry_public_key (F-92)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "advisor_telemetry_public_key" {
  description = "Optional governed-agent LANGFUSE_PUBLIC_KEY / advisor telemetry public key for plan-time collision checks against gateway_telemetry_public_key (F-92)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "causal_tier_enabled" {
  description = "Enable the DoWhy causal gatekeeper tier (CAGE_CAUSAL_TIER_ENABLED). Requires a dedicated plane-only telemetry Secret (telemetry_secret_name != \"advisor-secrets\") and causal_gatekeeper_strict_mode = true (F-92 / R-11)."
  type        = bool
  default     = false
}

variable "causal_gatekeeper_strict_mode" {
  description = "Require trace_id on causal telemetry spans and refuse producer-supplied timestamp ordering (CAUSAL_GATEKEEPER_STRICT_MODE, F-92)."
  type        = bool
  default     = false
}

variable "consensus_critics_enabled" {
  description = "Enable multi-model consensus critics (CAGE_CONSENSUS_CRITICS_ENABLED). Requires an active inference backend and, under enforcing postures, consensus_advisory_only = true (F-53..F-56 / R-11)."
  type        = bool
  default     = false
}

variable "consensus_advisory_only" {
  description = "Run consensus critics in advisory-only escalation mode so critic votes cannot replace human review (CAGE_CONSENSUS_ADVISORY_ONLY, F-56)."
  type        = bool
  default     = false
}
