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
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

locals {
  is_prod_or_staging            = contains(["prod", "production", "staging"], var.cage_env)
  cbf_strict_mode               = var.cbf_strict_mode != null ? var.cbf_strict_mode : local.is_prod_or_staging
  strict_replication            = var.strict_replication != null ? var.strict_replication : local.is_prod_or_staging
  redis_synchronous_replication = var.redis_synchronous_replication
  redis_wait_replicas           = var.redis_wait_replicas != null ? var.redis_wait_replicas : (local.is_prod_or_staging ? 1 : 0)
  redis_wait_timeout_ms         = var.redis_wait_timeout_ms
  reconciliation_replay_defense = var.reconciliation_replay_defense
}


locals {
  # Keep count/for_each/annotation keys deterministic at plan time when
  # Memorystore's managed_server_ca is (known after apply); the Deployment
  # precondition still enforces trimspace(var.redis_ca_pem) != "" at apply.
  mount_redis_ca = var.enable_redis_tls ? true : (var.redis_ca_pem != "")
}

resource "kubernetes_config_map_v1" "redis_ca" {
  count = local.mount_redis_ca ? 1 : 0

  metadata {
    name      = "gateway-redis-ca"
    namespace = var.namespace
    labels = {
      app = "gateway"
    }
  }

  data = {
    "ca.pem" = var.redis_ca_pem
  }
}

resource "helm_release" "gateway" {
  lifecycle {
    precondition {
      condition = (
        !contains(["staging", "prod", "production"], var.cage_env) ||
        (local.redis_wait_replicas <= var.governance_redis_replica_count)
      )
      error_message = "CAGE Invariant (§1.2): in staging and prod, CAGE_REDIS_WAIT_REPLICAS must be <= the governance instance's replica count."
    }
    precondition {
      condition     = !var.enable_redis_tls || trimspace(var.redis_ca_pem) != ""
      error_message = "CAGE Invariant (SC-8 / POAM-2026-086): when enable_redis_tls=true, redis_ca_pem must be non-empty so the pod mounts /etc/cage/tls/redis/ca.pem and sets REDIS_CA_CERT_PATH."
    }
    precondition {
      condition = (
        (!local.is_prod_or_staging || (
          trimspace(var.gateway_secret_name) != "" &&
          var.gateway_secret_name != "advisor-secrets" &&
          trimspace(local.telemetry_secret_name) != "" &&
          var.telemetry_secret_name != "advisor-secrets" &&
          local.telemetry_secret_name != "advisor-secrets" &&
          (
            trimspace(var.gateway_telemetry_public_key) == "" ||
            trimspace(var.advisor_telemetry_public_key) == "" ||
            var.gateway_telemetry_public_key != var.advisor_telemetry_public_key
          )
        )) &&
        (!var.causal_tier_enabled || (
          trimspace(local.telemetry_secret_name) != "" &&
          var.telemetry_secret_name != "advisor-secrets" &&
          local.telemetry_secret_name != "advisor-secrets" &&
          var.causal_gatekeeper_strict_mode &&
          (
            !local.is_prod_or_staging ||
            trimspace(var.advisor_telemetry_public_key) == "" ||
            (
              trimspace(var.gateway_telemetry_public_key) != "" &&
              var.gateway_telemetry_public_key != var.advisor_telemetry_public_key
            )
          )
        ))
      )
      error_message = "CAGE Invariant (F-84 / F-92 / R-2 / R-11): gateway telemetry credentials must never be shared with advisor-secrets or advisor telemetry keys in enforcing postures, and CAGE_CAUSAL_TIER_ENABLED=true requires a dedicated plane-only telemetry Secret (telemetry_secret_name != \"advisor-secrets\") and CAUSAL_GATEKEEPER_STRICT_MODE=true."
    }
    precondition {
      condition = !var.consensus_critics_enabled || (
        !contains(["none", "stub"], var.cage_inference_backend) &&
        (!local.is_prod_or_staging || var.consensus_advisory_only)
      )
      error_message = "CAGE Invariant (F-53..F-56 / R-11): CAGE_CONSENSUS_CRITICS_ENABLED=true requires an active semantic inference backend (cage_inference_backend not in [\"none\", \"stub\"]) and, under an enforcing posture, consensus_advisory_only=true so model critics cannot replace human review."
    }
    precondition {
      condition     = var.cage_inference_backend != "stub" || !contains(["prod", "production"], lower(trimspace(var.cage_env)))
      error_message = "CAGE Invariant (POAM-2026-191): CAGE_INFERENCE_BACKEND=stub is an opt-in non-production E2E backend and is refused when cage_env is prod or production."
    }
    precondition {
      condition = (
        (trimspace(var.evidence_previous_chain_head_hash) == "" && trimspace(var.evidence_previous_batch_attestation_digest) == "") ||
        (
          can(regex("^[0-9a-f]{64}$", trimspace(var.evidence_previous_chain_head_hash))) &&
          can(regex("^[0-9a-f]{64}$", trimspace(var.evidence_previous_batch_attestation_digest)))
        )
      )
      error_message = "CAGE Invariant (F-94 / R-10): evidence_previous_chain_head_hash and evidence_previous_batch_attestation_digest must either both be empty or both be lowercase 64-character hex SHA-256 digests."
    }
  }

  name      = "gateway-deployment"
  chart     = "${path.module}/deployment"
  namespace = var.namespace
  wait      = false

  values = [yamlencode({
    manifest = local.gateway_deployment_manifest
  })]

  depends_on = [kubernetes_config_map_v1.redis_ca]
}

locals {
  opa_check_command = [
    "/opa",
    "check",
    "--ignore=..*",
    "/etc/opa/authz/system_authz.rego",
    "/policies",
  ]

  # OPA Unix-socket native sidecar (F-19, F-102, R-15, D-195-3):
  # Declared in initContainers with restartPolicy = "Always" (Kubernetes 1.29+
  # native sidecar; rendered via a local Helm chart because hashicorp/kubernetes
  # 2.x omits restart_policy on init_container). Kubelet pulls and starts opa
  # and waits for its startupProbe before starting gateway, and keeps opa
  # running across gateway's preStop drain window on termination.
  opa_native_sidecar_container = {
    name            = "opa"
    image           = var.opa_image
    imagePullPolicy = "Always"
    restartPolicy   = "Always"
    args = [
      "run",
      "--server",
      "--addr=unix:///var/run/opa/opa.sock",
      "--authorization=basic",
      "--config-file=/config/opa_config.yaml",
      "--shutdown-wait-period=15",
      "--shutdown-grace-period=15",
      "--ignore=..*",
      "/etc/opa/authz/system_authz.rego",
      "/policies",
    ]
    securityContext = {
      allowPrivilegeEscalation = false
      readOnlyRootFilesystem   = true
      runAsNonRoot             = true
      runAsUser                = 1000
      runAsGroup               = 1000
      seccompProfile = {
        type = "RuntimeDefault"
      }
      capabilities = {
        drop = ["ALL"]
      }
    }
    lifecycle = {
      preStop = {
        exec = {
          command = local.opa_check_command
        }
      }
    }
    startupProbe = {
      exec = {
        command = local.opa_check_command
      }
      periodSeconds    = 1
      failureThreshold = 30
      timeoutSeconds   = 5
    }
    readinessProbe = {
      exec = {
        command = local.opa_check_command
      }
      initialDelaySeconds = 2
      periodSeconds       = 10
      failureThreshold    = 3
      timeoutSeconds      = 5
    }
    livenessProbe = {
      exec = {
        command = local.opa_check_command
      }
      initialDelaySeconds = 5
      periodSeconds       = 20
      failureThreshold    = 3
      timeoutSeconds      = 5
    }
    volumeMounts = [
      {
        name      = "opa-socket"
        mountPath = "/var/run/opa"
        readOnly  = false
      },
      {
        name      = "opa-policies"
        mountPath = "/policies"
        readOnly  = true
      },
      {
        name      = "opa-system-authz"
        mountPath = "/etc/opa/authz"
        readOnly  = true
      },
      {
        name      = "opa-config"
        mountPath = "/config"
        readOnly  = true
      },
    ]
    resources = {
      requests = {
        cpu    = var.opa_cpu_request
        memory = var.opa_memory_request
      }
      limits = {
        cpu    = var.opa_cpu_limit
        memory = var.opa_memory_limit
      }
    }
  }

  gateway_app_container = {
    name            = "gateway"
    image           = var.image
    imagePullPolicy = "Always"
    securityContext = {
      allowPrivilegeEscalation = false
      runAsNonRoot             = true
      runAsUser                = 1000
      seccompProfile = {
        type = "RuntimeDefault"
      }
      capabilities = {
        drop = ["ALL"]
      }
    }
    ports = [
      {
        containerPort = 8080
        name          = "http"
        protocol      = "TCP"
      },
      {
        containerPort = 50051
        name          = "grpc"
        protocol      = "TCP"
      },
      {
        containerPort = 9090
        name          = "metrics"
        protocol      = "TCP"
      },
    ]
    # Secrets from dedicated gateway Secret (R-2, F-84, F-92) — never advisor-secrets.
    envFrom = [
      {
        secretRef = {
          name = var.gateway_secret_name
        }
      },
    ]
    env = concat(
      [
        # Deployment jurisdiction: single source is the cage-deployment
        # ConfigMap (modules/deployment_config). optional = false: a pod
        # never starts without a declared region.
        {
          name = "CAGE_DEPLOYMENT_REGION"
          valueFrom = {
            configMapKeyRef = {
              name     = var.deployment_config_map_name
              key      = "CAGE_DEPLOYMENT_REGION"
              optional = false
            }
          }
        },
        {
          name  = "PORT"
          value = "8080"
        },
        {
          name  = "GATEWAY_GRPC_PORT"
          value = "50051"
        },
        {
          name  = "CAGE_METRICS_PORT"
          value = "9090"
        },
        {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        },
        {
          name  = "GOOGLE_CLOUD_LOCATION"
          value = var.region
        },
        {
          name  = "ENABLE_LOGGING"
          value = var.enable_logging
        },
        {
          name  = "USE_MOCK_BROKER"
          value = tostring(var.use_mock_broker)
        },
        {
          name  = "LANGCHAIN_TRACING_V2"
          value = "false"
        },
        {
          name  = "LANGSMITH_TRACING"
          value = "false"
        },
        {
          name  = "OTEL_TRACES_EXPORTER"
          value = "otlp"
        },
        {
          name = "OTEL_EXPORTER_OTLP_ENDPOINT"
          # Langfuse v3 native OTLP ingestion — no separate OTel Collector deployed.
          value = "http://langfuse-web.${var.namespace}.svc.cluster.local:3000/api/public/otel/v1/traces"
        },
        {
          name  = "OTEL_EXPORTER_OTLP_PROTOCOL"
          value = "http/protobuf"
        },
        {
          name = "OTEL_EXPORTER_OTLP_HEADERS"
          valueFrom = {
            secretKeyRef = {
              name     = var.gateway_secret_name
              key      = "OTEL_EXPORTER_OTLP_HEADERS"
              optional = true
            }
          }
        },
        {
          name  = "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY"
          value = "true"
        },
        {
          name  = "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY"
          value = "true"
        },
        {
          name  = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
          value = "true"
        },
        {
          name  = "OTEL_PYTHON_EXCLUDED_URLS"
          value = var.otel_python_excluded_urls
        },
        {
          name  = "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST"
          value = "content-type,accept,user-agent,x-request-id,x-goog-authenticated-user-email"
        },
        {
          name  = "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE"
          value = "content-type,content-length"
        },
        {
          name  = "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS"
          value = ".*session.*,.*token.*,authorization,set-cookie,cookie,x-api-key,proxy-authorization"
        },
        {
          name  = "REDIS_PORT"
          value = var.redis_port
        },
        {
          name  = "REDIS_HOST"
          value = var.redis_host
        },
        {
          name = "REDIS_PASSWORD"
          valueFrom = {
            secretKeyRef = {
              name     = var.gateway_secret_name
              key      = "REDIS_PASSWORD"
              optional = true
            }
          }
        },
        {
          name  = "REDIS_URL"
          value = "redis://${var.redis_host}:${var.redis_port}"
        },
        {
          name  = "CAGE_INFERENCE_BACKEND"
          value = var.cage_inference_backend
        },
        {
          name  = "VLLM_BASE_URL"
          value = var.vllm_base_url
        },
        {
          # Not a credential for in-cluster vLLM, which runs without
          # --api-key; startup requires it whenever a backend is set.
          name  = "VLLM_API_KEY"
          value = var.vllm_api_key
        },
        {
          name  = "VLLM_GATEWAY_URL"
          value = var.vllm_gateway_url
        },
        {
          name  = "VLLM_REASONING_API_BASE"
          value = var.vllm_reasoning_api_base
        },
        {
          name  = "VLLM_FAST_API_BASE"
          value = var.vllm_fast_api_base
        },
        {
          name  = "GUARDRAILS_MODEL_NAME"
          value = var.guardrails_model_name
        },
        {
          name  = "SERVICE_NAME"
          value = "hybrid-gateway"
        },
        # Causal-tier telemetry (CTRL_TEL_003 / F-92). The kernel reads only the
        # vendor-neutral TELEMETRY_* names from the gateway-scoped Secret
        # (isolated from advisor-secrets). Enforcing postures require
        # CAGE_TELEMETRY_PROVIDER to be set explicitly.
        {
          name  = "CAGE_TELEMETRY_PROVIDER"
          value = "remote"
        },
        {
          name  = "TELEMETRY_HOST"
          value = "http://langfuse-web.${var.namespace}.svc.cluster.local:3000"
        },
        {
          name = "TELEMETRY_PUBLIC_KEY"
          valueFrom = {
            secretKeyRef = {
              name     = local.telemetry_secret_name
              key      = "TELEMETRY_PUBLIC_KEY"
              optional = !var.causal_tier_enabled
            }
          }
        },
        {
          name = "TELEMETRY_SECRET_KEY"
          valueFrom = {
            secretKeyRef = {
              name     = local.telemetry_secret_name
              key      = "TELEMETRY_SECRET_KEY"
              optional = !var.causal_tier_enabled
            }
          }
        },
        {
          name  = "CAGE_CAUSAL_TIER_ENABLED"
          value = tostring(var.causal_tier_enabled)
        },
        {
          name  = "CAUSAL_GATEKEEPER_STRICT_MODE"
          value = tostring(var.causal_gatekeeper_strict_mode)
        },
        {
          name  = "CAGE_CONSENSUS_CRITICS_ENABLED"
          value = tostring(var.consensus_critics_enabled)
        },
        {
          name  = "CAGE_CONSENSUS_ADVISORY_ONLY"
          value = tostring(local.consensus_advisory_only)
        },
        {
          name  = "CAGE_DOMAIN"
          value = var.cage_domain
        },
        {
          name  = "CAGE_ENV"
          value = var.cage_env
        },
        {
          name  = "ENVIRONMENT"
          value = var.cage_env
        },
        {
          name  = "OPA_URL"
          value = var.opa_url
        },
        {
          name  = "CAGE_OPA_CONNECT_DEADLINE_SECONDS"
          value = "15"
        },
        # POAM-2026-080: deny-by-default ingress. Every path except the open
        # list requires one of these mesh identities in l5d-client-id.
        {
          name  = "CAGE_TRUSTED_CLIENT_IDENTITIES"
          value = join(",", var.trusted_client_identities)
        },
        {
          name  = "RECONCILIATION_PROVIDER"
          value = var.reconciliation_provider
        },
        {
          name  = "KMS_GOVERNANCE_KEY"
          value = var.kms_governance_key
        },
        {
          name  = "RECONCILER_KMS_KEY"
          value = var.reconciler_kms_key
        },
        {
          name  = "CAGE_KMS_PROVIDER"
          value = var.cage_kms_provider
        },
        # Track 6b Posture & Memorystore Invariants (§1.2, §2.1)
        {
          name  = "CAGE_CBF_STRICT_MODE"
          value = tostring(local.cbf_strict_mode)
        },
        {
          name  = "CAGE_STRICT_REPLICATION"
          value = tostring(local.strict_replication)
        },
        {
          name  = "CAGE_REDIS_SYNCHRONOUS_REPLICATION"
          value = tostring(local.redis_synchronous_replication)
        },
        {
          name  = "CAGE_REDIS_WAIT_REPLICAS"
          value = tostring(local.redis_wait_replicas)
        },
        {
          name  = "CAGE_REDIS_WAIT_TIMEOUT_MS"
          value = tostring(local.redis_wait_timeout_ms)
        },
        {
          name  = "CAGE_RECONCILIATION_REPLAY_DEFENSE"
          value = tostring(local.reconciliation_replay_defense)
        },
        {
          name  = "REDIS_TLS"
          value = tostring(var.enable_redis_tls)
        },
        # Evidence stream producer. The gateway appends unsigned hash-chained
        # records only; custody (chain re-verification, batch signing with
        # EVIDENCE_KMS_KEY, WORM writes) is the compliance bridge's job, so no
        # EVIDENCE_COLD_STORE*, EVIDENCE_KMS_KEY or WORM IAM reaches this pod.
        {
          name  = "EVIDENCE_STREAM_ENABLED"
          value = "true"
        },
        {
          name  = "EVIDENCE_CHAIN_BLOCKING"
          value = "true"
        },
        {
          name  = "EVIDENCE_STREAM_REDIS_URL"
          value = var.evidence_stream_redis_url
        },
        {
          name  = "EVIDENCE_STREAM_REDIS_DB"
          value = tostring(var.evidence_stream_redis_db)
        },
        {
          name  = "EVIDENCE_STREAM_KEY"
          value = var.evidence_stream_key
        },
        {
          name  = "EVIDENCE_PREVIOUS_CHAIN_HEAD_HASH"
          value = var.evidence_previous_chain_head_hash
        },
        {
          name  = "EVIDENCE_PREVIOUS_BATCH_ATTESTATION_DIGEST"
          value = var.evidence_previous_batch_attestation_digest
        },
        # Cap BLAS/OpenMP worker pools to the 2-CPU container limit (2000m).
        {
          name  = "OMP_NUM_THREADS"
          value = "2"
        },
        {
          name  = "OPENBLAS_NUM_THREADS"
          value = "2"
        },
      ],
      local.mount_redis_ca ? [
        {
          name  = "REDIS_CA_CERT_PATH"
          value = "/etc/cage/tls/redis/ca.pem"
        },
      ] : [],
      var.redis_auth_mode != "" ? [
        {
          name  = "REDIS_AUTH_MODE"
          value = var.redis_auth_mode
        },
      ] : [],
    )
    volumeMounts = concat(
      [
        {
          name      = "opa-socket"
          mountPath = "/var/run/opa"
          readOnly  = false
        },
      ],
      local.mount_redis_ca ? [
        {
          name      = "redis-ca"
          mountPath = "/etc/cage/tls/redis"
          readOnly  = true
        },
      ] : [],
    )
    lifecycle = {
      preStop = {
        exec = {
          command = ["/bin/sh", "-c", "sleep 5"]
        }
      }
    }
    startupProbe = {
      httpGet = {
        path = "/health"
        port = 8080
      }
      periodSeconds    = 5
      failureThreshold = 30
      timeoutSeconds   = 5
    }
    livenessProbe = {
      httpGet = {
        path = "/health"
        port = 8080
      }
      initialDelaySeconds = 15
      periodSeconds       = 20
      failureThreshold    = 3
      timeoutSeconds      = 5
    }
    readinessProbe = {
      httpGet = {
        path = "/health"
        port = 8080
      }
      initialDelaySeconds = 10
      periodSeconds       = 10
      failureThreshold    = 3
      timeoutSeconds      = 5
    }
    resources = {
      requests = {
        cpu    = "1000m"
        memory = "2Gi"
      }
      limits = {
        cpu    = "2000m"
        memory = "4Gi"
      }
    }
  }

  gateway_volumes = concat(
    [
      {
        name     = "opa-socket"
        emptyDir = {}
      },
      {
        name = "opa-policies"
        configMap = {
          name        = var.opa_policies_config_map_name
          defaultMode = 292 # 0444 octal
        }
      },
      {
        name = "opa-system-authz"
        configMap = {
          name        = var.opa_system_authz_config_map_name
          defaultMode = 292 # 0444 octal
        }
      },
      {
        name = "opa-config"
        configMap = {
          name        = var.opa_config_config_map_name
          defaultMode = 292 # 0444 octal
        }
      },
    ],
    local.mount_redis_ca ? [
      {
        name = "redis-ca"
        configMap = {
          name = kubernetes_config_map_v1.redis_ca[0].metadata[0].name
        }
      },
    ] : [],
  )

  gateway_deployment_manifest = {
    apiVersion = "apps/v1"
    kind       = "Deployment"
    metadata = {
      name      = "gateway"
      namespace = var.namespace
      labels = {
        app = "gateway"
      }
    }
    spec = {
      replicas             = var.replicas
      revisionHistoryLimit = 3
      selector = {
        matchLabels = {
          app = "gateway"
        }
      }
      template = {
        metadata = {
          labels = {
            app = "gateway"
          }
          annotations = merge(
            {
              "config.linkerd.io/skip-inbound-ports" = "9090"
            },
            var.network_policy_hash != "" ? {
              "cage.io/network-policy-hash" = var.network_policy_hash
            } : {},
            local.mount_redis_ca ? {
              "cage.io/redis-ca-sha256" = sha256(var.redis_ca_pem)
            } : {},
            var.opa_bundle_sha256 != "" ? {
              "cage.io/opa-bundle-sha256" = var.opa_bundle_sha256
            } : {}
          )
        }
        spec = {
          serviceAccountName            = var.service_account_name
          terminationGracePeriodSeconds = 35
          # §3, §7 Pitfalls: Governance-critical gateway pods must NEVER schedule on Spot nodes.
          affinity = {
            nodeAffinity = {
              requiredDuringSchedulingIgnoredDuringExecution = {
                nodeSelectorTerms = [
                  {
                    matchExpressions = [
                      {
                        key      = "cloud.google.com/gke-spot"
                        operator = "NotIn"
                        values   = ["true"]
                      },
                    ]
                  },
                ]
              }
            }
          }
          securityContext = {
            runAsNonRoot = true
            runAsUser    = 1000
            fsGroup      = 1000
            seccompProfile = {
              type = "RuntimeDefault"
            }
          }
          initContainers = [local.opa_native_sidecar_container]
          containers     = [local.gateway_app_container]
          volumes        = local.gateway_volumes
        }
      }
    }
  }
}

resource "kubernetes_service" "gateway" {
  metadata {
    name      = "gateway"
    namespace = var.namespace
    labels = {
      app = "gateway"
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
      name        = "http"
    }

    port {
      port        = 50051
      target_port = 50051
      protocol    = "TCP"
      name        = "grpc"
    }

    port {
      port        = 9090
      target_port = 9090
      protocol    = "TCP"
      name        = "metrics"
    }

    selector = {
      app = "gateway"
    }
  }
}

# ─── PodDisruptionBudget (only when replicas >= 2) ───────────────────────────
resource "kubernetes_pod_disruption_budget_v1" "gateway" {
  count = var.replicas >= 2 ? 1 : 0

  metadata {
    name      = "gateway-pdb"
    namespace = var.namespace
    labels = {
      app = "gateway"
    }
  }

  spec {
    min_available = 1

    selector {
      match_labels = {
        app = "gateway"
      }
    }
  }
}

# ─── Autoscaling on GMP Event-Loop Lag Custom Metric ─────────────────────────
resource "kubernetes_horizontal_pod_autoscaler_v2" "gateway" {
  count = var.enable_autoscaling && var.replicas >= 2 ? 1 : 0

  depends_on = [helm_release.gateway]

  metadata {
    name      = "gateway-hpa"
    namespace = var.namespace
    labels = {
      app = "gateway"
    }
  }

  spec {
    min_replicas = max(2, var.replicas)
    max_replicas = var.max_replicas

    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = local.gateway_deployment_manifest.metadata.name
    }

    metric {
      type = "Pods"
      pods {
        metric {
          name = "prometheus.googleapis.com|cage_event_loop_lag_seconds|gauge"
        }
        target {
          type          = "AverageValue"
          average_value = var.autoscaling_target_loop_lag
        }
      }
    }
  }
}

# ─── Mesh authorization (POAM-2026-080) ──────────────────────────────────────
# Linkerd half of the two-layer ingress check; the gateway's
# WorkloadIdentityMiddleware is the other half. A local chart rather than
# kubernetes_manifest because the policy.linkerd.io CRDs are installed in the
# same apply (infra/modules/service_mesh).
resource "helm_release" "mesh_policy" {
  count = var.enable_mesh_policy ? 1 : 0

  name      = "gateway-mesh-policy"
  chart     = "${path.module}/mesh-policy"
  namespace = var.namespace

  values = [yamlencode({
    trustedIdentities = var.trusted_client_identities
  })]
}

# ─── Prometheus / GMP Metrics Scrape Targets (R-6, F-91, NIST AU-12) ─────────
# Installed via a local Helm chart (same pattern as mesh_policy) so Terraform
# plans cleanly on fresh clusters before GKE installs monitoring.googleapis.com
# CRDs, while keeping PodMonitoring/gateway-metrics (and optional
# ServiceMonitor/stera-gateway-monitor) inside Terraform state across W.
resource "helm_release" "metrics_monitors" {
  count = var.enable_pod_monitoring || var.enable_service_monitor ? 1 : 0

  name      = "gateway-metrics-monitors"
  chart     = "${path.module}/metrics-monitors"
  namespace = var.namespace

  values = [yamlencode({
    podMonitoring = {
      enabled = var.enable_pod_monitoring
    }
    serviceMonitor = {
      enabled = var.enable_service_monitor
    }
  })]

  depends_on = [kubernetes_service.gateway]
}

locals {
  telemetry_secret_name   = trimspace(var.telemetry_secret_name) != "" ? var.telemetry_secret_name : var.gateway_secret_name
  consensus_advisory_only = local.is_prod_or_staging ? true : var.consensus_advisory_only
}
