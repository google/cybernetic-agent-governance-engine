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

# ─── vLLM Service Account (AC-3) ──────────────────────────────────────────────

resource "google_service_account" "vllm" {
  count        = var.enable_vllm_gpu ? 1 : 0
  account_id   = "cage-vllm-${var.environment}"
  display_name = "CAGE vLLM GPU Inference Service Account"
  project      = var.project_id
}

# Grant logging permissions (AU-2)
resource "google_project_iam_member" "vllm_logging" {
  count   = var.enable_vllm_gpu ? 1 : 0
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vllm[0].email}"
}

# Grant Artifact Registry access for model artifacts (if needed)
resource "google_project_iam_member" "vllm_artifact_registry" {
  count   = var.enable_vllm_gpu ? 1 : 0
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.vllm[0].email}"
}

# ─── HuggingFace Token Secret (Optional) ──────────────────────────────────────

resource "google_secret_manager_secret" "huggingface_token" {
  count     = var.enable_vllm_gpu && var.huggingface_token != "" ? 1 : 0
  secret_id = "cage-huggingface-token-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    environment = var.environment
    managed-by  = "terraform"
  }
}

resource "google_secret_manager_secret_version" "huggingface_token" {
  count       = var.enable_vllm_gpu && var.huggingface_token != "" ? 1 : 0
  secret      = google_secret_manager_secret.huggingface_token[0].id
  secret_data = var.huggingface_token
}

resource "google_secret_manager_secret_iam_member" "vllm_hf_token_access" {
  count     = var.enable_vllm_gpu && var.huggingface_token != "" ? 1 : 0
  secret_id = google_secret_manager_secret.huggingface_token[0].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vllm[0].email}"
}

# ─── vLLM Fast Inference Service (L4 GPU) ─────────────────────────────────────

resource "google_cloud_run_v2_service" "vllm_fast" {
  count    = var.enable_vllm_gpu ? 1 : 0
  name     = "cage-vllm-fast-${var.environment}"
  location = var.region
  project  = var.project_id

  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  labels = {
    environment = var.environment
    workload    = "vllm-inference"
    gpu-type    = "nvidia-l4"
    managed-by  = "terraform"
  }

  template {
    service_account       = google_service_account.vllm[0].email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    timeout = "3600s" # 1 hour timeout for long inference sessions

    scaling {
      # CRITICAL: min_instance_count prevents cold starts in production
      # Cold start = 3-5 minutes (model download + VRAM load)
      # Trade-off: Standing cost ~$200-300/month vs. user-facing latency
      min_instance_count = var.environment == "prod" ? 1 : 0
      max_instance_count = 3
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    # L4 GPU node selector (requires Cloud Run GPU GA)
    node_selector {
      accelerator = "nvidia-l4"
    }

    containers {
      name  = "vllm-inference"
      image = var.vllm_fast_image != "" ? var.vllm_fast_image : "vllm/vllm-openai:v0.5.4"

      ports {
        name           = "http1"
        container_port = 8000
      }

      resources {
        limits = {
          cpu              = "8"
          memory           = "32Gi"
          "nvidia.com/gpu" = "1"
        }
        startup_cpu_boost = true # Accelerate cold start
      }

      env {
        name  = "MODEL_NAME"
        value = var.vllm_fast_model
      }

      env {
        name  = "VLLM_LOGGING_LEVEL"
        value = "INFO"
      }

      # HuggingFace token (if needed for gated models)
      dynamic "env" {
        for_each = var.huggingface_token != "" ? [1] : []
        content {
          name = "HF_TOKEN"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.huggingface_token[0].secret_id
              version = "latest"
            }
          }
        }
      }

      args = [
        "--model", var.vllm_fast_model,
        "--host", "0.0.0.0",
        "--port", "8000",
        "--gpu-memory-utilization", "0.90",
        "--max-model-len", "8192",
        "--enable-auto-tool-choice",
        "--tool-call-parser", "hermes",
        "--trust-remote-code"
      ]

      startup_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        initial_delay_seconds = 60 # Allow time for model download
        period_seconds        = 10
        timeout_seconds       = 5
        failure_threshold     = 60 # 10 minutes max startup time
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        period_seconds    = 30
        timeout_seconds   = 5
        failure_threshold = 3
      }
    }
  }

  depends_on = [google_compute_subnetwork.subnet]
}

# ─── vLLM Reasoning Service (DeepSeek-R1) ─────────────────────────────────────

resource "google_cloud_run_v2_service" "vllm_reasoning" {
  count    = var.enable_vllm_gpu ? 1 : 0
  name     = "cage-vllm-reasoning-${var.environment}"
  location = var.region
  project  = var.project_id

  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  labels = {
    environment = var.environment
    workload    = "vllm-reasoning"
    gpu-type    = "nvidia-l4"
    managed-by  = "terraform"
  }

  template {
    service_account       = google_service_account.vllm[0].email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    timeout = "3600s"

    scaling {
      min_instance_count = var.environment == "prod" ? 1 : 0
      max_instance_count = 2 # Lower max for reasoning (longer sessions)
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    node_selector {
      accelerator = "nvidia-l4"
    }

    containers {
      name  = "vllm-reasoning"
      image = var.vllm_reasoning_image != "" ? var.vllm_reasoning_image : "vllm/vllm-openai:v0.5.4"

      ports {
        name           = "http1"
        container_port = 8000
      }

      resources {
        limits = {
          cpu              = "8"
          memory           = "32Gi"
          "nvidia.com/gpu" = "1"
        }
        startup_cpu_boost = true
      }

      env {
        name  = "MODEL_NAME"
        value = var.vllm_reasoning_model
      }

      env {
        name  = "VLLM_LOGGING_LEVEL"
        value = "INFO"
      }

      dynamic "env" {
        for_each = var.huggingface_token != "" ? [1] : []
        content {
          name = "HF_TOKEN"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.huggingface_token[0].secret_id
              version = "latest"
            }
          }
        }
      }

      args = [
        "--model", var.vllm_reasoning_model,
        "--host", "0.0.0.0",
        "--port", "8000",
        "--gpu-memory-utilization", "0.90",
        "--max-model-len", "32768", # Longer context for reasoning
        "--enable-auto-tool-choice",
        "--tool-call-parser", "hermes",
        "--trust-remote-code"
      ]

      startup_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        initial_delay_seconds = 90 # 14B model takes longer
        period_seconds        = 10
        timeout_seconds       = 5
        failure_threshold     = 60
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        period_seconds    = 30
        timeout_seconds   = 5
        failure_threshold = 3
      }
    }
  }

  depends_on = [google_compute_subnetwork.subnet]
}
