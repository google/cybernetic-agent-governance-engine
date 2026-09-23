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

# ─── Staging Environment Configuration (us-central1) ──────────────────────────

environment = "staging"
region      = "us-central1"
zone        = "us-central1-a"

# US_FED compliance profile for US-based staging
cage_deployment_region = "US_FED"

# ─── High Availability ────────────────────────────────────────────────────────
# Partial HA: security controls enabled, but minimal redundancy for cost control

enable_high_availability = false
enable_nist_compliance   = true

# ─── Database Sizing ──────────────────────────────────────────────────────────
# Increased capacity for staging validation

postgres_tier      = "db-g1-small"
postgres_disk_size = 20

redis_tier           = "BASIC"
redis_memory_size_gb = 2

# ─── Cloud Run Scaling ────────────────────────────────────────────────────────
# Maintain minimum instances for faster response times

gateway_min_instances = 1
gateway_max_instances = 10
gateway_cpu           = "2"
gateway_memory        = "2Gi"

advisor_min_instances = 1
advisor_max_instances = 5
advisor_cpu           = "1"
advisor_memory        = "1Gi"

# ─── Future Phase Toggles ─────────────────────────────────────────────────────
# Reserved for Phase 1b (sidecars)

enable_vllm_gpu        = false
enable_nemo_guardrails = false
