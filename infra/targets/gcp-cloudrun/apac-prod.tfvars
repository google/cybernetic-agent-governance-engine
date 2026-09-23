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

# ─── APAC Production Environment Configuration (asia-southeast1) ──────────────

environment = "prod"
region      = "asia-southeast1"
zone        = "asia-southeast1-a"

# APAC_MAS compliance profile: MAS TRM §4.2, MAS Notice 655 audit logging
cage_deployment_region = "APAC_MAS"

# ─── High Availability ────────────────────────────────────────────────────────
# Full HA: MAS TRM operational resilience requirements

enable_high_availability = true
enable_nist_compliance   = false # US_FED controls not applicable in APAC

# ─── Database Sizing ──────────────────────────────────────────────────────────
# Production-grade capacity with APAC data residency

postgres_tier      = "db-custom-2-7680"
postgres_disk_size = 50

redis_tier           = "STANDARD_HA"
redis_memory_size_gb = 5

# ─── Cloud Run Scaling ────────────────────────────────────────────────────────
# Always-on instances for MAS operational resilience

gateway_min_instances = 2
gateway_max_instances = 20
gateway_cpu           = "2"
gateway_memory        = "2Gi"

advisor_min_instances = 2
advisor_max_instances = 10
advisor_cpu           = "1"
advisor_memory        = "1Gi"

# ─── Future Phase Toggles ─────────────────────────────────────────────────────
# Reserved for Phase 1b (sidecars)

enable_vllm_gpu        = false
enable_nemo_guardrails = false
