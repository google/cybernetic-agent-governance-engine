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

# ─── EU Production Environment Configuration (europe-west1) ───────────────────

environment = "prod"
region      = "europe-west1"
zone        = "europe-west1-b"

# EU_ECB compliance profile: GDPR Art. 32, DORA Art. 10, EU AI Act Title III
cage_deployment_region = "EU_ECB"

# ─── High Availability ────────────────────────────────────────────────────────
# Full HA: DORA Art. 10 operational resilience requirements

enable_high_availability = true
enable_nist_compliance   = false # US_FED controls not applicable in EU

# ─── Database Sizing ──────────────────────────────────────────────────────────
# Production-grade capacity with EU data residency

postgres_tier      = "db-custom-2-7680"
postgres_disk_size = 50

redis_tier           = "STANDARD_HA"
redis_memory_size_gb = 5

# ─── Cloud Run Scaling ────────────────────────────────────────────────────────
# Always-on instances for DORA operational continuity

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
