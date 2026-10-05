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
  description = "Kubernetes namespace the CAGE workloads run in."
  type        = string
}

# No default: a missing region must fail the plan rather than silently apply
# the US_FED posture to an EU_ECB or APAC_MAS deployment (DEP-09).
variable "cage_deployment_region" {
  description = "Deployment jurisdiction: US_FED, EU_ECB, or APAC_MAS."
  type        = string

  validation {
    condition     = contains(["US_FED", "EU_ECB", "APAC_MAS"], var.cage_deployment_region)
    error_message = "cage_deployment_region must be one of: US_FED, EU_ECB, APAC_MAS."
  }
}
