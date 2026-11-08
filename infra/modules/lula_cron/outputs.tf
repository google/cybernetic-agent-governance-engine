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

output "cron_job_name" {
  description = "Name of the in-cluster Lula CronJob."
  value       = kubernetes_cron_job_v1.lula_audit.metadata[0].name
}

output "config_map_name" {
  description = "Name of the ConfigMap holding active Lula validation manifests."
  value       = kubernetes_config_map_v1.lula_specs.metadata[0].name
}

output "active_spec_count" {
  description = "Number of active (non-planned) Lula validation manifests mounted into the CronJob."
  value       = length(local.active_lula_specs)
}

output "active_spec_names" {
  description = "Sorted filenames of active Lula validation manifests mounted into the CronJob."
  value       = sort(keys(local.active_lula_specs))
}
