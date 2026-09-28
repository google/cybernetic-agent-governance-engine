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

output "trust_anchor_pem" {
  description = "Public certificate of the mesh root CA (Linkerd identityTrustAnchorsPEM)."
  value       = google_privateca_certificate_authority.mesh_root.pem_ca_certificates[0]
}

output "ca_pool_id" {
  description = "Full resource ID of the mesh CA pool."
  value       = google_privateca_ca_pool.mesh.id
}

output "identity_suffix" {
  description = "Suffix of every Linkerd workload identity: <sa>.<namespace>.<identity_suffix> (the l5d-client-id format)."
  value       = "serviceaccount.identity.linkerd.${var.cluster_domain}"
}

output "ready" {
  description = "Depend on this to order workloads after the proxy injector exists; pods created earlier run without a proxy."
  value       = helm_release.linkerd_control_plane.status
}
