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

output "key_ring_id" {
  description = "KMS Key Ring ID"
  value       = google_kms_key_ring.keyring.id
}

output "key_ring_name" {
  description = "KMS Key Ring name"
  value       = google_kms_key_ring.keyring.name
}

output "crypto_key_id" {
  description = "Symmetric CMEK Crypto Key ID"
  value       = google_kms_crypto_key.cmek_key.id

  depends_on = [
    google_kms_crypto_key_iam_member.cloudsql_agent,
    google_kms_crypto_key_iam_member.gcs_agent,
    google_kms_crypto_key_iam_member.redis_agent,
    google_kms_crypto_key_iam_member.gke_agent,
    google_kms_crypto_key_iam_member.memorystore_agent,
    google_kms_crypto_key_iam_member.additional_members,
  ]
}

output "crypto_key_name" {
  description = "Symmetric CMEK Crypto Key name"
  value       = google_kms_crypto_key.cmek_key.name
}
