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

output "bucket_name" {
  description = "Name of the retention-locked WORM bucket"
  value       = google_storage_bucket.bucket.name
}

output "bucket_id" {
  description = "ID of the retention-locked WORM bucket"
  value       = google_storage_bucket.bucket.id
}

output "bucket_url" {
  description = "URL of the retention-locked WORM bucket (gs://<name>)"
  value       = google_storage_bucket.bucket.url
}

output "bucket_self_link" {
  description = "Self-link URI of the retention-locked WORM bucket"
  value       = google_storage_bucket.bucket.self_link
}
