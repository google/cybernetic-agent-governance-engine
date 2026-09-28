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

variable "project_id" {
  description = "Google Cloud project ID"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "region" {
  description = "Google Cloud region"
  type        = string
}

variable "cage_deployment_region" {
  description = "Deployment jurisdiction (US_FED, EU_ECB, APAC_MAS)"
  type        = string
  default     = "US_FED"
}

variable "keyring_name" {
  description = "Name of the KMS key ring"
  type        = string
  default     = ""
}

variable "key_name" {
  description = "Name of the symmetric CMEK crypto key"
  type        = string
  default     = ""
}

variable "protection_level" {
  description = "KMS protection level (SOFTWARE or HSM)"
  type        = string
  default     = "SOFTWARE"
}

variable "rotation_period" {
  description = "Rotation period for the CMEK key (default 90 days = 7776000s)"
  type        = string
  default     = "7776000s"
}

variable "grant_service_agents" {
  description = "Whether to automatically grant cryptoKeyEncrypterDecrypter to standard GCP service agents (Cloud SQL, GCS, Redis)"
  type        = bool
  default     = true
}

variable "additional_encrypter_decrypter_members" {
  description = "Additional IAM members to grant roles/cloudkms.cryptoKeyEncrypterDecrypter on the CMEK key"
  type        = list(string)
  default     = []
}
