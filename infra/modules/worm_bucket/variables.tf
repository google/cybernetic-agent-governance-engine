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

variable "bucket_name" {
  description = "Bucket name (defaults to <project_id>-compliance-artifacts-<environment>)"
  type        = string
  default     = ""
}

variable "enable_cmek" {
  description = "Enable Customer-Managed Encryption Key (CMEK)"
  type        = bool
  default     = false
}

variable "kms_key_id" {
  description = "KMS crypto key ID for CMEK encryption"
  type        = string
  default     = null
}

variable "retention_period_seconds" {
  description = "Retention period in seconds (AU-9 WORM compliance: default 220752000 = 7 years)"
  type        = number
  default     = 220752000 # 2555 days / 7 years
}

variable "is_locked" {
  description = "Whether the retention policy is locked (irreversible AU-9 WORM lock)"
  type        = bool
  default     = false
}

variable "force_destroy" {
  description = "Allow deletion of non-empty bucket (should be false in production)"
  type        = bool
  default     = null
}

variable "archive_transition_days" {
  description = "Days after object creation to transition to ARCHIVE storage class"
  type        = number
  default     = 365
}
