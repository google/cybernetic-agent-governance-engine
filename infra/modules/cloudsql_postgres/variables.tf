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

variable "instance_name" {
  description = "Name of the Cloud SQL instance"
  type        = string
  default     = ""
}

variable "database_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "POSTGRES_15"
}

variable "tier" {
  description = "Cloud SQL machine tier (e.g. db-f1-micro, db-g1-small, db-custom-2-7680)"
  type        = string
  default     = "db-f1-micro"
}

variable "disk_size" {
  description = "Disk size in GB"
  type        = number
  default     = 10
}

variable "authorized_network" {
  description = "VPC network ID for private IP connectivity"
  type        = string
}

variable "enable_high_availability" {
  description = "Enable regional HA (multi-zone)"
  type        = bool
  default     = false
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery (PITR)"
  type        = bool
  default     = false
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

variable "deletion_protection" {
  description = "Whether deletion protection is enabled"
  type        = bool
  default     = false
}

variable "database_name" {
  description = "Default database name to create"
  type        = string
  default     = "langfuse"
}

variable "user_name" {
  description = "Default database user to create"
  type        = string
  default     = "langfuse"
}

variable "user_password" {
  description = "Password for built-in database user (ignored if user_type is CLOUD_IAM_SERVICE_ACCOUNT)"
  type        = string
  default     = null
  sensitive   = true
}

variable "user_type" {
  description = "Type of user: BUILT_IN or CLOUD_IAM_SERVICE_ACCOUNT"
  type        = string
  default     = "BUILT_IN"
}
