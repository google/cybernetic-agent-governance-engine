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
  description = "Google Cloud primary region"
  type        = string
}

variable "network_name" {
  description = "Name of the VPC network"
  type        = string
  default     = ""
}

variable "subnetwork_name" {
  description = "Name of the primary subnetwork"
  type        = string
  default     = ""
}

variable "subnet_cidr" {
  description = "CIDR range for the primary subnetwork"
  type        = string
  default     = "10.0.0.0/20"
}

variable "pod_cidr" {
  description = "Secondary CIDR range for GKE pods"
  type        = string
  default     = ""
}

variable "service_cidr" {
  description = "Secondary CIDR range for GKE services"
  type        = string
  default     = ""
}

variable "secondary_ip_ranges" {
  description = "Explicit list of secondary IP ranges for the subnetwork"
  type = list(object({
    range_name    = string
    ip_cidr_range = string
  }))
  default = []
}

variable "enable_audit_logging" {
  description = "Enable detailed Cloud NAT / VPC flow logging"
  type        = bool
  default     = false
}

variable "enable_psa" {
  description = "Enable Private Services Access (PSA) peering for Cloud SQL / Memorystore Redis"
  type        = bool
  default     = true
}

variable "psa_prefix_length" {
  description = "Prefix length for Private Services Access peering IP allocation"
  type        = number
  default     = 16
}

variable "enable_default_deny" {
  description = "Enforce default deny ingress firewall rule (SC-7 fail-closed boundary protection)"
  type        = bool
  default     = true
}
