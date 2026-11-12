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
  description = "GCP project that hosts the CA pool and the cert-manager issuer identity."
  type        = string
}

variable "region" {
  description = "Region of the Certificate Authority Service CA pool. Keep it in the deployment's data-residency region."
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod). Used in resource names."
  type        = string
}

variable "network" {
  description = "VPC network of the GKE cluster. The control-plane-to-node firewall rule for the admission webhooks is created here."
  type        = string
  default     = "default"
}

variable "master_ipv4_cidr_block" {
  description = "GKE control-plane CIDR of a private cluster. The API server calls the Linkerd admission webhooks from this range."
  type        = string
}

variable "enable_cni" {
  description = "Install linkerd2-cni and run the control plane with cniEnabled=true. Required wherever Pod Security Admission is 'restricted' (proxy-init needs NET_ADMIN otherwise)."
  type        = bool
  default     = false
}

variable "cluster_domain" {
  description = "Kubernetes cluster domain. Linkerd's identity trust domain defaults to it."
  type        = string
  default     = "cluster.local"
}


variable "proxy_required_namespaces" {
  description = "Namespaces whose pods must run the Linkerd proxy. An admission policy refuses any pod created there without it, so a pod created while the proxy injector is down waits for the injector instead of running outside the mesh. Empty installs no policy."
  type        = list(string)
  default     = []
}

variable "enable_deletion_protection" {
  description = "Protect the mesh root CA from accidental Terraform destruction in production; false in ephemeral dev/staging lifecycle tiers."
  type        = bool
  default     = true
}

variable "ca_pool_id" {
  description = "Optional explicit Google CAS CaPool ID. Google CAS permanently forbids reusing deleted CaPool IDs in the same project/region, so ephemeral deployments pass a random-suffixed ID."
  type        = string
  default     = ""
}

variable "cas_issuer_account_id" {
  description = "Optional explicit GCP Service Account ID (6-30 lowercase chars) for cert-manager google-cas-issuer. Ephemeral/rebuildable deployments pass a random-suffixed ID so recreating the mesh never reuses a recently deleted GSA email whose negative IAM cache outlives google-cas-issuer's ~60s PermanentError retry window."
  type        = string
  default     = ""

  validation {
    condition     = var.cas_issuer_account_id == "" || can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", var.cas_issuer_account_id))
    error_message = "cas_issuer_account_id must be empty or a valid 6-30 character GCP service account ID (^[a-z][-a-z0-9]{4,28}[a-z0-9]$)."
  }
}
