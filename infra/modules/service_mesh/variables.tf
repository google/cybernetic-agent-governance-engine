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

