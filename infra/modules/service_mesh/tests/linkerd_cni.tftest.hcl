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

# Plan-time contract of the linkerd2-cni release: wherever the CNI plugin is
# installed, its repair controller runs, so a meshed pod caught by the
# node-startup race (validator exit 95) is recreated instead of crash-looping
# until someone deletes it, and the repair-scope admission policy is installed
# with it to confine the controller's cluster-wide delete grant. Mock
# providers only, so no credentials and no state. CI runs it in the
# terraform-test job:
#   terraform -chdir=infra/modules/service_mesh test

mock_provider "google" {}
mock_provider "helm" {}
mock_provider "kubernetes" {}

variables {
  project_id             = "mesh-test-project"
  region                 = "us-central1"
  environment            = "test"
  master_ipv4_cidr_block = "172.16.0.0/28"
}

run "cni_release_runs_the_repair_controller" {
  command = plan

  variables {
    enable_cni = true
  }

  assert {
    condition     = length(helm_release.linkerd_cni) == 1
    error_message = "enable_cni = true must install linkerd2-cni"
  }
  assert {
    condition     = yamldecode(helm_release.linkerd_cni[0].values[0]).repairController.enabled == true
    error_message = "linkerd2-cni must run its repair controller, or pods caught by the node-startup race crash-loop until deleted by hand"
  }
  assert {
    # The chart gates the controller's command and env on this flag; off, the
    # container would run the installer instead of the controller.
    condition     = yamldecode(helm_release.linkerd_cni[0].values[0]).repairController.enableSecurityContext == true
    error_message = "repairController.enableSecurityContext must stay true: the chart renders the controller's command and env only when it is set"
  }
  assert {
    condition     = yamldecode(helm_release.linkerd_cni[0].values[0]).destCNIBinDir == "/home/kubernetes/bin"
    error_message = "GKE keeps CNI binaries in /home/kubernetes/bin"
  }
  assert {
    condition     = yamldecode(helm_release.linkerd_cni[0].values[0]).destCNINetDir == "/etc/cni/net.d"
    error_message = "linkerd2-cni must chain into the node's CNI configuration in /etc/cni/net.d"
  }
  assert {
    # The repair controller's delete grant is cluster-wide; the guard's
    # admission policy is what confines it to the controller's own node.
    condition     = length(helm_release.linkerd_cni_repair_guard) == 1
    error_message = "the linkerd2-cni repair controller must not run without the repair-scope admission policy"
  }
  assert {
    condition     = yamldecode(helm_release.linkerd_cni_repair_guard[0].values[0]).serviceAccountUsername == "system:serviceaccount:linkerd-cni:linkerd-cni"
    error_message = "the repair-scope policy must match the service account the linkerd2-cni chart binds to its ClusterRole"
  }
}

run "no_cni_installs_no_cni_release" {
  command = plan

  variables {
    enable_cni = false
  }

  assert {
    condition     = length(helm_release.linkerd_cni) == 0 && length(kubernetes_namespace.linkerd_cni) == 0
    error_message = "enable_cni = false must install neither linkerd2-cni nor its namespace"
  }
  assert {
    condition     = length(helm_release.linkerd_cni_repair_guard) == 0
    error_message = "enable_cni = false must not install the repair-scope policy"
  }
}
