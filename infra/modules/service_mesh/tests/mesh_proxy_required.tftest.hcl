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

# Plan-time contract of the proxy-required admission policy: every namespace
# listed in proxy_required_namespaces gets the policy that refuses pods without
# the Linkerd proxy, and an empty list installs none. Mock providers only, so
# no credentials and no state. CI runs it in the terraform-test job:
#   terraform -chdir=infra/modules/service_mesh test

mock_provider "google" {}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "time" {}

variables {
  project_id             = "mesh-test-project"
  region                 = "us-central1"
  environment            = "test"
  master_ipv4_cidr_block = "172.16.0.0/28"
}

run "listed_namespaces_get_the_policy" {
  command = plan

  variables {
    proxy_required_namespaces = ["governance-stack"]
  }

  assert {
    condition     = length(helm_release.mesh_proxy_required) == 1
    error_message = "a namespace listed in proxy_required_namespaces must get the proxy-required policy"
  }
  assert {
    condition     = endswith(helm_release.mesh_proxy_required[0].chart, "charts/mesh-proxy-required")
    error_message = "the policy must come from the module's mesh-proxy-required chart"
  }
  assert {
    condition     = tolist(yamldecode(helm_release.mesh_proxy_required[0].values[0]).namespaces) == tolist(["governance-stack"])
    error_message = "the policy must bind exactly the namespaces listed in proxy_required_namespaces"
  }
}

run "no_namespaces_install_no_policy" {
  command = plan

  assert {
    condition     = length(helm_release.mesh_proxy_required) == 0
    error_message = "an empty proxy_required_namespaces must install no policy"
  }
}
