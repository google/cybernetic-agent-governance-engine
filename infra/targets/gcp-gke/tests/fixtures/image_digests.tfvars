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

# TEST-ONLY FIXTURE. Never pass this file to a real plan or apply.
#
# image_digests has no default and no committed value (POAM-2026-131), so the
# mock-provider terraform tests need a map to plan with. Every reference is fake
# on purpose: the registry is under .invalid, a top-level domain reserved never to
# resolve (RFC 2606), and the digest is a repeated "deadbeef". The map holds every
# image any profile can deploy, so each run plans whatever its posture enables;
# runs that test coverage replace the map with their own.
#
#   terraform -chdir=infra/targets/gcp-gke test -var-file=staging.tfvars \
#     -var-file=tests/fixtures/image_digests.tfvars

image_digests = {
  "gateway"                    = "registry.invalid/cage-test/gateway@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "opa"                        = "registry.invalid/cage-test/opa@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "agentsight-ui"              = "registry.invalid/cage-test/agentsight-ui@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "langfuse"                   = "registry.invalid/cage-test/langfuse@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "langfuse-worker"            = "registry.invalid/cage-test/langfuse-worker@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "cloud-sql-proxy"            = "registry.invalid/cage-test/cloud-sql-proxy@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "clickhouse-server"          = "registry.invalid/cage-test/clickhouse-server@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "clickhouse-keeper"          = "registry.invalid/cage-test/clickhouse-keeper@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "compliance-bridge"          = "registry.invalid/cage-test/compliance-bridge@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "vllm-streamer"              = "registry.invalid/cage-test/vllm-streamer@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "governed-financial-advisor" = "registry.invalid/cage-test/governed-financial-advisor@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "nemo-guardrails"            = "registry.invalid/cage-test/nemo-guardrails@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "presidio-analyzer"          = "registry.invalid/cage-test/presidio-analyzer@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  "presidio-anonymizer"        = "registry.invalid/cage-test/presidio-anonymizer@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
