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

# Verification of the Persistent Evidence Custody Domain (§10a, R-10, F-66,
# F-94, F-97):
#   1. Evidence CMEK key defaults to HSM in staging/prod, 120-day destroy window,
#      and binds the evidence project's GCS service agent + custodian (never deployer).
#   2. Real PEM public keys from data.google_kms_crypto_key_version populate a
#      content-addressed WORM manifest object (trust-anchors/signing-key-manifest-<hex>.json)
#      that rotates cleanly without colliding with locked WORM objects and rejects
#      non-PEM resource path strings.
#   3. external_evidence_domain_enabled = true plans zero managed evidence resources
#      so sa-cage-deployer holds zero destroy path over evidence custody (AU-9(4)).
#   4. prod refuses single-project custody unless external_evidence_domain_enabled = true
#      or evidence_project_id != project_id, while staging allows single-project mode.

mock_provider "google" {}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "random" {}
mock_provider "time" {}

override_module {
  target = module.gke
  outputs = {
    cluster_ca_certificate = "dGVzdA=="
    cluster_endpoint       = "203.0.113.10"
    cluster_location       = "us-central1-a"
    cluster_name           = "cage-staging"
    is_regional            = false
    node_pools             = {}
    workload_identity_pool = "evidence-test-project.svc.id.goog"
  }
}

override_module {
  target = module.memorystore_governance
  outputs = {
    managed_server_ca     = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"]
    primary_endpoint_ip   = "10.10.0.5"
    primary_endpoint_port = 6379
    replica_count         = 1
  }
}

override_module {
  target = module.memorystore_app
  outputs = {
    primary_endpoint_ip   = "10.10.0.6"
    primary_endpoint_port = 6379
  }
}

variables {
  project_id                     = "evidence-test-project"
  authorized_networks            = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

run "staging_single_project_binds_gcs_service_agent_and_hsm_cmek" {
  command = plan

  override_data {
    target          = module.evidence_domain.data.google_project.evidence[0]
    override_during = plan
    values = {
      number = "123456789012"
    }
  }

  assert {
    condition     = module.evidence_domain.evidence_project_id == "evidence-test-project"
    error_message = "staging must allow single-project evidence custody when evidence_project_id is null"
  }
  assert {
    condition     = module.evidence_domain.evidence_cmek_destroy_scheduled_duration == "10368000s"
    error_message = "evidence CMEK key must enforce 120-day (10368000s) destroy_scheduled_duration"
  }
  assert {
    condition     = local.effective_kms_protection_level == "HSM"
    error_message = "staging must default kms_protection_level to HSM"
  }
  assert {
    condition     = module.evidence_domain.gcs_service_agent_email == "service-123456789012@gs-project-accounts.iam.gserviceaccount.com"
    error_message = "evidence_domain must resolve the evidence project's Cloud Storage service agent from data.google_project.evidence"
  }
  assert {
    condition     = data.google_kms_crypto_key_version.gateway_seal.version == 1 && data.google_kms_crypto_key_version.compliance_evidence.version == 1 && data.google_kms_crypto_key_version.reconciler_snapshot.version == 1
    error_message = "kms_signing.tf must resolve real PEM public keys via data.google_kms_crypto_key_version version 1 for all three governance signers"
  }
  assert {
    condition     = length(google_project_iam_audit_config.kms_signing_audit) == 1 && google_logging_project_sink.kms_asymmetric_sign[0].destination == "storage.googleapis.com/evidence-test-project-audit-logs-worm-staging" && google_logging_project_sink.admin_activity[0].destination == "storage.googleapis.com/evidence-test-project-audit-logs-worm-staging"
    error_message = "staging must enable KMS DATA_READ audit config and route both kms_asymmetric_sign and admin_activity sinks directly to module.evidence_domain.audit_logs_worm_bucket_name"
  }
  assert {
    condition     = toset(keys(module.evidence_domain.audit_log_sink_writers)) == toset(["kms_signing_audit", "admin_activity_audit"])
    error_message = "module.evidence_domain must grant objectCreator on audit-logs-worm using static sink keys known at plan time"
  }
  assert {
    condition     = google_logging_project_sink.admin_activity[0].filter == "logName=\"projects/evidence-test-project/logs/cloudaudit.googleapis.com%2Factivity\""
    error_message = "the Admin Activity sink filter must interpolate var.project_id and carry no literal interpolation sequence"
  }
}

run "dev_with_enforce_in_dev_enables_kms_audit_sinks" {
  command = plan

  override_data {
    target          = module.evidence_domain.data.google_project.evidence[0]
    override_during = plan
    values = {
      number = "123456789012"
    }
  }

  variables {
    environment           = "dev"
    enable_kms_audit_logs = false
    inference_backend     = "none"
    enable_gpu_node_pool  = false
    enforce_in_dev        = true
  }

  assert {
    condition     = length(google_project_iam_audit_config.kms_signing_audit) == 1 && length(google_logging_project_sink.kms_asymmetric_sign) == 1 && toset(keys(module.evidence_domain.audit_log_sink_writers)) == toset(["kms_signing_audit", "admin_activity_audit"])
    error_message = "an enforcing dev posture (enforce_in_dev = true) must enable KMS Data Access audit logging and both audit-log sinks"
  }
}

run "extra_sink_writer_identities_cannot_override_managed_sinks" {
  command = plan

  override_data {
    target          = module.evidence_domain.data.google_project.evidence[0]
    override_during = plan
    values = {
      number = "123456789012"
    }
  }

  override_resource {
    target          = google_logging_project_sink.kms_asymmetric_sign
    override_during = plan
    values = {
      writer_identity = "serviceAccount:kms-sink-writer@evidence-test-project.iam.gserviceaccount.com"
    }
  }

  variables {
    audit_log_sink_writer_identities = {
      kms_signing_audit = "serviceAccount:rogue-writer@evidence-test-project.iam.gserviceaccount.com"
      org_audit         = "serviceAccount:org-sink-writer@evidence-test-project.iam.gserviceaccount.com"
    }
  }

  assert {
    condition     = toset(keys(module.evidence_domain.audit_log_sink_writers)) == toset(["kms_signing_audit", "admin_activity_audit", "org_audit"])
    error_message = "extra audit_log_sink_writer_identities must add grants alongside the managed AS-6 sink keys"
  }
  assert {
    condition     = module.evidence_domain.audit_log_sink_writers["kms_signing_audit"] == "serviceAccount:kms-sink-writer@evidence-test-project.iam.gserviceaccount.com"
    error_message = "an extra audit_log_sink_writer_identities entry must never replace the managed KMS sink's writer identity"
  }
}

run "dev_disables_kms_audit_sinks_by_default_without_computed_for_each_errors" {
  command = plan

  override_data {
    target          = module.evidence_domain.data.google_project.evidence[0]
    override_during = plan
    values = {
      number = "123456789012"
    }
  }

  variables {
    environment           = "dev"
    enable_kms_audit_logs = false
    inference_backend     = "none"
    enable_gpu_node_pool  = false
    enforce_in_dev        = false
  }

  assert {
    condition     = length(google_project_iam_audit_config.kms_signing_audit) == 0 && length(google_logging_project_sink.kms_asymmetric_sign) == 0 && length(google_logging_project_sink.admin_activity) == 0 && length(module.evidence_domain.audit_log_sink_writers) == 0
    error_message = "dev must omit KMS audit config and Cloud Logging sinks when enable_kms_audit_logs = false"
  }
}

run "prod_refuses_single_project_evidence_domain_without_external_or_distinct_project" {
  command = plan

  variables {
    environment = "prod"
  }

  expect_failures = [terraform_data.evidence_domain_isolation_guard]
}

run "external_evidence_domain_plans_zero_managed_custody_resources" {
  command = plan

  variables {
    environment                      = "prod"
    external_evidence_domain_enabled = true
    evidence_project_id              = "external-evidence-custody-proj"
    external_evidence_cmek_key_id    = "projects/external-evidence-custody-proj/locations/us-central1/keyRings/cage-evidence-custody-keyring-prod/cryptoKeys/cage-evidence-cmek-key"
  }

  assert {
    condition     = module.evidence_domain.managed_custody_resource_count == 0 && module.worm_bucket.managed_bucket_count == 0 && length(google_storage_bucket_iam_member.compliance_bridge_worm_creator) == 0 && length(google_storage_bucket_iam_member.compliance_bridge_worm_viewer) == 0
    error_message = "external_evidence_domain_enabled = true must plan zero managed KMS/bucket/IAM resources in workload state"
  }
}

run "evidence_domain_module_applies_gcs_agent_and_pem_versioned_manifest" {
  command = apply

  module {
    source = "../../modules/evidence_domain"
  }

  override_data {
    target = data.google_project.evidence[0]
    values = {
      number = "987654321098"
    }
  }

  variables {
    evidence_project_id             = "evidence-custody-proj"
    workload_project_id             = "workload-ephemeral-proj"
    environment                     = "staging"
    region                          = "us-central1"
    cage_deployment_region          = "US_FED"
    evidence_bucket_name            = "evidence-custody-proj-cage-evidence-worm"
    custodian_service_account_email = "cage-compliance-bridge@workload-ephemeral-proj.iam.gserviceaccount.com"
    signing_key_manifest = {
      "gateway-seal" = {
        kid            = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/1"
        key_version_id = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/1"
        algorithm      = "EC_SIGN_P256_SHA256"
        public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgatewayv1testkey000000000001\n-----END PUBLIC KEY-----\n"
      }
    }
  }

  assert {
    condition     = contains(google_kms_crypto_key_iam_binding.evidence_cmek_crypto_operator[0].members, "serviceAccount:service-987654321098@gs-project-accounts.iam.gserviceaccount.com")
    error_message = "google_kms_crypto_key_iam_binding.evidence_cmek_crypto_operator[0].members must bind the evidence project's GCS service agent"
  }
  assert {
    condition     = startswith(google_storage_bucket_object.signing_key_manifest[0].name, "trust-anchors/signing-key-manifest-") && endswith(google_storage_bucket_object.signing_key_manifest[0].name, ".json")
    error_message = "google_storage_bucket_object.signing_key_manifest[0].name must be content-addressed"
  }
  assert {
    condition     = strcontains(google_storage_bucket_object.signing_key_manifest[0].content, "-----BEGIN PUBLIC KEY-----")
    error_message = "archived signing_key_manifest JSON must contain real PEM public key material"
  }
}

run "evidence_domain_key_rotation_produces_distinct_manifest_object_key" {
  command = apply

  module {
    source = "../../modules/evidence_domain"
  }

  override_data {
    target = data.google_project.evidence[0]
    values = {
      number = "987654321098"
    }
  }

  variables {
    evidence_project_id             = "evidence-custody-proj"
    workload_project_id             = "workload-ephemeral-proj"
    environment                     = "staging"
    region                          = "us-central1"
    cage_deployment_region          = "US_FED"
    evidence_bucket_name            = "evidence-custody-proj-cage-evidence-worm"
    custodian_service_account_email = "cage-compliance-bridge@workload-ephemeral-proj.iam.gserviceaccount.com"
    signing_key_manifest = {
      "gateway-seal" = {
        kid            = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/2"
        key_version_id = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/2"
        algorithm      = "EC_SIGN_P256_SHA256"
        public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgatewayv2rotatedkey000000002\n-----END PUBLIC KEY-----\n"
      }
    }
  }

  assert {
    condition     = output.signing_key_manifest_object_name != run.evidence_domain_module_applies_gcs_agent_and_pem_versioned_manifest.signing_key_manifest_object_name
    error_message = "key rotation must write a distinct content-addressed manifest object path so WORM retention locks never block rotation"
  }
}

run "evidence_domain_ephemeral_epoch_produces_distinct_manifest_object_key" {
  command = apply

  module {
    source = "../../modules/evidence_domain"
  }

  override_data {
    target = data.google_project.evidence[0]
    values = {
      number = "987654321098"
    }
  }

  variables {
    evidence_project_id             = "evidence-custody-proj"
    workload_project_id             = "workload-ephemeral-proj"
    environment                     = "staging"
    region                          = "us-central1"
    cage_deployment_region          = "US_FED"
    evidence_bucket_name            = "evidence-custody-proj-cage-evidence-worm"
    custodian_service_account_email = "cage-compliance-bridge@workload-ephemeral-proj.iam.gserviceaccount.com"
    deployment_epoch_id             = "a1b2c3d4"
    signing_key_manifest = {
      "gateway-seal" = {
        kid            = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/1"
        key_version_id = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/1"
        algorithm      = "EC_SIGN_P256_SHA256"
        public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgatewayv1testkey000000000001\n-----END PUBLIC KEY-----\n"
      }
    }
  }

  assert {
    condition     = output.signing_key_manifest_object_name != run.evidence_domain_module_applies_gcs_agent_and_pem_versioned_manifest.signing_key_manifest_object_name
    error_message = "ephemeral deployment_epoch_id must write a distinct append-only WORM manifest object path even when KMS key versions are unchanged"
  }
}

run "evidence_domain_rejects_resource_path_in_public_key_pem" {
  command = plan

  module {
    source = "../../modules/evidence_domain"
  }

  override_data {
    target          = data.google_project.evidence[0]
    override_during = plan
    values = {
      number = "987654321098"
    }
  }

  variables {
    evidence_project_id             = "evidence-custody-proj"
    workload_project_id             = "workload-ephemeral-proj"
    environment                     = "staging"
    region                          = "us-central1"
    cage_deployment_region          = "US_FED"
    evidence_bucket_name            = "evidence-custody-proj-cage-evidence-worm"
    custodian_service_account_email = "cage-compliance-bridge@workload-ephemeral-proj.iam.gserviceaccount.com"
    signing_key_manifest = {
      "gateway-seal" = {
        kid            = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/1"
        key_version_id = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal/cryptoKeyVersions/1"
        algorithm      = "EC_SIGN_P256_SHA256"
        public_key_pem = "projects/workload-ephemeral-proj/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/gateway-seal"
      }
    }
  }

  expect_failures = [google_storage_bucket_object.signing_key_manifest]
}

run "bound_genesis_rotation_wires_prior_head_and_attestation_to_gateway" {
  command = plan

  override_data {
    target          = module.evidence_domain.data.google_project.evidence[0]
    override_during = plan
    values = {
      number = "123456789012"
    }
  }

  variables {
    evidence_previous_chain_head_hash                = "1111111111111111111111111111111111111111111111111111111111111111"
    evidence_previous_batch_attestation_digest       = "2222222222222222222222222222222222222222222222222222222222222222"
    infra_evidence_previous_chain_head_hash          = "3333333333333333333333333333333333333333333333333333333333333333"
    infra_evidence_previous_batch_attestation_digest = "4444444444444444444444444444444444444444444444444444444444444444"
  }

  assert {
    condition     = module.gateway.evidence_previous_chain_head_hash == "1111111111111111111111111111111111111111111111111111111111111111" && module.gateway.evidence_previous_batch_attestation_digest == "2222222222222222222222222222222222222222222222222222222222222222"
    error_message = "gcp-gke must propagate paired 64-hex bound-genesis rotation digests into gateway container EVIDENCE_PREVIOUS_* env vars (F-94)"
  }

  assert {
    condition     = module.compliance_bridge[0].infra_evidence_previous_chain_head_hash == "3333333333333333333333333333333333333333333333333333333333333333" && module.compliance_bridge[0].infra_evidence_previous_batch_attestation_digest == "4444444444444444444444444444444444444444444444444444444444444444"
    error_message = "gcp-gke must propagate paired 64-hex bound-genesis rotation digests into compliance-bridge INFRA_EVIDENCE_PREVIOUS_* env vars (POAM-2026-205)"
  }
}

run "bound_genesis_rotation_refuses_unpaired_or_malformed_digests" {
  command = plan

  module {
    source = "../../modules/gateway"
  }

  variables {
    namespace                                  = "governance-stack"
    deployment_config_map_name                 = "cage-deployment"
    image                                      = "registry.invalid/cage-test/gateway@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    opa_image                                  = "registry.invalid/cage-test/opa@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    project_id                                 = "evidence-test-project"
    region                                     = "us-central1"
    redis_host                                 = "10.10.0.5"
    governance_redis_replica_count             = 1
    evidence_stream_redis_url                  = "redis://10.10.0.5:6379"
    evidence_stream_redis_db                   = 1
    evidence_stream_key                        = "cage:evidence:stream"
    evidence_previous_chain_head_hash          = "1111111111111111111111111111111111111111111111111111111111111111"
    evidence_previous_batch_attestation_digest = ""
    cage_inference_backend                     = "none"
    vllm_base_url                              = ""
    vllm_reasoning_api_base                    = ""
    vllm_fast_api_base                         = ""
    vllm_api_key                               = ""
    cage_env                                   = "staging"
    guardrails_model_name                      = "Qwen/Qwen2.5-1.5B-Instruct"
    opa_url                                    = "http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock"
    governance_salt                            = "test-governance-salt-0123456789abcdef"
    trusted_client_identities                  = ["cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"]
    service_account_name                       = "cage-gateway-sa"
    reconciler_kms_key                         = "projects/evidence-test-project/locations/us-central1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
  }

  expect_failures = [helm_release.gateway]
}
