# Cloud Run vs GKE — Security Posture Parity Audit

**Scope:** [gcp-cloudrun](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun) vs [gcp-gke](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-gke) + [gcp_gke_cluster module](file:///Users/laah/Code/cybernetic-governance-engine/infra/modules/gcp_gke_cluster/main.tf) + [deployment/k8s hardening](file:///Users/laah/Code/cybernetic-governance-engine/deployment/k8s/K8S_SECURITY_HARDENING.md). Compared at the `prod.tfvars` posture (US_FED, `enable_nist_compliance=true`).

## Verdict: ❌ Not at parity

Cloud Run is weaker than GKE on **supply-chain integrity**, **governance-signing wiring**, **east-west segmentation / egress**, **Redis auth**, and **evidence WORM**. It is stronger on edge protection (WAF, VPC-SC) and service-to-service authn to vLLM.

---

## Gaps (Cloud Run weaker than GKE)

### 🔴 Critical

| # | Gap | Cloud Run evidence | GKE counterpart |
|---|---|---|---|
| C1 | **Binary Authorization not enforced on any Cloud Run service.** Cloud Run only enforces BinAuthz if each service/job sets `binary_authorization { use_default = true }` (or an org policy requires it). No service sets it. The attestor also has **no `public_keys`**, so nothing could verify attestations anyway. `prod.tfvars` doesn't set `enable_binary_authorization`, and it defaults to `false`. | [binary_authorization.tf:50-117](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/binary_authorization.tf#L50-L117), [variables.tf](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/variables.tf), [prod.tfvars](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/prod.tfvars) | `PROJECT_SINGLETON_POLICY_ENFORCE`, prod enables it ([gke main.tf:95-97](file:///Users/laah/Code/cybernetic-governance-engine/infra/modules/gcp_gke_cluster/main.tf#L95-L97)) |
| C2 | **Governance signing / seal material isn't wired.** No `GOVERNANCE_SALT`, `KMS_GOVERNANCE_KEY` or `CAGE_KMS_PROVIDER` on gateway, advisor or compliance-bridge. The injected `CAGE_ROUTING_SEAL_SALT` is **not read anywhere in `src/`**. The result: in dev the well-known default salt is used, so seals can be forged. In staging/prod the startup guards stop the gateway from booting. That fails closed, but the deployment doesn't work. | [main.tf:817-900](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L817-L900), [routing_seal.py:243](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/governance/routing_seal.py#L243), [hybrid_server.py:169-202](file:///Users/laah/Code/cybernetic-governance-engine/src/gateway/server/hybrid_server.py#L169-L202) | Wired via [gke main.tf:613-627](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-gke/main.tf#L613-L627), [governed_advisor:264-293](file:///Users/laah/Code/cybernetic-governance-engine/infra/modules/governed_advisor/main.tf#L264-L293) |
| C3 | **`RECONCILIATION_PROVIDER = "stub"` on the gateway.** The CBF then evaluates against fabricated balances. The BLOCKER-06 guard makes prod refuse to start, and dev/staging run on fake ledger data. | [main.tf:827-830](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L827-L830) | `"gcs"` ([gke main.tf:625](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-gke/main.tf#L625)) |

### 🟠 High

| # | Gap | Cloud Run evidence | GKE counterpart |
|---|---|---|---|
| H1 | **Egress is open, not default-deny.** TCP/443 to `0.0.0.0/0` is allowed and there's no deny-egress rule. Every service uses `egress = ALL_TRAFFIC` through Cloud NAT. | [main.tf:103-122](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L103-L122) | `default-deny-egress` + Cilium FQDN lockdown ([cilium/egress-lockdown.yaml](file:///Users/laah/Code/cybernetic-governance-engine/deployment/k8s/cilium/egress-lockdown.yaml)) |
| H2 | **Flat east-west network.** All services share one subnet with no `network_tags`, and firewall sources are `var.subnet_cidr`. Any service (e.g. agentsight-ui) can reach Redis, ClickHouse and Postgres. | [main.tf:70-89](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L70-L89), [clickhouse_vm.tf:258-259](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/clickhouse_vm.tf#L258-L259) | Per-workload NetworkPolicies ([network-policy-hardening.yaml](file:///Users/laah/Code/cybernetic-governance-engine/deployment/k8s/network-policy-hardening.yaml)) |
| H3 | **Memorystore Redis has no AUTH and no in-transit TLS.** `auth_enabled` and `transit_encryption_mode` aren't set, and the URLs are `redis://host:port`. Redis holds the evidence stream and rate-limit state. | [main.tf:212-252](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L212-L252) | Password auth ([redis_cache:54-60](file:///Users/laah/Code/cybernetic-governance-engine/infra/modules/redis_cache/main.tf#L54-L60)) |
| H4 | **The Langfuse trace bucket has no WORM retention, and its writer has `objectAdmin`.** The writer can delete evidence. | [main.tf:328-357](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L328-L357), [main.tf:657-661](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L657-L661) | Locked 7-year retention plus `objectCreator` only ([gke main.tf:144-147, 193-203](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-gke/main.tf#L144-L203)) |
| H5 | **NeMo Guardrails (input rails / PII) is disabled in prod.** | [prod.tfvars](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/prod.tfvars) `enable_nemo_guardrails = false` | Default `true` ([gke variables.tf:307-310](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-gke/variables.tf#L307-L310)) |

### 🟡 Medium

| # | Gap | Evidence |
|---|---|---|
| M1 | Gateway ingress is `INGRESS_TRAFFIC_ALL` by default because `enable_load_balancer` defaults to `false` and prod doesn't set it. IAM invoker still applies, but there's no WAF in front. | [main.tf:737](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L737) |
| M2 | A hardcoded `VLLM_API_KEY = "cage-cloudrun-dev-key"` sits in a plaintext env var. This breaks the secret-hygiene rule in AGENTS.md. | [main.tf:897-900](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L897-L900), [1005-1008](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L1005-L1008) |
| M3 | The ClickHouse password is embedded in plaintext in `CLICKHOUSE_MIGRATION_URL`. This undoes the Secret Manager ref on `CLICKHOUSE_PASSWORD`. | [main.tf:1337-1340](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L1337-L1340), [1498-1501](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L1498-L1501) |
| M4 | The `test_automation` SA gets `run.invoker` on every service, **including prod**. Nothing gates it by environment. | [main.tf:2168-2229](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L2168-L2229), [vllm.tf:373-389](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/vllm.tf#L373-L389) |
| M5 | There's no east-west mTLS on VPC paths: ClickHouse over HTTP :8123 and Redis in plaintext. GKE has a Linkerd mTLS policy ([linkerd-mtls-policy.yaml](file:///Users/laah/Code/cybernetic-governance-engine/deployment/k8s/linkerd-mtls-policy.yaml)). | [main.tf:1332-1335](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L1332-L1335) |
| M6 | VPC-SC uses `organization_id`, which defaults to `""`, and prod.tfvars doesn't set it. If it's empty, the prod NIST plan fails. | [vpc_service_controls.tf:27-31](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/vpc_service_controls.tf#L27-L31) |
| M7 | The reconciliation daemon has no `vpc_access`, and neither it nor NeMo sets a CMEK `encryption_key`. | [main.tf:1685-1766](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L1685-L1766) |

---

## Parity (both sides equal)

- **CMEK:** off in prod on both (`enable_cmek=false`).
- **Hardcoded Langfuse init password:** present on both sides ([CR main.tf:1274-1277](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-cloudrun/main.tf#L1274-L1277), [GKE main.tf:536-537](file:///Users/laah/Code/cybernetic-governance-engine/infra/targets/gcp-gke/main.tf#L536-L537)). Both should be fixed.
- **Compliance-artifact bucket:** locked WORM plus `objectCreator` on both.
- **POAM-019 dual-project guard:** present on both.
- **Workload isolation:** Cloud Run's sandbox (gVisor / gen2 microVM, non-privileged) is a reasonable match for GKE's PSA-restricted + seccomp + caps-drop.

## Where Cloud Run is stronger

- Cloud Armor WAF (OWASP CRS, adaptive L7 DDoS, rate limiting) plus a MODERN/TLS 1.2 SSL policy, when the LB is enabled.
- A VPC Service Controls perimeter (GKE has none).
- IAM-authenticated invocation to vLLM. GKE uses unauthenticated in-cluster HTTP with `api_key = "EMPTY"`.
- Cloud SQL `ENCRYPTED_ONLY`, no public IP, PITR. GKE runs in-cluster Postgres with no backups.
- No exposed control plane. GKE prod keeps a public master endpoint (`enable_private_master_endpoint=false`).

---

## Suggested remediation (priority order)

1. Add `binary_authorization { use_default = true }` to every `google_cloud_run_v2_service`/`_job`. Add a KMS-backed `public_keys` block to the attestor. Set `enable_binary_authorization = true` in all prod tfvars.
2. Wire `GOVERNANCE_SALT` (a Secret Manager ref), `KMS_GOVERNANCE_KEY` and `CAGE_KMS_PROVIDER=gcp` into the gateway, advisor and compliance-bridge. Drop the dead `CAGE_ROUTING_SEAL_SALT`.
3. Set `RECONCILIATION_PROVIDER = "gcs"`.
4. Add a `deny all egress` firewall at low priority. Add tag-scoped allow rules, using `network_tags` on each service's `vpc_access`, for Redis, ClickHouse, Postgres and specific external FQDNs/ranges.
5. Redis: `auth_enabled = true`, `transit_encryption_mode = "SERVER_AUTHENTICATION"`. Put the AUTH string in Secret Manager.
6. Langfuse traces bucket: add a locked `retention_policy` and downgrade the writer to `objectCreator` + `legacyBucketReader`.
7. Prod tfvars: `enable_nemo_guardrails = true`, `enable_load_balancer = true`.
8. Move the vLLM key and ClickHouse URL into Secret Manager. Gate the test-automation invoker bindings with `var.environment != "prod"`.
9. Add a CI parity check, e.g. a `tflint`/OPA-conftest rule, that fails if any Cloud Run service lacks `binary_authorization` or `network_tags`.
