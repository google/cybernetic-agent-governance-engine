# External Evaluator Guide

This guide is written for independent auditors, security reviewers, and prospective adopters verifying the runtime governance, cryptographic custody, and infrastructure isolation claims of the Cybernetic Agent Governance Engine (CAGE) directly from repository source and reproducible execution artifacts.

> [!NOTE]
> CAGE is a reference architecture, not a vendor-operated SaaS. Every verification command below runs against artifacts you export, containers you boot locally, or a disposable Google Cloud project (`<PROJECT_ID>`) under your own administrative control.

---

## 1. Three Evaluation Paths (Cheapest First)

Choose the evaluation tier that matches the claims you need to verify. Start with **Path A** (seconds, zero cloud credentials, standard library only) before progressing to local containers (**Path B**) or full clean-room GKE certification (**Path C**).

### 1a. Path A — Static & Offline Conformance (`packages/cage-conformance` + `proof/`)

Path A verifies exported governance traces (`GOVERNANCE_TRACE`), tamper-evident evidence streams (`cage-audit/3.0`), `GovernanceEnvelope` cryptographic signatures, and exported Cloud KMS audit-log corroboration bundles on an air-gapped workstation with zero cluster access.

#### Installation (Published Release Wheel or Source Checkout)

The standalone verifier [`packages/cage-conformance/`](../packages/cage-conformance/) (`v0.4.0`) declares zero third-party runtime dependencies (`dependencies = []` in [`packages/cage-conformance/pyproject.toml`](../packages/cage-conformance/pyproject.toml)) so an auditor can verify traces, hash chains, and conformance reports using only the Python `>=3.10` standard library. Its formal transition model and invariant engine (`model.py`, `trace_conformance.py`, `stream_invariants.py`) are byte-identical copies of [`proof/model.py`](../proof/model.py), [`proof/trace_conformance.py`](../proof/trace_conformance.py), and [`proof/stream_invariants.py`](../proof/stream_invariants.py), enforced in CI by [`scripts/check_conformance_sync.py`](../scripts/check_conformance_sync.py).

```bash
# Option 1: Install the standalone wheel from the client-v0.3.0 GitHub Release (no repo clone needed)
pip install "https://github.com/google/cybernetic-agent-governance-engine/releases/download/client-v0.3.0/cage_conformance-0.4.0-py3-none-any.whl"

# Optional: install `cryptography` only if verifying RS256 OIDC-attested reports (`attest` / `verify-report`)
pip install "cryptography>=42"

# Optional: install `cage-client` (v0.3.0) to test out-of-band `kid` GovernanceEnvelope verification
pip install "https://github.com/google/cybernetic-agent-governance-engine/releases/download/client-v0.3.0/cage_client-0.3.0-py3-none-any.whl"
```

From a local CAGE repository checkout:

```bash
# Option 2: Install from source checkout (or add `[attest]` for OIDC report attestation)
pip install ./packages/cage-conformance
pip install './packages/cage-conformance[attest]'

# Confirm byte-for-byte parity between `proof/` and `packages/cage-conformance/`
uv run python scripts/check_conformance_sync.py

# Run the standalone Python BFS formal safety model (add TLA_TOOLS_JAR=/path/to/tla2tools.jar for TLC)
make verify-tla
```

#### Exact Offline Verification Commands

Every `cage-conformance verify` invocation requires explicit provenance flags (`--provider-id`, `--adapter-author-org`, `--counterparty-org`, `--adapter-version`, `--adapter-commit`, `--runner-org`, `--runner-identity`) so reports record only explicitly declared runner metadata ([`packages/cage-conformance/src/cage_conformance/cli.py`](../packages/cage-conformance/src/cage_conformance/cli.py)):

```bash
# 1. Verify a `cage-audit/3.0` evidence stream export across RFC 8785 JCS link hashes and INV-1..INV-5
cage-conformance verify --stream <evidence.jsonl> \
  --expected-thresholds-digest <64-hex-thresholds-digest> \
  --require-thresholds-loaded \
  --require-settled \
  --provider-id cage-kernel \
  --adapter-author-org "Google LLC" \
  --counterparty-org "<EVALUATOR_ORG>" \
  --adapter-version 4.1.0 \
  --adapter-commit "$(git rev-parse --short HEAD)" \
  --runner-org "<EVALUATOR_ORG>" \
  --runner-identity "auditor@example.test" \
  --output <stream_report.json>

# Equivalent in-repo CLI wrapper over `proof/stream_invariants.py` (`check_stream()`)
uv run python scripts/check_trace_conformance.py --stream <evidence.jsonl> \
  --expected-thresholds-digest <64-hex-thresholds-digest> \
  --require-thresholds-loaded \
  --require-settled

# 2. Verify a `GOVERNANCE_TRACE` JSONL export against `proof/model.py` (`reachable_over()`)
cage-conformance verify --trace <events.jsonl> \
  --provider-id cage-kernel \
  --adapter-author-org "Google LLC" \
  --counterparty-org "<EVALUATOR_ORG>" \
  --adapter-version 4.1.0 \
  --adapter-commit "$(git rev-parse --short HEAD)" \
  --runner-org "<EVALUATOR_ORG>" \
  --runner-identity "auditor@example.test" \
  --output <trace_report.json>

# 3. Re-derive report posture, validate schema integrity, and print the RFC 8785 JCS SHA-256 digest
cage-conformance verify-report <stream_report.json>

# 4. Corroborate HSM-signed `cage-evidence-batch/1` WORM attestations and per-key caller isolation
#    against an offline Cloud Audit Log export (`AS-6`)
cage-conformance verify-audit-corroboration \
  --audit-logs <cloud_audit_logs.jsonl> \
  --evidence <worm_attestations.jsonl>

# 5. Diagnose canonical JCS signing preimages on an `actuator_01` execution receipt
cage-conformance diagnose-receipt \
  packages/cage-conformance/src/cage_conformance/vectors/actuator_01_readme_receipt.json
```

Exit codes are fail-closed: `verify`, `verify-audit-corroboration`, and `diagnose-receipt` exit `0` on conformance, `1` on findings, and `2` on unreadable input or invalid arguments (`0` checked records is rejected as non-conformant).

#### What Offline Verification Proves (Zero Cluster Access)

Running `check_stream()` in [`proof/stream_invariants.py`](../proof/stream_invariants.py) (invoked by both `cage-conformance verify --stream` and [`scripts/check_trace_conformance.py`](../scripts/check_trace_conformance.py) `--stream`) mechanically proves:

- **`cage-audit/3.0` Hash-Chain & Digest Well-Formedness (`chain_schema`, `chain_hash`, `chain_continuity`, `digest_format`, `thresholds`)**: Every record recomputes its SHA-256 `record_hash` over `prev_hash || JCS(header) || payload_json` under pure-stdlib RFC 8785 JSON Canonicalization Scheme (JCS), sequence numbers are contiguous from genesis (`sequence == 0` with `prev_hash == ""`), every `governance_decision_digest` and `refusal_proof_hash` at any JSON depth is a 64-character lowercase SHA-256 hex digest, and `GOVERNANCE_THRESHOLDS_LOADED` matches `--expected-thresholds-digest`.
- **`INV-1` — No Action Binds Without a Single-Use Routing Seal (`no_direct_bind`, `single_use`)**: Every `GOVERNANCE_SEAL_CONSUMED` binds by `decision_record_hash` to an earlier valid `GOVERNANCE_DECISION` with matching `action` and `params_hash` at most once per decision and per `seal_ref`; every actuation receipt (`ACTUATION_RECEIPT`, `ACTUATION_REFUSAL_RECEIPT`, `ACTUATION_INDETERMINATE_RECEIPT`) binds by `governance_decision_digest` to an earlier `GOVERNANCE_SEAL_CONSUMED` at most once per `seal_ref`.
- **`INV-2` — The Control Barrier Is Never Breached (`cbf_barrier`)**: Every `CBF_COMMIT` carries a unique `debit_id` and finite numeric fields satisfying `state_after == state_before - cost`, `h_t == state_before - threshold`, `h_next == state_after - threshold`, `h_next >= 0`, and forward-invariance decay `h_next >= (1 - gamma) * h_t` for `gamma` in `(0, 1]`.
- **`INV-3` — A Seal Implies Every Planned Stage Passed (`decision_schema`, `plan`, `coverage`, `seal`, `reachable`, `narrow_reverified`)**: Every `GOVERNANCE_DECISION` (`schema_version == 2`) carries `seal_present == True`, a non-`DRY_RUN` profile, and stage plan/outcome pairs whose projection is reachable in `reachable_over()` ([`proof/model.py`](../proof/model.py)); `NARROW` verdicts additionally prove that the clamped parameter re-run independently planned and passed every stage.
- **`INV-4` — Rollback Conserves the Balance (`cbf_rollback`, `settlement`)**: `ROLLED_BACK` restores the exact committed `cost` of its `CBF_COMMIT` at most once, `ROLLED_BACK_UNLEDGERED` and `NOOP` restore `0.0` without mutating scalar state, and `GOVERNANCE_SETTLEMENT` agrees with rollback and actuation outcomes with zero settlement failures.
- **`INV-5` — Every Denial Produces an Evidence Record (`refusal_evidence`, `evidence_loss`)**: Every refusal record carries a 64-hex `proof_hash` (or `receipt_digest`), every caller-supplied `--expected-refusal-hash` appears on the stream, observed distinct refusals satisfy `--expected-refusal-count`, `publish_failures == 0`, and any `WORKLOAD_QUARANTINE_RECEIPT` naming a `refusal_proof_hash` appears strictly after that refusal on a genesis-complete stream.
- **Out-of-Band `kid` Envelope Verification (`CageClient`)**: [`packages/cage-client/`](../packages/cage-client/) verifies `GovernanceEnvelope` signatures (`ES256` on P-256 and `EdDSA` on Ed25519) over RFC 8785 JCS bytes strictly against keys resolved out-of-band by `kid` (`{gateway_url}/governance/.well-known/jwks.json` or caller-pinned PEMs), enforces `expires_at`, and checks `subject.action` + `subject.action_hash`.

#### What Offline Verification Cannot Prove

- **Authentic Runtime Provenance Without Hardware Corroboration**: Because `cage-audit/3.0` link hashes are unkeyed SHA-256 digests, a standalone JSONL file cannot by itself prove that an uncompromised gateway emitted it rather than an offline script. Closing that gap requires verifying the Cloud KMS HSM-signed `cage-evidence-batch/1` WORM attestations alongside independent Cloud KMS `AsymmetricSign` Data Access audit logs (`verify-audit-corroboration` / Path C Phase 5).
- **Live Infrastructure & Mesh Isolation**: Static exports cannot prove that GKE nodes are private, that Linkerd mTLS `Server` and `AuthorizationPolicy` manifests reject unmeshed pod traffic, that GCS WORM retention policies are locked (`is_locked == true`), that Binary Authorization blocks unattested container images, or that `CronJob/lula-audit` is actively polling the cluster.
- **Specification-Lineage Independence**: While `packages/cage-conformance` imports nothing from `src/`, its `model.py` shares a specification lineage with the runtime governor's stage selection; parity between [`proof/model.py`](../proof/model.py) and `src/gateway/governance/governor/` is pinned by [`tests/test_formal_profile_parity.py`](../tests/test_formal_profile_parity.py), [`tests/test_tier_registry_formal_parity.py`](../tests/test_tier_registry_formal_parity.py), and [`tests/test_governance_trace_conformance.py`](../tests/test_governance_trace_conformance.py).

---

### 1b. Path B — Local Docker Compose ([`docker-compose.yml`](../docker-compose.yml) / [`docs/QUICKSTART.md`](QUICKSTART.md))

Path B boots the live Layer 1 gateway (`src/gateway/server/hybrid_server.py`), Open Policy Agent (`opa`), and `noeviction` Redis locally to exercise synchronous policy evaluation, asymmetric JWT routing-seal mint/verify/consume, single-use nonce consumption, CBF/fiscal reservation and settlement, blocking refusal receipts, and live `cage:evidence:stream` emission without cloud credentials or LLM API keys.

#### Exact Commands

```bash
# 1. Configure development posture (.env.example sets CAGE_ENV=dev, CAGE_KMS_PROVIDER=ed25519,
#    CAGE_DOMAIN=finance, CAGE_DEPLOYMENT_REGION=US_FED, CAGE_ALLOW_DEV_LOOPBACK_IDENTITY=true)
cp .env.example .env
docker compose up -d

# 2. Confirm open liveness path succeeds, while unauthenticated or host-spoofed
#    l5d-client-id calls from outside the gateway container fail closed with HTTP 403
curl -fsS http://localhost:8080/health
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/mcp/
# Expected: 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/mcp/ \
  -H "l5d-client-id: cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
# Expected: 403

# 3. Exercise governed MCP discovery, an allowed action (mint -> verify -> consume -> settle),
#    and a policy-blocked action (signed refusal receipt + 64-hex proof_hash) via LT-1 loopback
scripts/compose_gateway_call.sh /mcp/ '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

scripts/compose_gateway_call.sh /tools/execute \
  '{"tool_name":"execute_trade_action","params":{"symbol":"AAPL","amount":250.0,"currency":"USD","confidence":0.99,"transaction_id":"11111111-1111-4111-8111-111111111111","side":"buy"}}'

scripts/compose_gateway_call.sh /tools/execute \
  '{"tool_name":"execute_trade_action","params":{"symbol":"BTC","amount":100.0,"currency":"USD","confidence":0.99,"transaction_id":"33333333-3333-4333-8333-333333333333","side":"buy"}}'

# 4. Export the authoritative Redis DB 1 evidence stream (`cage:evidence:stream`) and
#    verify all 5 stream invariants, RFC 8785 JCS link hashes, threshold baseline, and settlement
docker compose exec -T gateway python -c '
import json, os, redis
r = redis.from_url(
    os.environ.get("REDIS_URL", "redis://redis:6379"),
    db=int(os.environ.get("EVIDENCE_STREAM_REDIS_DB", "1")),
    decode_responses=True,
)
for _, fields in r.xrange("cage:evidence:stream"):
    print(json.dumps(fields))
' | uv run python scripts/check_trace_conformance.py \
      --stream \
      --require-thresholds-loaded \
      --require-settled \
      --expected-refusal-count 1

# 5. Tear down local containers when finished
docker compose down -v
```

#### Reduced-Fidelity Boundaries in Docker Compose

Docker Compose is an application-logic harness, **not** an infrastructure-isolation target. Evaluators must account for five explicit fidelity boundaries:

1. **Software `Ed25519` Signing Instead of Cloud KMS HSM**: Compose sets `CAGE_KMS_PROVIDER=ed25519` under `CAGE_ENV=dev` / `development`, generating an ephemeral in-memory Ed25519 keypair. Enforcing postures (`local`, `staging`, `production` in [`src/gateway/governance/env_posture.py`](../src/gateway/governance/env_posture.py)) reject software keys at startup and require asymmetric Cloud KMS keys (`gcp`, `aws`, or `azure`), CMEK storage encryption, and independent KMS audit logs.
2. **No Linkerd mTLS Mesh or Pod-Local OPA UDS**: Compose runs no Linkerd proxy, SPIFFE workload certificates, Kubernetes `Server` / `AuthorizationPolicy` manifests, or `NetworkPolicy` isolation, and queries `opa` over the internal Compose bridge network (`http://opa:8181`) rather than a pod-local Unix domain socket. [`scripts/compose_gateway_call.sh`](../scripts/compose_gateway_call.sh) uses `docker compose exec` over the dev-only loopback opt-in (`LT-1`: requires both `CAGE_ENV=dev`/`development` and `CAGE_ALLOW_DEV_LOOPBACK_IDENTITY=true`, and is unconditionally refused when `is_enforcing()` is `True` in [`src/gateway/server/workload_identity.py`](../src/gateway/server/workload_identity.py)).
3. **No In-Cluster Lula `v0.16.0` CronJob or Compliance Bridge**: Compose starts only `opa`, `redis`, and `gateway` by default (plus optional `app` under `--profile advisor`), omitting `compliance-bridge`, `CronJob/lula-audit`, ClickHouse/Langfuse sovereign telemetry, and the continuous-monitoring dead-man's switch.
4. **No Retention-Locked WORM Cold Store**: Evidence records remain in ephemeral container Redis (`cage:evidence:stream` on DB `1`) with no `EvidenceCustodian` KMS batch attestation (`cage-evidence-batch/1`), no immutable GCS WORM object retention lock, and no cross-teardown `BOUND_CHAIN_ROTATION`.
5. **Mock Broker Actuation & No Bundled LLM Backend (`USE_MOCK_BROKER=true`)**: Default `docker compose up -d` starts neither `vllm` nor `inference-stub` (`--profile advisor` requires caller-supplied `MODEL_FAST` / `MODEL_REASONING` endpoints), so `/v1/chat/completions` NeMo proxy rails and advisor-side `CageClient` envelope verification are not exercised unless an external model endpoint or client script is attached, and `/tools/execute` dispatches to the in-process mock broker (`USE_MOCK_BROKER=true`).

---

### 1c. Path C — Full GKE Clean-Room Certification ([`scripts/staging_lifecycle.sh`](../scripts/staging_lifecycle.sh) `--fresh-project`)

Path C runs the end-to-end Gate W release-validation harness ([`scripts/staging_lifecycle.sh`](../scripts/staging_lifecycle.sh)) against a disposable GCP project to verify every infrastructure, cryptographic custody, service-mesh, continuous-compliance, and cross-teardown chain-continuity control over the live wire. Reference certification metadata is recorded in [`compliance/gate_w_certification.json`](../compliance/gate_w_certification.json) (note that the committed `fa772122` archive predates the `#732` advisor `cage-client==0.3.0` wheel migration and `#733` Linkerd `all-authenticated` / `:9090` mTLS + GMP absence-alarm hardening until the next `--fresh-project` refresh lands).

#### Prerequisites

- **Disposable Evaluator-Owned `<PROJECT_ID>` and `<BILLING_ACCOUNT>`**: Supply a brand-new or unused `<PROJECT_ID>` that Phase 0 creates and links to `<BILLING_ACCOUNT>` (requires `roles/resourcemanager.projectCreator` and `roles/billing.user`, plus `roles/logging.privateLogViewer` for Phase 5 Cloud KMS Data Access audit-log read-back). Never reuse an existing operated project (see [Section 3](#3-worm-contamination--shared-instance-blast-radius-warning)).
- **`/32`-Authorized Deployer VM (`<VM_NAME>` in `<ZONE>`)**: Run from a Linux x86_64 VM with a static `/32` egress IP (`DEPLOYER_EGRESS_IP` or auto-detected into `TF_VAR_authorized_networks` as `<EGRESS_IP>/32` so private-node GKE `master_authorized_networks` admits `kubectl`, `helm`, and `lula`), equipped with `gcloud`, `terraform`, `kubectl`, `helm`, `jq`, `lula` (`v0.16.0`), and `uv`.
- **Cloud Build Only for GKE Container Images**: Per [`AGENTS.md`](../AGENTS.md#deployment-rules), `deploy_all.sh` builds all GKE images remotely via Google Cloud Build (`deployment/docker/cloudbuild.image.yaml`), pins immutable `@sha256:` digests, and attaches Binary Authorization Grafeas build attestations. Never build GKE images on a local Docker daemon.

#### Exact Invocation Shape

```bash
# Full unskipped clean-room Gate W certification with in-mesh E2E advisor + deterministic inference stub
./scripts/staging_lifecycle.sh \
  --fresh-project=<PROJECT_ID> \
  --billing-account=<BILLING_ACCOUNT> \
  --enable-e2e-advisor \
  --archive-dir=artifacts/gate-w-eval
```

> [!TIP]
> If you do not hold credentials for external third-party partner sandboxes, append `--allow-partner-outage`. All first-party GCP, GKE, KMS, WORM, CAS, Linkerd, Lula, and E2E advisor gates remain strictly fail-closed, while `<archive-dir>/manifest.json` transparently records `"partner_conformance_status": "unreachable_waived"` rather than claiming partner endpoint certification.

#### Phase-by-Phase Read-Back Summary

[`scripts/staging_lifecycle.sh`](../scripts/staging_lifecycle.sh) exports `TF_VAR_startup_grace_hours=0` by default so cold-start grace windows cannot mask compliance failures:

| Phase / Stage | What Executes & Reads Back (Fail-Closed) |
|---|---|
| **Phase 0 (`--fresh-project`)** | Captures `<archive-dir>/pre-run-project-inventory.json` (confirming `project_pre_existed: false` and `0` prior APIs, buckets, or keys for `deployment_target_mode: "fresh_project_clean_room"`), creates `<PROJECT_ID>`, links `<BILLING_ACCOUNT>`, and runs [`scripts/bootstrap_gcp_project.sh`](../scripts/bootstrap_gcp_project.sh) to provision the Terraform state bucket, Cloud KMS keyring/keys, Binary Authorization attestor/note, and WORM buckets. |
| **Phase 1 (Provision & Zero-Drift)** | Runs [`deploy_all.sh`](../deploy_all.sh) (`--target gcp-gke --env staging --auto-approve`) to build images in Cloud Build, sign Binary Authorization attestations, and apply [`infra/targets/gcp-gke/`](../infra/targets/gcp-gke/main.tf), followed immediately by `terraform plan -detailed-exitcode` requiring exit code `0` (zero post-apply drift). |
| **Phase 2 (Workload & Zero-Restart)** | Fetches `cage-staging` credentials in `<ZONE>`, waits up to `600s` for all non-Job pods in `governance-stack` to become `Ready`, dynamically checks every `Deployment` and `StatefulSet` (`readyReplicas >= desired`), confirms `CronJob/lula-audit` is active (`.spec.suspend != true`), and asserts `restartCount == 0` across every container and `initContainer`. |
| **Phase 3 (Host + In-Cluster Lula `v0.16.0`)** | Verifies `startup_grace_active == false` on `GET /v1/metrics/A.5.3`, seeds real governed custody traffic ([`tests/e2e/run_gke_e2e_suite.py`](../tests/e2e/run_gke_e2e_suite.py) `--seed-only`), runs host `lula validate` across every active Kubernetes-domain `compliance/lula/lula-validation-*.yaml` spec (logging `# cage-status: planned` specs to `<archive-dir>/lula/planned-lula-specs.txt`), launches in-cluster `Job/lula-gate-w` from `CronJob/lula-audit` to evaluate internal API-domain specs and verify `/v1/infra/events` `INGESTED` custody receipts, and checks `GET /v1/evidence/verify?require_citable=true` (`ok=true`, `citable=true`, `verified > 0`, `failures=0`, `gaps=0`, `unsigned=0`). |
| **Phase 4 (Regional Posture & Residency)** | Executes `us_fed`, `eu_ecb`, and `apac_mas` regional suites (requiring `passed >= 1` per run), runs live GCP data-residency checks ([`tests/infrastructure/test_data_residency.py`](../tests/infrastructure/test_data_residency.py) `--run-integration`), and runs [`scripts/verify_langfuse_posture.py`](../scripts/verify_langfuse_posture.py) `--posture staging` across operational and compliance Langfuse instances. |
| **Phase 5 (Live Sweeps, GMP & `AS-6` KMS Audit Logs)** | Runs first-party `live_external` (`-m "live_external and not partner" --run-live-external` with `CAGE_REQUIRE_LIVE_CAS=1`), full `integration` (`-m integration --run-integration`), in-mesh E2E advisor scenarios (`--full-e2e`: 12 checks across Linkerd mTLS, `NetworkPolicy`, and ephemeral operator OIDC HITL JWKS), and `partner_integration` (`-p tests.fixtures.require_live`). Queries Cloud Monitoring `projects.timeSeries.list` for both `prometheus.googleapis.com/cage_event_loop_lag_seconds/histogram` (`gateway`) and `prometheus.googleapis.com/cage_evidence_verified_batches/gauge` (`compliance-bridge`), re-verifies WORM custody, and runs [`scripts/verify_audit_corroboration.py`](../scripts/verify_audit_corroboration.py) (`AS-6`) matching WORM `cage-evidence-batch/1` attestations and per-key caller isolation (`compliance-evidence`, `gateway-seal`, `reconciler-snapshot`) against Cloud KMS `AsymmetricSign` Data Access audit logs. |
| **Phase 6 — Initial Teardown, Stages 4–5 Rebuild & Stage 5b `BOUND_CHAIN_ROTATION`** | Quiesces `CronJob/lula-audit`, `gateway`, and `reconciliation-worker`, flushes final WORM batches, extracts pre-teardown chain anchors via [`scripts/read_worm_chain_anchor.py`](../scripts/read_worm_chain_anchor.py) (`--all-streams` across `cage:evidence:stream` and `cage:evidence:infra:stream`), detaches persistent KMS/BinAuthz/WORM state (`PF8`), and runs `terraform destroy`. Stage 4 re-imports foundational state (`bootstrap_gcp_project.sh --import-state`), Stage 5 rebuilds cleanly (`SKIP_BUILD=true BOOTSTRAP_IMPORT_STATE=true`) with `TF_VAR_evidence_previous_chain_head_hash` and `TF_VAR_evidence_previous_batch_attestation_digest` and verifies zero Terraform drift, and **Stage 5b** seeds post-rebuild custody records, verifies `--require-bound-rotation` (`bound_rotations >= 1`, `verified >= pre_teardown_batches + 1`, `gaps == 0`, cryptographically binding the new genesis record to the pre-teardown chain head and attestation digest), and re-corroborates Cloud KMS `AsymmetricSign` audit logs (`AS-6`). |
| **Stage 6 (`PF9` Zero-Survivor Check)** | Executes final `terraform destroy` and queries `gcloud` across GKE clusters, Cloud SQL instances, GCS buckets, service accounts, Binary Authorization attestors, and Resource Manager liens, failing closed on any unexpected workload survivor while recording retained-by-design foundational/WORM artifacts in `<archive-dir>/post-destroy-project-inventory.json`. |

#### Archive Directory Layout (`--archive-dir`)

Every run populates a self-contained audit bundle under `<archive-dir>`:

- `<archive-dir>/manifest.json` — Top-level verdict (`overall_status`, `full_unskipped_gate_w`, `deployment_target_mode`, `phase_failures`, `drift_read_back_scope`, `lula`, `pytest_suites`, `partner_conformance_status`, and `worm_continuity` including `post_rebuild_bound_rotation_verified`).
- `<archive-dir>/pre-run-project-inventory.json` and `<archive-dir>/post-destroy-project-inventory.json` — Pre-Phase-0 cleanliness proof and Stage 6 `PF9` survivor inventory.
- `<archive-dir>/pytest-suites.jsonl` and `<archive-dir>/e2e-advisor-summary.json` — Per-suite `collected`, `passed`, `skipped`, `deselected`, and `failed` counts plus E2E advisor scenario results.
- `<archive-dir>/lula/` — Host OSCAL outputs (`assessment-results-*.yaml`), in-cluster auditor log (`<archive-dir>/lula/job-lula-gate-w.log`), `<archive-dir>/lula/planned-lula-specs.txt`, and `<archive-dir>/lula/pre-lula-custody-seed.json`.
- `<archive-dir>/worm/` and `<archive-dir>/post-rebuild-custody-seed.json` — Raw `/v1/evidence/verify` payloads from Phase 3, Phase 5, pre-teardown quiescence, and Stage 5b cross-teardown `BOUND_CHAIN_ROTATION`.
- `<archive-dir>/audit-corroboration-phase5.json` and `<archive-dir>/audit-corroboration-stage5b.json` — `AS-6` Cloud KMS `AsymmetricSign` audit-log corroboration reports before and after cluster rebuild.

---

### 1d. Understanding Local `pytest` Output: Live-Suite Selection & Skip Banner

When an evaluator runs `make test-fast` (`uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -q` in [`Makefile`](../Makefile)), CAGE intentionally runs only hermetic offline tests and prints an explicit notice listing every live suite that did not execute.

1. **Fail-Closed Selection-Marker Contract**: `_assert_selection_markers()` in [`tests/conftest.py`](../tests/conftest.py) requires every collected test to carry at least one marker from `SELECTION_MARKERS` (`unit`, `local`, `integration`, `load`, `chaos`, `live_external`, `partner_integration`, `e2e`; `MARKER_GUARD_EXEMPT_MODULES` is empty). Any unmarked test aborts collection with `PYTEST MARKER CONTRACT VIOLATION` so tests cannot silently vanish from CI gates. Hermetic sessions also run `_refuse_reachable_dotenv()` ([`tests/fixtures/dotenv_guard.py`](../tests/fixtures/dotenv_guard.py)) and abort if a `.env` file is reachable on disk, preventing ambient stack credentials from altering offline test behavior.
2. **Why `make test-fast` Skips Live Suites — and How `pytest_terminal_summary` Surfaces Them**: Suites marked `integration`, `live_external`, `partner_integration`, `e2e`, or `chaos` require live Kubernetes services, Cloud KMS/WORM/CAS APIs, external partner sandboxes, or Redis failover injection. `make test-fast` deselects them via `-m "local or unit"`, and when pytest is invoked without `-m`, `pytest_collection_modifyitems()` in [`tests/conftest.py`](../tests/conftest.py) auto-skips them unless their opt-in CLI flag (`--run-integration`, `--run-live-external`, `--run-partner-integration`, `--run-e2e`, `--run-chaos`) is supplied. To prevent a green hermetic unit run from being misread as live infrastructure validation, `pytest_deselected()` and `pytest_terminal_summary()` (via `format_unexecuted_live_suites_notice()` in [`tests/conftest.py`](../tests/conftest.py)) emit a controller-level banner at the end of the session:
   ```text
   --- live / opt-in suites not executed ---
     [NOT EXECUTED] @integration: <N> deselected — pass --run-integration against a live target to execute
     [NOT EXECUTED] @live_external: <N> deselected — pass --run-live-external against a live target to execute
     [NOT EXECUTED] @partner_integration: <N> deselected — pass --run-partner-integration against a live target to execute
     [NOT EXECUTED] @e2e: <N> deselected — pass --run-e2e against a live target to execute
     [NOT EXECUTED] @chaos: <N> deselected — pass --run-chaos against a live target to execute
   ```
3. **Preventing Vacuous Zero-Executed Passes (`tests/fixtures/require_live.py`)**: Standard `pytest` exits `0` when all selected tests call `pytest.skip(...)` (for instance, when credentials or endpoints are missing even after passing `--run-partner-integration`). Loading `-p tests.fixtures.require_live` ([`tests/fixtures/require_live.py`](../tests/fixtures/require_live.py)) registers the `RequireLive` plugin, which records every skipped or `xfail` item during the session and forces `session.exitstatus = pytest.ExitCode.TESTS_FAILED` in `pytest_sessionfinish`, printing `FAILED: every selected test must run` under a `=== require-live ===` summary section. Complementing this plugin, `run_pytest_require_passed` in [`scripts/staging_lifecycle.sh`](../scripts/staging_lifecycle.sh) parses every suite's terminal counts into `<archive-dir>/pytest-suites.jsonl` and fails closed whenever `passed < 1`.

---

## 2. Verification Coverage Matrix

Each cell below is graded conservatively (`Exercised`, `Partial (...)`, or `Not exercised`) so evaluators know exactly which evaluation tier validates each security and governance property over real primitives versus software/offline substitutes.

| Security / Governance Property | Primary Code & Test Anchors | Offline Conformance | Local Docker Compose | GKE `--fresh-project` (Gate W) |
|---|---|---|---|---|
| **`GovernanceEnvelope` signing & out-of-band `kid` verification** | [`governance_envelope.py`](../src/gateway/governance/governance_envelope.py), [`routing_seal.py`](../src/gateway/governance/routing_seal.py), [`jwks.py`](../packages/cage-client/src/cage_client/jwks.py), [`crypto.py`](../packages/cage-client/src/cage_client/crypto.py) | **Partial** (verifies exported `ES256`/`EdDSA` signatures over RFC 8785 JCS bytes against pinned PEMs via [`core.py`](../packages/cage-client/src/cage_client/core.py); live `/governance/jwks` requires `--endpoint --profile substrate-v1`) | **Partial** (live `{gateway_url}/governance/.well-known/jwks.json` `kid` resolution and single-use nonce consumption, but signed with dev-only in-memory `Ed25519` rather than Cloud KMS, and default `docker compose up -d` omits the `cage-client` advisor consumer unless `--profile advisor` + model endpoints are supplied) | **Exercised** (`ES256` backed by Cloud KMS `gateway-seal` HSM P-256 key in [`kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf) + live JWKS `kid` resolution via `--enable-e2e-advisor` in [`run_gke_e2e_suite.py`](../tests/e2e/run_gke_e2e_suite.py); note committed `fa772122` archive predates `#732` wheel migration) |
| **Blocking refusal & deferral receipts** | [`decisions.py`](../src/gateway/governance/decisions.py), [`stream.py`](../src/gateway/governance/evidence/stream.py), [`defer_queue.py`](../src/gateway/governance/defer_queue.py) | **Partial** (`INV-5` in [`stream_invariants.py`](../proof/stream_invariants.py) checks 64-hex `proof_hash`, `--expected-refusal-hash`, `--expected-refusal-count`, and `publish_failures == 0` on exported JSONL; no live Redis blocking failure path) | **Exercised** (`EVIDENCE_CHAIN_BLOCKING=true` commits refusal and deferral records synchronously to container Redis DB `1` before returning `proof_hash`) | **Exercised** (`EVIDENCE_CHAIN_BLOCKING=true` on AOF-persisted Memorystore Valkey + KMS-signed WORM custody in [`evidence_custodian.py`](../src/compliance_bridge/evidence_custodian.py)) |
| **`INV-1`–`INV-5` stream invariants & `cage-audit/3.0` chain** | [`stream_invariants.py`](../proof/stream_invariants.py), [`check_trace_conformance.py`](../scripts/check_trace_conformance.py), [`test_stream_invariants_oracle.py`](../tests/test_stream_invariants_oracle.py) | **Exercised** (stdlib-only RFC 8785 JCS SHA-256 link hashes, contiguous sequences, `digest_format`, and all five invariants `INV-1`–`INV-5` over exported JSONL) | **Exercised** (live `cage:evidence:stream` emission verified end-to-end via `scripts/check_trace_conformance.py --stream --require-thresholds-loaded --require-settled`) | **Exercised** (live emission + in-cluster `CustodyVerifier` in [`evidence_verifier.py`](../src/compliance_bridge/evidence_verifier.py) + Phase 5 [`run_gke_e2e_suite.py`](../tests/e2e/run_gke_e2e_suite.py) conformance) |
| **OPA policy evaluation over pod-local UDS** | [`opa.py`](../src/gateway/governance/governor/stages/opa.py), [`infra/modules/opa_policy/main.tf`](../infra/modules/opa_policy/main.tf), [`lula-validation-sc4.yaml`](../compliance/lula/lula-validation-sc4.yaml) | **Partial** (`INV-3` verifies that the `opa` stage was planned and recorded `PASS` in `GOVERNANCE_DECISION`, not live Rego evaluation or UDS transport) | **Partial** (evaluates real domain Rego in `openpolicyagent/opa:0.70.0-static`, but over internal Compose HTTP `http://opa:8181` rather than a Unix domain socket) | **Exercised** (read-only Rego ConfigMaps mounted into the gateway pod's OPA sidecar over pod-local UDS `module.opa.uds_url`, verified in Phase 3 Lula `sc4`/`ac3` and Phase 5 E2E) |
| **CBF & fiscal pre-reservation barriers** | [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py), [`debit_ledger.py`](../src/gateway/governance/safety/debit_ledger.py), [`fiscal_limit_guard.py`](../src/cage_finance/safety/fiscal_limit_guard.py) | **Partial** (`INV-2` and `INV-4` verify `CBF_COMMIT`, `CBF_ROLLBACK`, and `GOVERNANCE_SETTLEMENT` forward invariance on exported streams, plus formal BFS in [`distributed_cbf_model.py`](../proof/distributed_cbf_model.py); no live Redis Lua atomicity) | **Partial** (executes atomic Lua pre-reservation, CBF commit, and rollback on single-node container Redis with `0` replicas and `USE_MOCK_BROKER=true`; no `WAIT` replication or KMS-signed `reconciler-snapshot`) | **Partial** (TLS/IAM Memorystore Valkey with `replica_count = 1` for `WAIT 1` replication and `reconciliation-worker` KMS `reconciler-snapshot` signing; default ledger feed uses `_DefaultSimulatedProvider` per `POAM-2026-096` and broker actuation uses `USE_MOCK_BROKER` in staging) |
| **Human OIDC + WebAuthn HITL quorum & `POST_HITL` revalidation** | [`defer_queue.py`](../src/gateway/governance/defer_queue.py), [`oidc_verifier.py`](../src/compliance_bridge/oidc_verifier.py), [`src/compliance_bridge/main.py`](../src/compliance_bridge/main.py) | **Not exercised** (requires live `DeferQueue` state, out-of-band operator JWKS verification, and `revalidate_post_hitl()`; covered offline only in hermetic unit tests) | **Not exercised** ([`docker-compose.yml`](../docker-compose.yml) omits `compliance-bridge` and runs `CAGE_ENV=dev`, where `WEBAUTHN_BINDING_REQUIRED` is inactive) | **Partial** (`--enable-e2e-advisor` exercises live distinct-principal OIDC JWT quorum via ephemeral out-of-band `kid` JWKS, mandatory W3C `webauthn.get` challenge binding, and single-use `POST_HITL` drift revalidation in [`run_gke_e2e_suite.py`](../tests/e2e/run_gke_e2e_suite.py); uses ephemeral test keys rather than a corporate IdP + hardware FIDO2 token) |
| **Cloud KMS asymmetric key custody & CMEK** | [`kms_signer.py`](../src/gateway/governance/kms_signer.py), [`kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf), [`infra/modules/kms/main.tf`](../infra/modules/kms/main.tf), [`infra/modules/evidence_domain/main.tf`](../infra/modules/evidence_domain/main.tf) | **Not exercised** (checks public-key signatures and exported logs, not live HSM custody or CMEK disk/bucket encryption) | **Not exercised** (uses in-memory software `Ed25519` via `CAGE_KMS_PROVIDER=ed25519` and unencrypted local container storage) | **Exercised** (per-workload `EC_SIGN_P256_SHA256` HSM keys `gateway-seal`, `compliance-evidence`, `reconciler-snapshot`, `binauthz-attestor` with authoritative per-key IAM policies + HSM CMEK across GKE, Cloud SQL, Memorystore, and WORM buckets; automated signing-key rotation remains open under `POAM-2026-012`) |
| **Retention-locked WORM & cross-teardown `BOUND_CHAIN_ROTATION`** | [`evidence_custodian.py`](../src/compliance_bridge/evidence_custodian.py), [`evidence_verifier.py`](../src/compliance_bridge/evidence_verifier.py), [`infra/modules/worm_bucket/main.tf`](../infra/modules/worm_bucket/main.tf), [`read_worm_chain_anchor.py`](../scripts/read_worm_chain_anchor.py) | **Not exercised** (verifies single-stream JSONL exports; cannot test GCS `is_locked = true` retention policies or cluster rebuild continuity) | **Not exercised** (no `compliance-bridge` custodian or GCS WORM bucket) | **Partial** (Phase 3/5 and Stage 5b exercise `is_locked = true` WORM `put_if_absent`, KMS-signed `cage-evidence-batch/1` attestations, `/v1/evidence/verify?require_citable=true`, and cross-teardown `BOUND_CHAIN_ROTATION` across `cage:evidence:stream` and `cage:evidence:infra:stream` under the `86400s` 1-day staging lock; the `220752000s` 2,555-day lock and separate `<PROJECT_ID>-evidence` project isolation apply in `prod`, `POAM-2026-084`) |
| **Linkerd mTLS & `AuthorizationPolicy` / `NetworkPolicy`** | [`workload_identity.py`](../src/gateway/server/workload_identity.py), [`infra/modules/service_mesh/main.tf`](../infra/modules/service_mesh/main.tf), [`mesh_policy.tf`](../infra/targets/gcp-gke/mesh_policy.tf), [`network_policy.tf`](../infra/targets/gcp-gke/network_policy.tf), [`test_linkerd_mesh_conformance.py`](../tests/integration/test_linkerd_mesh_conformance.py) | **Not exercised** | **Partial** (`WorkloadIdentityMiddleware` rejects missing or host-forged `l5d-client-id` headers with HTTP `403`, but uses dev-only `LT-1` container loopback rather than Linkerd mTLS or `NetworkPolicy`) | **Partial** (Google CAS-anchored Linkerd mTLS with `proxy_required_namespaces`, `defaultInboundPolicy = "all-authenticated"`, meshed `:9090`/`4191` `Server` policies, pod-IP-only `l5d-client-id` trust, and GKE Dataplane V2 `NetworkPolicy`; `POAM-2026-007` / `POAM-2026-080` / `POAM-2026-195` remain open pending post-`#733` `--fresh-project` GMP scrape certification) |
| **In-cluster Lula `v0.16.0` continuous auditing & dead-man's switch** | [`infra/modules/lula_cron/main.tf`](../infra/modules/lula_cron/main.tf), [`lula_alerting.tf`](../infra/targets/gcp-gke/lula_alerting.tf), [`sla_monitor.py`](../src/compliance_bridge/sla_monitor.py), [`compliance/lula/README.md`](../compliance/lula/README.md) | **Not exercised** | **Not exercised** | **Partial** (Phase 2 verifies active `CronJob/lula-audit` and `1800s` `2 x schedule` dead-man alert policies; Phase 3 evaluates `26/26` active Lula `v0.16.0` specs — `22` host Kubernetes-domain + `4` in-cluster `Job/lula-gate-w` API-domain — under `startup_grace_hours=0` with `/v1/infra/events` WORM custody; `7` planned/adopter-operated specs and `5` AI 600-1 stubs remain tracked in [`compliance/lula/README.md`](../compliance/lula/README.md)) |
| **GMP Prometheus metrics & KMS Cloud Audit Log corroboration (`AS-6`)** | [`monitors.yaml`](../infra/modules/gateway/metrics-monitors/templates/monitors.yaml), [`metrics_alerting.tf`](../infra/targets/gcp-gke/metrics_alerting.tf), [`lula-validation-metrics.yaml`](../compliance/lula/lula-validation-metrics.yaml), [`verify_audit_corroboration.py`](../scripts/verify_audit_corroboration.py) | **Partial** (`cage-conformance verify-audit-corroboration` corroborates exported `cage-evidence-batch/1` attestations and per-key caller isolation against exported Cloud Audit Log JSONL; no live GMP or Cloud Logging API query) | **Partial** (`GET /metrics` exposes Prometheus counters on `gateway`, but no GMP `PodMonitoring` collector, absence alarm, or Cloud KMS audit logs exist) | **Exercised** (Phase 5 queries Cloud Monitoring `projects.timeSeries.list` for both `prometheus.googleapis.com/cage_event_loop_lag_seconds/histogram` and `prometheus.googleapis.com/cage_evidence_verified_batches/gauge` and runs [`verify_audit_corroboration.py`](../scripts/verify_audit_corroboration.py) in Phase 5 and Stage 5b against live Cloud KMS `AsymmetricSign` Data Access logs) |
| **Binary Authorization container admission** | [`perimeter.tf`](../infra/targets/gcp-gke/perimeter.tf), [`kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf), [`infra/modules/gcp_gke_cluster/main.tf`](../infra/modules/gcp_gke_cluster/main.tf) | **Not exercised** | **Not exercised** | **Partial** (`enable_binary_authorization = true` configures `REQUIRE_ATTESTATION` / `ENFORCED_BLOCK_AND_AUDIT_LOG` in [`perimeter.tf`](../infra/targets/gcp-gke/perimeter.tf) and admits Cloud Build `binauthz-attestor`-attested images across Phase 1 and Stage 5; Gate W runs positive admission only, with no negative unattested-pod rejection probe, and whitelists GKE/Linkerd/cert-manager registries by pattern) |
| **Multi-turn LLM inference proxy & NeMo rails** | [`inference_proxy.py`](../src/gateway/server/inference_proxy.py), [`nemo_node_factory.py`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py), [`redactor.py`](../src/integrations/presidio/redactor.py) | **Not exercised** | **Not exercised** (default `docker compose up -d` starts no `vllm` or `inference-stub`, so `/v1/chat/completions` is unexercised unless an external OpenAI-compatible backend is wired) | **Partial** (`--enable-e2e-advisor` exercises `/v1/chat/completions` over the deterministic CPU `inference-stub` rather than GPU `vllm` weights; open multi-turn NeMo input-history and `choices[1:]` PII scrubbing gaps are tracked in [`docs/POAM.md`](POAM.md)) |
| **Regional `US_FED` / `EU_ECB` / `APAC_MAS` isolation** | [`constants.py`](../src/gateway/governance/constants.py), [`thresholds.py`](../src/gateway/governance/schemas/thresholds.py), [`test_data_residency.py`](../tests/infrastructure/test_data_residency.py), [`lula-validation-eu-fria.yaml`](../compliance/lula/lula-validation-eu-fria.yaml) | **Partial** (`--expected-thresholds-digest` binds an exported stream to a regional `config/thresholds/<REGION>_BASELINE.json` digest; does not verify cloud resource placement) | **Partial** (`CAGE_DEPLOYMENT_REGION` switches `ControlRegistry` and threshold baselines in-process across `US_FED`, `EU_ECB`, and `APAC_MAS`; no cloud residency enforcement) | **Partial** (Phase 4 runs `us_fed`, `eu_ecb`, and `apac_mas` suites plus live GCP residency checks in [`test_data_residency.py`](../tests/infrastructure/test_data_residency.py) for the deployed region — `US_FED` / `us-central1` by default — while Terraform preconditions enforce `europe-*` for `EU_ECB` and `asia-*` for `APAC_MAS`; live GKE residency in `europe-*` or `asia-*` requires separate regional Gate W runs) |

---

## 3. WORM Contamination & Shared-Instance Blast-Radius Warning

> [!WARNING]
> **Never run adversarial, red-team, load, or integration probes against an existing operated or shared staging cluster, and never reuse an operated cluster's WORM buckets.** Always run live GKE evaluations inside a dedicated, disposable Google Cloud project (`./scripts/staging_lifecycle.sh --fresh-project=<PROJECT_ID>`). Probing a shared cluster permanently contaminates retention-locked compliance archives that cannot be deleted even by a project owner until lock expiry, and exhausts fail-closed stateful budgets for all other callers.

### 3a. Irreversible Retention-Locked WORM Buckets & Deletion Liens

In [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf) (`local.retention_period_seconds` and `local.retention_locked`) and [`infra/modules/evidence_domain/variables.tf`](../infra/modules/evidence_domain/variables.tf), CAGE locks Google Cloud Storage retention policies (`is_locked = true`) across every enforcing posture (`staging`, `prod`, and `dev` with `enforce_in_dev = true`):

| Environment Tier | `retention_period_seconds` | Human Duration | `is_locked` | Affected Buckets & KMS Custody Guards |
|---|---|---|---|---|
| **`staging`** | `86400` | `1` day (`24` hours) | `true` (irreversible) | `<PROJECT_ID>-evidence-worm-staging` ([`infra/modules/worm_bucket/main.tf`](../infra/modules/worm_bucket/main.tf)), `<PROJECT_ID>-audit-logs-worm-staging` ([`infra/modules/evidence_domain/main.tf`](../infra/modules/evidence_domain/main.tf)), and `langfuse-event-upload-<PROJECT_ID>-<hex>` ([`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf)) |
| **`prod`** (and [`evidence_domain/variables.tf`](../infra/modules/evidence_domain/variables.tf) default) | `220752000` | `2,555` days (`7` years) | `true` (irreversible) | `<EVIDENCE_PROJECT_ID>-evidence-worm-prod`, `<EVIDENCE_PROJECT_ID>-audit-logs-worm-prod`, and `langfuse-event-upload-<PROJECT_ID>-<hex>`; encrypted with `google_kms_crypto_key.evidence_cmek` (`destroy_scheduled_duration = "10368000s"` / `120` days in [`infra/modules/evidence_domain/main.tf`](../infra/modules/evidence_domain/main.tf)) |
| **`dev`** (`enforce_in_dev = false`) | `220752000` | `2,555` days (`7` years) | `false` (unless `enforce_in_dev = true`) | Unlocked in non-enforcing `dev` (`force_destroy = true`); irreversibly locked for `2,555` days if `enforce_in_dev = true` is ever applied |

Once `is_locked = true` is committed, Google Cloud Storage refuses every attempt to shorten `retention_period`, remove the policy, overwrite an object, or delete a bucket containing unexpired objects, and places an `origin: storage.googleapis.com` deletion lien on the GCP project (`PF9` in [`scripts/staging_lifecycle.sh`](../scripts/staging_lifecycle.sh)). Even a `1`-day `staging` lock prevents immediate project deletion for `24` hours after the last write; accidental `prod` or `enforce_in_dev = true` writes lock objects and project liens for `7` years.

### 3b. Permanent Hash-Chain & Cross-Teardown `BOUND_CHAIN_ROTATION` Contamination

Refusals and fault injections are not ephemeral log lines in CAGE — they are primary evidentiary records:

- Every governed `ALLOW`, `NARROW`, `DENY`, `DEFER`, `REQUIRE_APPROVAL`, `WORKLOAD_QUARANTINE_RECEIPT`, and `STATE_COMMITMENT` appends a `cage-audit/3.0` link onto `cage:evidence:stream` ([`src/gateway/governance/evidence/stream.py`](../src/gateway/governance/evidence/stream.py)), which `EvidenceCustodian` ([`src/compliance_bridge/evidence_custodian.py`](../src/compliance_bridge/evidence_custodian.py)) signs with `EVIDENCE_KMS_KEY` (`compliance-evidence`) and writes via `put_if_absent` into the WORM bucket alongside Cloud KMS `AsymmetricSign` Data Access audit logs.
- Adversarial or uncoordinated test runs against an operated cluster permanently interleave synthetic records into the production/staging SHA-256 chain and mutate the terminal `previous_chain_head_hash` and `previous_batch_attestation_digest` anchors read by [`scripts/read_worm_chain_anchor.py`](../scripts/read_worm_chain_anchor.py), invalidating expected cross-teardown `BOUND_CHAIN_ROTATION` proofs (`POAM-2026-084`).
- Attempting to "clean up" test records by deleting or trimming Redis stream entries on a live cluster triggers `EvidenceChainCorruptError` in [`src/gateway/governance/evidence/stream.py`](../src/gateway/governance/evidence/stream.py) (halting all subsequent seal issuance fail-closed) and causes `CustodyVerifier` ([`src/compliance_bridge/evidence_verifier.py`](../src/compliance_bridge/evidence_verifier.py)) to flag permanent sequence gaps (`gaps > 0`, `citable = false`) on `GET /v1/evidence/verify`.

### 3c. Exhaustible Stateful Pools & Fail-Closed Circuit Breakers

Shared CAGE deployments maintain bounded, fail-closed state in `noeviction` Memorystore Valkey / Redis and LangGraph session state that adversarial testing will intentionally trip:

- **`DeferQueue` Capacity on `noeviction` Redis DB `1` ([`src/gateway/governance/defer_queue.py`](../src/gateway/governance/defer_queue.py))**: Pending `DEFER` and `REQUIRE_APPROVAL` tickets persist as `DEFER:{defer_id}` hashes and `DEFER:expiry_index` sorted-set entries (`_DEFAULT_TTL = 14400` seconds / `4` hours) on Redis DB `1` (`maxmemory-policy noeviction`), sharing memory with `cage:evidence:stream` (`EVIDENCE_STREAM_MAX_LEN = 100000`). Flooding a shared instance with low- or medium-confidence requests saturates operator HITL queues and `noeviction` memory, causing subsequent writes to fail closed.
- **Single-Use Nonce & Execution-Idempotency Pools ([`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py), [`src/gateway/infrastructure/redis_single_use.py`](../src/gateway/infrastructure/redis_single_use.py), [`src/gateway/governance/execution_idempotency.py`](../src/gateway/governance/execution_idempotency.py))**: Routing seals (`GOVERNANCE_SEAL_TTL_S = 30` seconds default) and caller `transaction_id` keys consume atomic `SET NX` single-use markers in `noeviction` Redis; replaying static fixture `transaction_id` values collides with prior runs, and high-concurrency tunnel sweeps (`-n auto`) exhaust port-forward TCP and `BlockingConnectionPool` slots.
- **`MAX_CONSECUTIVE_DENIALS` Halts & Shared Scalar Budgets ([`src/governed_financial_advisor/graph/nodes/safety_node.py`](../src/governed_financial_advisor/graph/nodes/safety_node.py), [`src/governed_financial_advisor/graph/nodes/explainer_node.py`](../src/governed_financial_advisor/graph/nodes/explainer_node.py))**: Policy-probing mitigation halts an agent session once `consecutive_denials >= MAX_CONSECUTIVE_DENIALS` (`2`), while CBF scalar state (`safety:current_cash` in [`src/gateway/governance/safety/cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py)), daily fiscal caps ([`src/cage_finance/safety/fiscal_limit_guard.py`](../src/cage_finance/safety/fiscal_limit_guard.py)), GCRA rate limits ([`src/gateway/server/rate_limit.py`](../src/gateway/server/rate_limit.py)), and token quotas ([`src/gateway/governance/token_quota_proxy.py`](../src/gateway/governance/token_quota_proxy.py)) are shared runtime budgets that red-team traffic depletes for co-tenant workloads.

---

## 4. Adversarial Review Scope Statement

External security reviewers and bug-bounty / red-team assessors should use the boundary below to separate actionable governance or security bypasses (**In Scope**) from declared reference-architecture boundaries and non-production stubs (**Out of Scope**). Known open gaps are tracked transparently in [`docs/POAM.md`](POAM.md).

### 4a. In Scope (Valid Security & Governance Targets)

1. **Layer 1 Kernel Admissibility & Stage Mediation**: Any bypass of `assemble_governor()` ([`src/gateway/governance/governor/assembly.py`](../src/gateway/governance/governor/assembly.py)) or `run_pipeline()` ([`src/gateway/governance/governor/pipeline.py`](../src/gateway/governance/governor/pipeline.py)); any execution path that violates formal stage reachability or `NARROW` clamped re-verification in [`proof/model.py`](../proof/model.py); any upward import or domain/vendor leakage breaking [`scripts/check_import_boundaries.py`](../scripts/check_import_boundaries.py); or any unclassified or malformed tool call that fails open past FTRA ([`src/gateway/governance/ftra/`](../src/gateway/governance/ftra/)), STPA ([`src/gateway/governance/stpa_validator.py`](../src/gateway/governance/stpa_validator.py)), OPA ([`src/gateway/governance/governor/stages/opa.py`](../src/gateway/governance/governor/stages/opa.py)), CBF ([`src/gateway/governance/safety/cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py)), or fiscal pre-reservation ([`src/cage_finance/safety/fiscal_limit_guard.py`](../src/cage_finance/safety/fiscal_limit_guard.py)).
2. **Out-of-Band `kid` Trust-Anchor Resolution**: Any verifier across [`packages/cage-client/`](../packages/cage-client/), [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py), [`src/compliance_bridge/oidc_verifier.py`](../src/compliance_bridge/oidc_verifier.py), [`src/compliance_bridge/evidence_verifier.py`](../src/compliance_bridge/evidence_verifier.py), or [`src/integrations/trust/key_manifest.py`](../src/integrations/trust/key_manifest.py) that trusts an embedded key header (`jwk`, `jku`, `x5c`, `x5u`), permits symmetric/asymmetric algorithm confusion, or fails open on an unknown or expired `kid`.
3. **Routing-Seal Single-Use & Replay Resistance**: Any domain tool actuation bypassing `verify_and_consume_seal()` ([`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py)) and `ActuatorRegistry` ([`src/gateway/governance/execution_actuator.py`](../src/gateway/governance/execution_actuator.py)); replay or double-spend of a routing seal, `ConsequenceToken` ([`src/gateway/governance/consequence_gateway.py`](../src/gateway/governance/consequence_gateway.py)), or `CBF_COMMIT` rollback; or public state mutation bypassing private `_resolve()`, distinct-principal OIDC + enforcing-posture WebAuthn challenge verification, or single-use `POST_HITL` drift revalidation in [`src/gateway/governance/defer_queue.py`](../src/gateway/governance/defer_queue.py).
4. **WORM / Cloud KMS Evidence Chain & Custody Verification**: Any hash-chain forgery, silent record drop on refusal/deferral, replica chain fork, or canonicalization mismatch on `cage:evidence:stream` ([`src/gateway/governance/evidence/stream.py`](../src/gateway/governance/evidence/stream.py)) that escapes [`proof/stream_invariants.py`](../proof/stream_invariants.py) or `CustodyVerifier` ([`src/compliance_bridge/evidence_verifier.py`](../src/compliance_bridge/evidence_verifier.py)); seal issuance when `EVIDENCE_CHAIN_BLOCKING=true` and commit fails; forged cross-teardown `BOUND_CHAIN_ROTATION` headers; or per-workload Cloud KMS signing-key / IAM boundary violations ([`infra/targets/gcp-gke/kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf), [`scripts/verify_audit_corroboration.py`](../scripts/verify_audit_corroboration.py)).
5. **Linkerd mTLS & `NetworkPolicy` Pod Isolation**: Forging `l5d-client-id` over loopback (`127.0.0.1` / `::1`) or from unmeshed peers in enforcing postures ([`src/gateway/server/workload_identity.py`](../src/gateway/server/workload_identity.py), [`src/compliance_bridge/auth.py`](../src/compliance_bridge/auth.py)); bypassing GKE Dataplane V2 L3/L4 policies in [`infra/targets/gcp-gke/network_policy.tf`](../infra/targets/gcp-gke/network_policy.tf) (for example, reaching the gateway's UDS-only OPA sidecar over the network or reaching `vllm` directly from `governed-financial-advisor`); or scheduling unmeshed pods into `governance-stack` (`proxy_required_namespaces` in [`infra/modules/service_mesh/main.tf`](../infra/modules/service_mesh/main.tf)), beyond the open items already disclosed in [`docs/POAM.md`](POAM.md) (`POAM-2026-007`, `POAM-2026-080`, `POAM-2026-195`).
6. **Fail-Closed Startup & Terraform Plan-Time Posture Guards**: Any enforcing posture (`local`, `staging`, `production` in [`src/gateway/governance/env_posture.py`](../src/gateway/governance/env_posture.py) or `local.enforcing_posture` in [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf)) that accepts software signing keys (`ed25519` / HMAC), dev loopback identity (`LT-1`), disabled `CageClient` verification, `/0` control-plane CIDRs (`control_plane_access_guard`), empty or shared compliance telemetry keys (`poam_019_empty_key_guard`, `poam_019_shared_key_guard`), cross-region WORM bucket placement, or standalone Terraform guards skipped under targeted plans ([`tests/infrastructure/test_guard_placement.py`](../tests/infrastructure/test_guard_placement.py)).

### 4b. Out of Scope / Declared Reference Boundaries

1. **Unoperated Reference Architecture (Not a Live SaaS)**: CAGE is open-source reference infrastructure rather than a Google-operated cloud service ([`AGENTS.md`](../AGENTS.md), [`SECURITY.md`](../SECURITY.md)). Reports assuming a live multi-tenant vendor SaaS, hosted control plane, or production customer data store are out of scope.
2. **Declared Non-Production Domain Stubs (`cage_healthcare` and `cage_physical_ai`)**: `finance` ([`src/cage_finance/`](../src/cage_finance/)) is the sole finalized, production-eligible domain plugin (`POAM-2026-076`–`078`, `POAM-2026-198` in [`docs/POAM.md`](POAM.md)). Both [`src/cage_healthcare/`](../src/cage_healthcare/) and [`src/cage_physical_ai/`](../src/cage_physical_ai/) declare stub maturity and are mechanically blocked from assembling in enforcing postures (`staging`, `production`, `local`) by [`src/gateway/governance/governor/assembly.py`](../src/gateway/governance/governor/assembly.py) and [`src/gateway/governance/contracts.py`](../src/gateway/governance/contracts.py) (with `physical_ai` also lacking a `DomainConfig` / `.rego` bundle and blocked at plan time by `terraform_data.domain_opa_policies_guard` in [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf)). Missing clinical or kinematic domain rules inside those stubs are out of scope; only a bypass allowing a stub plugin to run in an enforcing posture is in scope.
3. **Declared `adopter-operated` Regional Controls & `planned` Compliance Specs**: Seven of the 33 Lula manifests in [`compliance/lula/README.md`](../compliance/lula/README.md) are explicitly non-active in standalone CAGE Gate W runs (`26` active + `7` planned/not-applicable) and are not claimed as implemented software controls:
   - **5 `adopter-operated` (`# cage-status: not-applicable`) institutional controls** outside the standalone software boundary (illustrative templates for deploying institutions): EU AI Act Art. 9 organizational risk register ([`lula-validation-eu-ai-act-art9.yaml`](../compliance/lula/lula-validation-eu-ai-act-art9.yaml)), DORA Art. 10 enterprise SIEM/SOC incident classification ([`lula-validation-dora-art10.yaml`](../compliance/lula/lula-validation-dora-art10.yaml)), MAS FEAT demographic fairness sign-off ([`lula-validation-mas-feat.yaml`](../compliance/lula/lula-validation-mas-feat.yaml)), MAS Notice 655 enterprise RTO & 1-hour notification ([`lula-validation-mas-notice655.yaml`](../compliance/lula/lula-validation-mas-notice655.yaml)), and MAS TRM §6.3 enterprise MRM inventory ([`lula-validation-mas-trm-s6.yaml`](../compliance/lula/lula-validation-mas-trm-s6.yaml)).
   - **`planned` `EU-006` GDPR Art. 22(3) subject-initiated contestation intake** ([`docs/compliance/eu_ecb/POAM_EU_ECB.md`](compliance/eu_ecb/POAM_EU_ECB.md), [`lula-validation-gdpr-art22.yaml`](../compliance/lula/lula-validation-gdpr-art22.yaml)): runtime `REQUIRE_APPROVAL` human dual-control quorum is active, whereas external data-subject contestation intake and `GET /v1/compliance/gdpr/art22` are declared `planned` work.
   - **`planned` `RA-5` in-cluster vulnerability-scanning CronJob** (`POAM-2026-010` in [`docs/POAM.md`](POAM.md), [`lula-validation-ra5.yaml`](../compliance/lula/lula-validation-ra5.yaml)): vulnerability scanning runs in CI ([`sbom.yml`](../.github/workflows/sbom.yml), [`security-scan.yml`](../.github/workflows/security-scan.yml)); `CronJob/security-scanner` (alongside the 5 NIST AI 600-1 metric stubs ratcheted by `compliance/lula/.stub-baseline`) is declared `planned` work.
4. **Simulated Market & Broker Fixtures vs. Real Security Primitives**: Under the Completeness Principle and Interface Tiering in [`AGENTS.md`](../AGENTS.md#external-vendor-adapter-standards-plugin-architecture), CAGE is *safety- and security-complete*, not *commercially complete*. Domain data feeds and commercial execution backends — including `USE_MOCK_BROKER=true` in non-prod profiles, [`StubMarketDataProvider`](../src/cage_finance/safety/bounding/providers.py), `_DefaultSimulatedProvider` in [`src/gateway/governance/reconciliation/daemon.py`](../src/gateway/governance/reconciliation/daemon.py) (`POAM-2026-038`, `POAM-2026-096`), and the opt-in deterministic CPU `inference-stub` (`--enable-e2e-advisor`) — are intentionally simulated Tier 2 fixtures rather than live brokerage, exchange, or core-banking integrations. Conversely, security primitives (Cloud KMS asymmetric signing, out-of-band `kid` verification, Linkerd SPIFFE mTLS workload identity, single-use Redis seal consumption, and retention-locked WORM custody) are never simulated in enforcing postures and remain strictly **in scope**.
