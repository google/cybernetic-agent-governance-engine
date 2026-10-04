# Upstream Pull Request Draft for `nvidia/openshell`

This document contains the complete pull request specification ready to be submitted to [`nvidia/openshell`](https://github.com/nvidia/openshell).

---

## PR Title

```text
feat(provider): add CAGE PolicyProvider plugin for STERA and dual-control HITL governance
```

---

## PR Description

### Summary

This pull request introduces `openshell-provider-cage`, an upstream `PolicyProvider` SPI plugin connecting **NVIDIA OpenShell** sandboxes to **CAGE (Cybernetic Agent Governance Engine)**.

While OpenShell provides kernel-level sandbox enforcement (Linux Landlock, network namespaces, seccomp, MCP filtering), high-assurance enterprise deployments (financial services, regulated healthcare, and defense) require agent actions to be validated against formal safety constraints (STAMP/STPA), domain policies (OPA Rego), irreversibility reachability (FTRA), and dual-control human-in-the-loop (HITL) approval gates before execution.

This plugin allows OpenShell supervisors to delegate pre-execution policy evaluation directly to CAGE's **Symbolic Governor** (`Profile.DRY_RUN`) and automatically hold dangerous operations in CAGE's dual-control approval queue (`DeferQueue`) until cryptographic WebAuthn approvals are provided.

---

### Key Capabilities

1. **Deterministic Pre-Execution Admissibility**:
   - Implements OpenShell's `PolicyProvider` interface.
   - Evaluates dynamic proposals (`SubmitPolicyAnalysis`, `ApproveDraftChunk`, outbound network requests, MCP tool calls) against CAGE's `/v1/governance/validate` endpoint in `dry_run` profile.
   - Rejection causes the OpenShell supervisor to immediately block the action and report STPA/UCA violation codes to the agent without changing state.

2. **Dual-Control Human-in-the-Loop (HITL) Deferral**:
   - When CAGE determines an action requires operator approval (`REQUIRE_APPROVAL` or `DEFER`), the plugin parks a `DeferToken` in CAGE's `DeferQueue` with four-eyes quorum enforcement (`required_quorum >= 2`).
   - The supervisor transitions the sandbox request to a held/pending state until approved out-of-band by authorized personnel using hardware security keys (WebAuthn).

3. **STPA Sandbox Policy Spec Ingestion**:
   - Adds `stpa_loader.py` to parse CAGE's STPA-compiled policy artifacts (`generated_sandbox_policy.yaml`).
   - Maps formal STPA safety constraints into OpenShell Landlock filesystem restrictions (`read_only`, `read_write`), binary execution whitelists, and egress network rules.

4. **WORM Evidence Stream & OCSF v1.1.0 Integration**:
   - Normalizes sandbox activity into OCSF v1.1.0 event classes:
     - `3001`: File System Activity
     - `4001`: Network Activity
     - `6003`: API Activity
   - Recursively redacts sensitive API keys and tokens before dispatching to CAGE's tamper-evident audit log.

5. **Fail-Closed Out-of-Band Workload Quarantine**:
   - If a critical Control Barrier Function (CBF) breach occurs during action evaluation, the refusal payload signals `quarantined=true`.
   - The plugin instructs OpenShell to immediately isolate the sandbox workload and sever model inference / network egress routes.

---

### Sequence Diagram

```text
OpenShell Supervisor               openshell-provider-cage                   CAGE Gateway
        |                                     |                                   |
        |--- 1. evaluate(proposal) ---------->|                                   |
        |                                     |--- 2. POST /v1/governance/validate |
        |                                     |       (Profile: dry_run, mTLS)     |
        |                                     |                                   |
        |                                     |<-- 3. Verdict: REQUIRE_APPROVAL ---|
        |                                     |       (or ALLOW with Seal)        |
        |                                     |                                   |
        |<-- 4. PolicyEvaluationOutcome ------|                                   |
        |       (deferred / allowed / denied) |                                   |
        |                                     |                                   |
        |=== 5. Hold or Execute sandbox action ===================================|
        |                                     |                                   |
        |--- 6. report_telemetry(ocsf_event) >|                                   |
        |                                     |--- 7. POST /v1/evidence/ocsf ---->|
```

---

### Configuration Example

```yaml
# openshell.yaml
policy_providers:
  cage:
    module: openshell_provider_cage
    endpoint: "https://cage-gateway.internal:8080"
    mTLS:
      client_cert: "/etc/openshell/certs/client.pem"
      client_key: "/etc/openshell/certs/client-key.pem"
      ca_cert: "/etc/openshell/certs/ca.pem"
    sandbox_policy_path: "/etc/openshell/generated_sandbox_policy.yaml"
    quarantine_on_hard_breach: true
```

---

### Security & Compliance Invariants

- **Fail-Closed Execution**: If CAGE is unreachable, the network times out, or the payload is malformed, `evaluate()` returns `allowed=False, rejected=True`.
- **Zero In-Process Credential Leakage**: All outbound telemetry passes through `scrub_credentials()` targeting HuggingFace tokens (`hf_*`), Langfuse credentials (`pk-lf-*`, `sk-lf-*`), Google API keys, and connection strings.
- **Linkerd mTLS Identity**: Requests to CAGE carry verified SPIFFE ServiceAccount identities via `l5d-client-id`.
- **Four-Eyes HITL Security**: Deferrals always require `required_quorum >= 2` to prevent single-operator bypass.

---

### Test Matrix

- `TestCagePolicyProvider.test_evaluate_allows_clean_proposal`: Verifies clean proposals obtain `ALLOW` with routing seal.
- `TestCagePolicyProvider.test_evaluate_parks_require_approval_proposal`: Verifies high-risk proposals return `deferred=True` with `defer_id`.
- `TestCagePolicyProvider.test_evaluate_detects_quarantine_on_hard_denial`: Verifies hard CBF breaches trigger workload quarantine.
- `TestCagePolicyProvider.test_evaluate_fails_closed_on_network_error`: Verifies gateway timeouts or network partition fail closed.
- `TestStpaPolicyLoaderAndOcsf.test_load_cage_sandbox_policy`: Verifies Landlock paths and binary whitelists parse into OpenShell structures.
- `TestStpaPolicyLoaderAndOcsf.test_scrub_credentials`: Verifies credential regex sanitization.

All tests run hermetically with 100% pass rate.
