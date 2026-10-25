<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->
> **Partner Integration Status & Non-Endorsement Header**
> - **Authorship:** Partner-authored or bilateral integration specification material; **not Google-authored** product documentation.
> - **Endorsement:** **Not Google-endorsed.** Hosting in this repository is for technical interoperability and conformance reference only and does not constitute a Google certification, qualification, or regulatory endorsement.
> - **Contribution & License:** Contributed under the repository CLA and licensed under Apache-2.0.
> - **Verification Status:** `AUTHOR_SELF_TEST` — **not independently verified** (`independent_of_author: false`, `third_party_independent: false`). Independent or counterparty verification requires executing `cage-conformance` with verified OIDC runner provenance.
<!-- /CAGE-PARTNER-CONTENT-HEADER -->

# NVIDIA OpenShell Partner Integration (actuator_02)

> **Architecture Standard — Generic in Code, Specific in Prose.**  
> In accordance with CAGE architecture standards (ADR-008), the runtime implementation in
> `src/integrations/` uses the anonymized identifier `actuator_02`. This document contains the
> partner-specific technical alignment, upstream contribution artifacts, and wire contracts for
> **NVIDIA OpenShell**.

---

## Overview

[NVIDIA OpenShell](https://github.com/nvidia/openshell) is an open-source agent execution and sandbox runtime providing OS-level isolation (Linux Landlock, network namespaces, seccomp), MCP tool filtering, and ephemeral credential brokerage.

The CAGE integration bridges OpenShell with CAGE's **STERA Admissibility Engine** through two symmetrical layers:

1. **Downstream Execution Adapter (`src/integrations/actuator_02/`)**:
   - `Actuator02Adapter`: Implements `ExecutionActuator`, brokering dynamic pre-credentials via `CredentialBroker` and dispatching signed actuation clearances (`CAGE_SANDBOX_ASSERTION_V1:`) over mTLS.
   - `OcsfEvidenceIngestor`: Normalizes OCSF v1.1.0 audit telemetry (`class_uid in {1001, 1007, 4001}`) and commits records to CAGE's tamper-evident evidence stream (`controlId: "AU-2"` / `"AC-3"`).
   - `PolicyAdvisorBridge`: Bridges dynamic sandbox permission proposals to `SymbolicGovernor.validate_action(..., profile=Profile.DRY_RUN)` and parks dual-control (`required_quorum >= 2`) `DeferToken`s in `DeferQueue`.

2. **Upstream Contribution Package (`contrib/openshell-provider-cage/`)**:
   - A standalone Python plugin package implementing OpenShell's `PolicyProvider` SPI.
   - Allows standard OpenShell supervisor deployments to delegate pre-execution policy evaluation directly to CAGE.

---

## Seal Verification Profile (default)

Every actuation sends the governor's routing seal under profile `cage-seal/1`
(`X-CAGE-Routing-Seal` + `X-CAGE-Seal-Profile`), so the Supervisor can verify
independently that CAGE authorised this exact `(action, params)`. CAGE refuses
to dispatch a clearance without a JWS seal. The Supervisor-side checks are a
specification and not yet implemented upstream. See
[`SEAL_VERIFICATION_PROFILE.md`](SEAL_VERIFICATION_PROFILE.md).

---

## Upstream Contribution Draft

For the complete GitHub Pull Request submission drafted for `nvidia/openshell`, see:
- [`UPSTREAM_PR_DRAFT.md`](UPSTREAM_PR_DRAFT.md): Ready-to-file pull request title, description, architecture explanation, and test matrix.

---

## File Reference

- Upstream Plugin Package: [`contrib/openshell-provider-cage/`](../../../contrib/openshell-provider-cage/)
- CAGE Layer 3 Integration Adapter: [`src/integrations/actuator_02/`](../../../src/integrations/actuator_02/)
- STPA Compiler Target: [`src/gateway/governance/stpa_compiler.py`](../../../src/gateway/governance/stpa_compiler.py) (`--targets sandbox`)
- Generated Sandbox Policy Artifact: [`config/sandbox/generated_sandbox_policy.yaml`](../../../config/sandbox/generated_sandbox_policy.yaml)
