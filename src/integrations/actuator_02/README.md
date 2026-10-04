# `actuator_02` — NVIDIA OpenShell Supervisor Adapter (Layer 3)

## Overview

`src.integrations.actuator_02` implements the CAGE Layer 3 execution and telemetry adapter for the **NVIDIA OpenShell Supervisor** (`https://github.com/NVIDIA/OpenShell`).

Per `AGENTS.md` (*Generic in Code, Specific in Prose*), the package path and runtime `actuator_id` use the anonymized identifier `actuator_02` (with factory aliases `"actuator_02"`, `"a02"`, and `"openshell"` in [`execution_actuator.py`](../../gateway/governance/execution_actuator.py)).

## Capabilities & Responsibilities

1. **Seal-Bound `PreCredentials` Brokerage (`Actuator02Adapter`)**:
   - Implements [`ExecutionActuator`](../../gateway/governance/seams/actuation.py) (`actuator_id = "actuator_02"`).
   - Requires an [`ExecutionClearance`](../../gateway/governance/seams/actuation.py) with `decision == "ALLOW"` and a JWS routing seal on its `routing_seal` field. The seal has already been verified and consumed by [`verify_and_consume_seal()`](../../gateway/governance/routing_seal.py) before dispatch. A clearance without a JWS seal is refused before any credential is brokered (`ROUTING_SEAL_MISSING` / `ROUTING_SEAL_NOT_JWS`).
   - Brokers credentials via [`CredentialBrokerAdapter.fetch_credential()`](../../gateway/governance/seams/credential_broker.py). Brokered headers can never set `X-CAGE-*` headers.
   - Canonicalizes the clearance envelope per RFC 8785 (JCS), signs the assertion with `CAGE_OPENSHELL_ASSERTION_V1:`, and submits to the OpenShell Supervisor over mTLS (`ACTUATOR_02_ENDPOINT`, `ACTUATOR_02_CERT_PATH`, `ACTUATOR_02_KEY_PATH`, `ACTUATOR_02_CA_PATH`).
   - Sends the seal out of band (`X-CAGE-Routing-Seal`, `X-CAGE-Seal-Profile: cage-seal/1`) for independent Supervisor verification. The seal is never in the envelope body. See [`SEAL_VERIFICATION_PROFILE.md`](../../../docs/partners/actuator_02/SEAL_VERIFICATION_PROFILE.md).
   - Verifies the Supervisor's detached Ed25519 receipt signature against an out-of-band `kid`-resolved key manifest (`ACTUATOR_02_RECEIPT_KEY_MANIFEST_URL`).

2. **OCSF Telemetry Hash-Chain Ingestion (`OcsfEvidenceIngestor`)**:
   - Ingests OpenShell **OCSF (Open Cybersecurity Schema Framework)** events (`class_uid` `1001` File System Activity, `1007` Process Activity, `4001` Network Activity).
   - Sanitizes credential/PII fields and commits `SANDBOX_OCSF_TELEMETRY` records (`controlId: "AU-2"` / `"AC-3"`) into [`EvidenceStreamSink`](../../gateway/governance/evidence/stream.py) bound to `governance_decision_digest`.

3. **Policy Advisor Dynamic Escalation Bridge (`PolicyAdvisorBridge`)**:
   - Evaluates OpenShell Policy Advisor (`SubmitPolicyAnalysis` / `ApproveDraftChunk`) permission proposals against [`SymbolicGovernor.validate_action()`](../../gateway/governance/governor/governor.py) (`Profile.DRY_RUN`).
   - Rejects proposals that violate hard STPA constraints (`ViolationKind.HARD`) and parks `REQUIRE_APPROVAL` proposals in [`DeferQueue`](../../gateway/governance/defer_queue.py) (`DeferReason.HITL_REQUIRED`).
