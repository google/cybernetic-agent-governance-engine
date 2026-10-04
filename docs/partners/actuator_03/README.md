# NVIDIA Sentry / DOCA DPU Partner Integration (actuator_03)

> **Architecture Standard — Generic in Code, Specific in Prose.**  
> In accordance with CAGE architecture standards (ADR-008), the runtime implementation in
> `src/integrations/` uses the anonymized identifier `actuator_03`. This document contains the
> partner-specific technical alignment and wire contracts for **NVIDIA Sentry** and
> **DOCA Flow on BlueField-4 DPUs**.

---

## Overview

NVIDIA Sentry on BlueField-4 Data Processing Units (DPUs) enforces in-silicon network flow isolation and packet drops at line rate (800 Gbps) independently of the host CPU and OS kernel.

When an autonomous AI agent experiences a catastrophic Control Barrier Function (CBF) breach or an uncontainable FTRA state divergence, software-level killswitches on the host may be compromised or bypassed. `actuator_03` provides an out-of-band hardware quarantine path:

1. **Directive Issuance**:
   - CAGE issues a `QuarantineDirective` (`thread_id`, `agent_svid`, `reason: CRITICAL_CBF_BREACH`, `governance_decision_digest`).
   - The directive is signed with `CAGE_QUARANTINE_ASSERTION_V1:` using CAGE's KMS private key.

2. **Hardware In-Silicon Actuation**:
   - Dispatched over mTLS to the DPU's NVIDIA Sentry DOCA Flow management endpoint (`POST /v1/dpu/quarantine`).
   - The DPU programs a hardware packet-drop rule (`dpu_doca_flow_drop`) directly into the NIC's eSwitch flow table, severing the agent's inference and network paths in silicon.

3. **Ed25519 Detached Verification**:
   - The DPU returns an `ActuationReceipt` signed with its hardware-bound private key (`CAGE_QUARANTINE_RECEIPT_V1:`).
   - CAGE verifies the signature against an independently-fetched key manifest by `kid` before recording the `WORKLOAD_QUARANTINE_RECEIPT` into the tamper-evident WORM evidence stream (`controlId: "SC-7"`).

---

## File Reference

- Layer 3 Adapter Implementation: [`src/integrations/actuator_03/`](../../../src/integrations/actuator_03/)
- Layer 1 Quarantine Seam Protocol: [`src/gateway/governance/seams/quarantine.py`](../../../src/gateway/governance/seams/quarantine.py)
- CAGE Workload Quarantine Actuators: [`src/gateway/governance/quarantine_actuator.py`](../../../src/gateway/governance/quarantine_actuator.py)
