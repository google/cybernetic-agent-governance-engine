# NVIDIA Sentry / DOCA DPU Partner Integration (actuator_03)

<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->
> [!NOTE]
> **Third-party integration material.** Its presence in this repository is not
> a Google certification or endorsement of the partner or its products. For the
> integration's current verification status, see
> [Live Verification Status](../README.md#live-verification-status).
<!-- /CAGE-PARTNER-CONTENT-HEADER -->

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

## Dual-Pathway Containment & Open-Source Licensing Boundary

- **Default Commodity Open-Source Baseline (`CAGE_INFERENCE_PROXY_SVID` + Cilium/eBPF)**:
  - On commodity Kubernetes / GKE deployments without DPU hardware, CAGE defaults to [`InferenceProxySvidQuarantineActuator`](../../../src/gateway/governance/quarantine_actuator.py) (revoking offending `thread_id` and `agent_svid` principals at the inference proxy) paired with static L3/L4 + DNS-snooped `FQDNNetworkPolicy` egress lockdown ([`deployment/k8s/cilium/egress-lockdown.yaml`](../../../deployment/k8s/cilium/egress-lockdown.yaml)) and Linkerd SPIFFE mTLS.
- **Zero Proprietary SDKs or Firmware Blobs (`IN_SILICON_DPU`)**:
  - `actuator_03` is a 100% CAGE-authored, over-the-wire HTTPS/mTLS client (`httpx`, RFC 8785 JCS, Ed25519). No proprietary DOCA libraries, headers, or binaries are vendored or linked in this repository. Any SmartNIC or DPU appliance implementing the `/v1/dpu/quarantine` wire contract can serve as the hardware enforcement endpoint.

---

## File Reference

- Layer 3 Adapter Implementation: [`src/integrations/actuator_03/`](../../../src/integrations/actuator_03/)
- Layer 1 Quarantine Seam Protocol: [`src/gateway/governance/seams/quarantine.py`](../../../src/gateway/governance/seams/quarantine.py)
- CAGE Workload Quarantine Actuators: [`src/gateway/governance/quarantine_actuator.py`](../../../src/gateway/governance/quarantine_actuator.py)
- Cilium / GKE Dataplane V2 Egress Policies: [`deployment/k8s/cilium/egress-lockdown.yaml`](../../../deployment/k8s/cilium/egress-lockdown.yaml)
