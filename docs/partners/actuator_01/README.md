# Archytan ArbiterKernel Partner Integration (actuator_01)

<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->
> [!NOTE]
> **Third-party integration material.** Its presence in this repository is not
> a Google certification or endorsement of the partner or its products. For the
> integration's current verification status, see
> [Live Verification Status](../README.md#live-verification-status).
<!-- /CAGE-PARTNER-CONTENT-HEADER -->

> **Architecture Standard — Generic in Code, Specific in Prose.**
> In accordance with CAGE architecture standards (ADR-008), the runtime implementation in
> `src/integrations/` uses the anonymized identifier `actuator_01`. This directory contains
> the partner-supplied reference vector artifacts for **Archytan** (`ArbiterKernel`).

---

## Reference Artifacts

| File | Description | Extracted Fixture |
|---|---|---|
| [`vector3_direct_json.pdf`](vector3_direct_json.pdf) | Archytan `ArbiterKernel` Vector 1 (DIRECT path) canonical JSON specification (`arbiter-kernel/cmd/gen-cage-vectors`) | [`tests/fixtures/actuator_01/vector1_direct.json`](../../../tests/fixtures/actuator_01/vector1_direct.json) |
| [`vector3_escalate_json.pdf`](vector3_escalate_json.pdf) | Archytan `ArbiterKernel` Vector 3 (ESCALATE path) canonical JSON specification (`arbiter-kernel/cmd/gen-cage-vectors`) | [`tests/fixtures/actuator_01/vector3_escalate.json`](../../../tests/fixtures/actuator_01/vector3_escalate.json) |

## Implementation & Alignment References

- Layer 3 Integration Adapter: [`src/integrations/actuator_01/`](../../../src/integrations/actuator_01/) ([`README.md`](../../../src/integrations/actuator_01/README.md))
- Vector Alignment Notes: [`docs/operations/ARCHYTAN_VECTOR_ALIGNMENT.md`](../../operations/ARCHYTAN_VECTOR_ALIGNMENT.md)
- Live Conformance Suite: [`tests/test_actuator_01_live.py`](../../../tests/test_actuator_01_live.py)
