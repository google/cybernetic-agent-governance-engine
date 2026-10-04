# `actuator_03` — NVIDIA Sentry / BlueField-4 DPU DOCA Quarantine Adapter (Layer 3)

## Overview

`src.integrations.actuator_03` implements the CAGE Layer 3 hardware-offloaded quarantine adapter for **NVIDIA Sentry** running on **NVIDIA BlueField-4 DPUs** via **NVIDIA DOCA** flow isolation, alongside CAGE's native [`InferenceProxySvidQuarantineActuator`](../../gateway/governance/quarantine_actuator.py).

Per `AGENTS.md` (*Generic in Code, Specific in Prose*), the package path and runtime `actuator_id` use the anonymized identifier `actuator_03` (with factory aliases `"actuator_03"`, `"a03"`, `"sentry"`, and `"doca_quarantine"`).

## Capabilities & Responsibilities

- Implements both [`QuarantineActuator`](../../gateway/governance/seams/quarantine.py) and [`ExecutionActuator`](../../gateway/governance/seams/actuation.py) (`actuator_id = "actuator_03"`).
- Canonicalizes [`QuarantineDirective`](../../gateway/governance/seams/quarantine.py) per RFC 8785 (JCS) and signs the directive with `RawMessageSigner` (`CAGE_QUARANTINE_ASSERTION_V1:`).
- Submits out-of-band flow-drop directives over mTLS (`ACTUATOR_03_ENDPOINT`, `ACTUATOR_03_CERT_PATH`, `ACTUATOR_03_KEY_PATH`, `ACTUATOR_03_CA_PATH`).
- Verifies the DPU's detached Ed25519 flow-drop receipt signature against an independently fetched `kid`-resolved key manifest (`ACTUATOR_03_RECEIPT_KEY_MANIFEST_URL`).
