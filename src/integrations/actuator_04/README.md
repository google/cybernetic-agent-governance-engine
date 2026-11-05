# Actuator 04: Host OS Kernel Containment & Hardware Attestation Adapter

This package implements Google CAGE's Layer 3 vendor-anonymized adapter (`actuator_04`) bridging the CAGE Governance Gateway to the native Host OS Kernel Substrate (**KillSwitch**).

Per CAGE `AGENTS.md` (*Generic in Code, Specific in Prose*), all Python source files in this directory use generic, vendor-neutral identifiers (`actuator_04`, `HOST_OS_KERNEL`), naming KillSwitch strictly in prose, K8s manifests, and technical documentation.

## Capabilities & Architecture

`actuator_04` covers **all four CAGE external seams**:

1. **Quarantine Actuator (`QuarantineActuator`)**:
   - Outbound KMS-signed assertions (`CAGE_QUARANTINE_ASSERTION_V1:`) over RFC 8785 JCS canonical bytes.
   - Inbound Ed25519 detached receipt verification (`CAGE_QUARANTINE_RECEIPT_V1:`) resolved out-of-band via `Ed25519KeyManifestClient` (`/.well-known/jwks.json`).
   - Native OS host enforcement via Windows Filtering Platform (`FwpmFilterAdd0` + `SetTcpEntry` + `NtSuspendProcess`), Linux Netlink (`RTN_BLACKHOLE` + Landlock LSM + eBPF `SIGSTOP`), or macOS PF.
   - Quorum-approved release (`POST /v1/cage/release`) requiring verified dual-operator signatures (`quorum >= 2`), advancing the workload's generation epoch (`Gen N -> Gen N+1`) to prevent replay of pre-quarantine tokens.
2. **Execution Actuator (`ExecutionActuator`)**:
   - Validates ADR-008 single-use routing seals (`verify_and_consume_seal()`).
   - Dispatches authorized host-level containment directives.
3. **Normative Provider (`NormativeProvider`)**:
   - Delegates compliance checks to `/v1/cage/conformal/validate`.
   - Evaluates calibrated Mahalanobis nonconformity $p$-values $p_k(x) > \alpha$ and deterministic voter consensus (`killswitch-conformal` + `killswitch-adjudication`).
4. **Attestation Provider (`AttestationProvider`)**:
   - Queries `/v1/cage/attest` for live discrete hardware TPM 2.0 PCR quotes (`PCR 0..7`) and active Ring-0 firewall states.
   - Compares quotes against baseline measurements, emitting `AttestationStatus.DRIFT_DETECTED` on PCR drift.
5. **Bidirectional Signed OCSF Ingestor (`Actuator04OcsfIngestor`)**:
   - Ingests Ed25519-signed OCSF 1001 (File), 1007 (Process), and 4001 (Network) security events.
   - Intercepts $<1\ \mu\text{s}$ Crown-Jewel file lineage taint or sandbox escapes (`severity >= 4`), automatically quarantining the offending `agent_svid` across all gateway endpoints (`/v1/chat/completions`, `/governance/validate-action`, `/mcp`).

## Multi-Node DaemonSet Routing & Cluster Fan-Out

In Kubernetes clusters, host quarantine daemons run as a DaemonSet (`host-quarantine-daemon.yaml`) on every worker node:
- **Node-Targeted Routing**: When `sandbox_id` has node affinity (`node-a/sbx-1`), the transport routes directly to that node.
- **Cluster Fan-Out**: When node placement is unknown or cluster-wide containment is requested, `Actuator04Transport` fans out concurrently across all nodes via `asyncio.gather`. All nodes must return verified receipts with matching `envelope_digest` (fail-closed).

## Configuration

| Environment Variable | Description | Default |
|---|---|---|
| `ACTUATOR_04_ENDPOINT` | Single daemon endpoint URL (dev/fallback) | `""` |
| `ACTUATOR_04_NODE_ENDPOINTS` | Multi-node map (`node-a=https://...,node-b=https://...` or JSON) | `""` |
| `ACTUATOR_04_CERT_PATH` | Path to client TLS certificate | `""` |
| `ACTUATOR_04_KEY_PATH` | Path to client TLS private key | `""` |
| `ACTUATOR_04_CA_PATH` | Path to CA root bundle | `""` |
| `ACTUATOR_04_RECEIPT_KEY_MANIFEST_URL` | JWKS manifest URL (`/.well-known/jwks.json`) | `""` |
| `ACTUATOR_04_REQUIRE_SIGNED_RECEIPTS` | Fail-closed signature requirement | `True` in enforcing |
| `ACTUATOR_04_EXPECTED_TPM_PCR_QUOTE` | Golden TPM 2.0 SHA-256 PCR 0..7 quote | `""` |
| `ACTUATOR_04_CONFORMAL_ALPHA` | Conformal significance threshold $\alpha$ | `0.05` |
