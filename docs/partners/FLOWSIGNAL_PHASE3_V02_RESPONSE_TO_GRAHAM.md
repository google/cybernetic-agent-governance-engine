# FlowSignal Phase 3 v0.2 — Response to Graham's Context Field Question

**Date:** 2026-09-15  
**Re:** `context` field semantics in CageAuthorityDetermineRequest

---

Hi Graham,

Thanks again for the clarification on the Phase 3 v0.2 integration. It has resolved most of the ambiguity we encountered during our final pre-staging review.

We have now reconciled our side around the specific bilateral contract you described: provider_01 transforming directly into the frozen CageAuthorityDetermineRequest and targeting /cage/validate, with the later Bearer-over-TLS arrangement for the initial staging exercise.

Regarding your implementation detail question about the `context` field semantics:

## Answer: Context Field Treatment

Based on our current implementation and intended semantics, **`context` is descriptive metadata for audit correlation, not authority-bearing input to FlowSignal's determination logic.**

### Specifics

**1. Authority Binding**

`magnitude` (the numeric value) is the **sole authority-bearing field** that should drive FlowSignal's determination. The `context` field provides human-readable annotation (e.g., "Large equity purchase: AAPL 500 shares") for audit trails and operator review, but **should not influence the ALLOW/REFUSE/ESCALATE decision algorithmically**.

Think of `context` as equivalent to a memo field on a bank transaction — it explains *what* the action represents in business terms, but the authority determination must be made solely on `magnitude` + `currency` + your policy rules.

**2. Response Preservation**

CAGE does **not** expect `context` to be returned/preserved in the `/cage/validate` response. We only consume:
- `decision` (mandatory: `ALLOW` | `REFUSE` | `ESCALATE`)
- Optional: `message`, `authority_record_id`, `authority_state_version`

If FlowSignal wants to preserve `context` internally for correlation or audit logging, that's fine, but it's not required in the wire protocol response.

**3. Design Rationale**

This aligns with the fail-closed principle: authority decisions must be **deterministic from numeric bounds**, not from parsing free-text descriptions. The current behavior you identified (accepting `context` at the CAGE-facing boundary but dropping it during translation into native FlowSignal request) is **safe and matches our intended usage model**.

### Important Caveat

If your native FlowSignal schema binds authority decisions to **both** a numeric threshold **AND** semantic action classification (e.g., "equity purchase" vs. "derivative trade" triggering different policy branches), we should discuss whether that semantic binding belongs in a separate structured field (e.g., `action_type` enum) rather than overloading the free-text `context` field.

But for the Phase 3 v0.2 candidate as currently specified, your implementation is correct.

## Implementation Status on CAGE Side

Quick follow-up on our Phase 3 v0.2 readiness:

We've updated our `provider_01` adapter in CAGE to match the frozen candidate schema — payloads now transform directly to `CageAuthorityDetermineRequest` (`magnitude`, `context`, `currency`, `platform`, `execution_id`, `evidence_references`, `approval_id`) targeting `/cage/validate`, backed by strict fail-closed mTLS validation.

**All our internal regression and conformance gates are green.** Whenever your staging environment is ready for traffic on v0.2, let me know and we can run our live partner integration harness against it to verify the wire roundtrip.

## Code Evidence (for Reference)

From our implementation:

- **Schema:** [`docs/partners/FLOWSIGNAL_PHASE3_V02_SCHEMA.md`](../../docs/partners/FLOWSIGNAL_PHASE3_V02_SCHEMA.md)
- **Adapter:** [`src/integrations/provider_01/provider.py`](../../src/integrations/provider_01/provider.py)
- **Decision Mapping:** `_map_flowsignal_decision()` examines only `decision`, `magnitude`, `actor_id`, `thread_id` — `context` is never read after transmission

Everything else now looks substantially clearer from our side, so once you've confirmed this point and completed the final regression/hostile review, we should be in a position to proceed with live integration testing.

---

## Additional Update: GovernanceEnvelope v3.0 Breaking Change

One additional item to flag for your integration pipeline:

In our latest baseline freeze, CAGE upgraded its core envelope schema to **GovernanceEnvelope v3.0** (`_ENVELOPE_VERSION = "3.0"`). This release introduces a **breaking change to the top-level wire contract and root cryptographic digest**.

### What Changed

**Canonical Digest Sealing:** To enforce whole-envelope non-widening guarantees, `SubjectMetadata` now explicitly binds three additional fields:
- `consequence_ceiling` (e.g., `"LOW_INFORMATIONAL"`, `"HIGH_FINANCIAL"`)
- `target_route` (e.g., `"local://default"`, `"synthetic://resource/alpha"`)
- `executor_id` (e.g., `"kernel"`, `"actuator_01"`)

**RFC 8785 (JCS) Invariant:** These fields participate directly in the canonical JCS serialization. Any existing signature verifier computing SHA-256 digests over the raw envelope will fail unless updated to include these properties in the `subject` block.

### Action Required (If Applicable)

If FlowSignal's integration performs cryptographic signature verification on CAGE governance envelopes (e.g., validating our KMS-signed evidence submissions):

1. **Update your schema parsers** to accept the expanded `SubjectMetadata` fields in the `subject` block.
2. **Ensure your JCS signature verification logic** includes these fields when reconstructing the canonical payload for digest comparison.

**Inner attestation DAG structures remain unaffected.** This change only impacts the top-level envelope schema.

### Reference Implementation

From [`src/gateway/governance/governance_envelope.py:136-155`](../../src/gateway/governance/governance_envelope.py#L136-L155):

```python
@dataclass
class SubjectMetadata:
    """Metadata about the governance subject (action being governed)."""

    action: str
    action_hash: str
    thread_id: str | None = None
    agent_id: str | None = None
    consequence_ceiling: str = "LOW_INFORMATIONAL"  # NEW in v3.0
    target_route: str = "local://default"  # NEW in v3.0
    executor_id: str = "kernel"  # NEW in v3.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "action_hash": self.action_hash,
            "consequence_ceiling": self.consequence_ceiling,  # Bound in digest
            "target_route": self.target_route,  # Bound in digest
            "executor_id": self.executor_id,  # Bound in digest
        }
```

Please reach out if you need our updated reference fixtures or JCS test vectors to validate your verification pipeline.

---

Best,

Lars
