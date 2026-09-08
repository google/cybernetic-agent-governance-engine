# actuator_01 — SignerResolver Pattern & Multi-Party Quorum Design

**Status:** Architecture Specification (as-built + normative deltas)
**Layer:** Layer 3 — Integrations (`src/integrations/actuator_01/`)
**Scope:** Per-operator quorum signing, distinct-URN enforcement, orchestrator test architecture
**Related:** [`actuator_01_kms_iam_model.md`](actuator_01_kms_iam_model.md), [`VENDOR_NEUTRALITY_CONTRACT.md`](VENDOR_NEUTRALITY_CONTRACT.md)

> **Reference Architecture Note.** CAGE is an illustrative reference architecture, not a
> deployed service. The signer topology described here (single shared key by default,
> per-operator resolution as an opt-in seam) is deliberately legible rather than
> operationally hardened. Adopters must supply a real resolver before production use —
> see [`actuator_01_kms_iam_model.md`](actuator_01_kms_iam_model.md) §2.

---

## 1. Problem Statement

`Actuator01Adapter.actuate()` builds a quorum signature list by iterating
`clearance.approvals`. The original defect was that the loop passed the adapter's single
`self._signer` to `sign_for_quorum()` on every iteration:

```python
# DEFECTIVE (pre-fix)
for approval in clearance.approvals:
    urn = approval.get("approver_urn", "")
    operator_urns.append(urn)
    sig = sign_for_quorum(self._signer, canonical_bytes)  # ← same key every time
    quorum_signatures.append(sig)
```

Because `sign_for_quorum()` is deterministic over `(key, canonical_bytes)` and
`canonical_bytes` is loop-invariant, this produced **N byte-identical signatures**
presented as N independent operator attestations.

### 1.1 Why local tests could not catch it

| Property | Testable pre-fix? | Reason |
|---|---|---|
| Signature format / length | Yes | `signatures.py` is signature-count-agnostic |
| Domain-tag isolation | Yes | Covered by [`test_actuator_01_signatures.py`](../../tests/test_actuator_01_signatures.py) |
| Envelope canonicalization | Yes | Covered by [`test_actuator_01_envelope.py`](../../tests/test_actuator_01_envelope.py) |
| Header positional alignment | Partially | Client tests used constant mock signatures |
| **Multi-party quorum semantics** | **No** | No seam existed to inject distinct keys |
| **`signatures[i]` belongs to `urns[i]`** | **No** | Constant mock (`b"a" * 64`) cannot detect permutation |

A constant-output mock signer makes misalignment **unobservable**: if every signature is
identical, any permutation of the signature list is indistinguishable from the correct one.
This is the root cause of the coverage blind spot, not merely an omission of test cases.

### 1.2 Failure mode at the live boundary

Local tests pass; live actuation fails. Archytan verifies `signature[i]` against the
registered public key of `operator_urn[i]`. With one shared key, at most one index verifies
and the envelope is rejected — the failure surfaces only against a live partner endpoint.

---

## 2. Design Principle: Signer Topology Is a Deployment Concern

The adapter must not know *how* operator identity maps to key material. Workload-Identity
key rings, per-ceremony OIDC downscoping, and the reference single-key model are all
legitimate topologies. The adapter's only requirement is:

> Given an operator URN, obtain a signer that holds *that operator's* key.

This is expressed as an injected callable — a resolver — rather than as configuration
inside the adapter. The adapter stays vendor-neutral and topology-agnostic; the resolver
is where IAM complexity lives.

---

## 3. `SignerResolver` Type Definition

Declared in [`adapter.py`](../../src/integrations/actuator_01/adapter.py:79):

```python
from collections.abc import Callable
from src.gateway.governance.kms_signer import KMSGovernanceSigner

# Type alias for per-operator signer resolution
SignerResolver = Callable[[str], KMSGovernanceSigner]
```

### 3.1 Why a type alias and not a `Protocol`

A `Protocol` class would be justified if resolvers needed lifecycle methods
(`close()`, `warm_up()`, `list_operators()`). They do not. The contract is a single
total function from URN to signer, so a `Callable` alias is the minimal faithful
encoding. It also lets callers pass a bare `lambda`, a `dict.__getitem__`, a bound
method, or a `functools.partial` with no adapter boilerplate and no inheritance.

**Consequence:** resolvers are structurally typed. Any callable of the right shape
qualifies. This is what makes the test mocks in §6 trivial.

### 3.2 Contract obligations

| Obligation | Requirement |
|---|---|
| **Totality** | Must return a signer or raise. Must never return `None`. |
| **Purity of identity** | The returned signer must hold key material for *that* URN, not a default. |
| **Failure mode** | Raise `RuntimeError` on unknown URN. The adapter catches it and fails closed with `QUORUM_SIGNING_FAILED`. |
| **Determinism** | Repeated calls for the same URN must resolve equivalent key material (may return distinct instances). |
| **No I/O guarantee** | Resolvers *may* perform network I/O (token exchange). Callers must assume it can be slow. |

### 3.3 Non-obligations (deliberate)

- The resolver is **not** required to be thread-safe. `actuate()` calls it sequentially.
- The resolver is **not** required to cache. Caching is the resolver author's concern.
- The resolver **does not** validate that the URN is authorized — that is the governance
  decision's responsibility, already settled before an `ExecutionClearance` exists.

### 3.4 Reference resolver implementations

```python
# Reference model — single shared key (current default, see §4.2)
resolver = lambda _urn: shared_signer

# Adopter Option A — per-operator Workload Identity key rings
_SIGNERS = {
    "urn:actuator_01:op:alice": KMSGovernanceSigner(key_id=ALICE_KEY),
    "urn:actuator_01:op:bob": KMSGovernanceSigner(key_id=BOB_KEY),
}


def resolver(urn: str) -> KMSGovernanceSigner:
    try:
        return _SIGNERS[urn]
    except KeyError:
        raise RuntimeError(f"No registered signing key for operator {urn}")


# Adopter Option B — per-ceremony OIDC downscoping (recommended)
def resolver(urn: str) -> KMSGovernanceSigner:
    token = exchange_ceremony_token(urn, lifetime=MAX_TTL_SECONDS)
    return KMSGovernanceSigner.from_ceremony_token(token)
```

Option B is the recommended adopter hardening; rationale is in
[`actuator_01_kms_iam_model.md`](actuator_01_kms_iam_model.md) §2.

---

## 4. Adapter Changes

### 4.1 Constructor signature

```python
def __init__(
    self,
    client: ActuatorHttpClient,
    signer: KMSGovernanceSigner,
    signer_resolver: SignerResolver | None = None,
) -> None:
    self._client = client
    self._signer = signer
    self._resolve_signer = signer_resolver or (lambda _urn: signer)
```

`signer_resolver` is a keyword-optional third parameter. All existing two-argument
construction sites remain valid, so this is a **non-breaking additive change** despite
AGENTS.md permitting breaking changes — no breakage was necessary to achieve structural
clarity here.

### 4.2 Role separation between `signer` and `signer_resolver`

These are **not** redundant. They serve two distinct cryptographic roles:

| Parameter | Role | Used at |
|---|---|---|
| `signer` | **Issuer identity.** Signs the 120-byte execution assertion — CAGE's own attestation that governance reached ALLOW. | Step 3, `build_assertion(..., signer=self._signer)` |
| `signer_resolver` | **Operator identity.** Resolves each approving operator's key for quorum signatures. | Step 4, `self._resolve_signer(urn)` |

The assertion is signed by CAGE-as-issuer; quorum signatures are signed by
operators-as-approvers. Collapsing these into one parameter would conflate the issuer
and approver trust domains — precisely the conflation that caused the original defect.
`signer` therefore remains **required**, not optional.

### 4.3 Default resolver — deliberate identity-signature behavior

When `signer_resolver is None`, the default `lambda _urn: signer` reproduces the original
behavior: all operators share one key, so signatures are identical. **This is intentional
and must not be "fixed".**

Rationale: the reference architecture has exactly one KMS key available
(`KMS_GOVERNANCE_KEY`). Fabricating distinct-looking signatures from one key would be
security theater. The honest default is to produce what the key material actually
supports, and to make the seam for real multi-party signing explicit and injectable.
[`test_default_resolver_uses_base_signer`](../../tests/test_actuator_01_adapter.py:163)
asserts this identity behavior so it can never silently regress into fake distinctness.

### 4.4 Signing loop (as-built)

```python
operator_urns: list[str] = []
quorum_signatures: list[str] = []

try:
    for approval in clearance.approvals:
        urn = approval.get("approver_urn", "")
        if not urn:
            raise RuntimeError("Approval record missing approver_urn")
        operator_urns.append(urn)
        operator_signer = self._resolve_signer(urn)
        sig = sign_for_quorum(operator_signer, canonical_bytes)
        quorum_signatures.append(sig)
except RuntimeError as exc:
    return ActuationReceipt(... code="QUORUM_SIGNING_FAILED" ...)
```

**Positional-alignment invariant.** `operator_urns` and `quorum_signatures` are appended
within the same loop iteration, in the same order, with no intervening sort, filter, or
set operation. Therefore `signatures[i]` is by construction the signature of
`urns[i]`. Any future refactor that derives one list independently of the other —
e.g. a comprehension over `set(approvals)`, or sorting URNs for header stability —
breaks this invariant silently. §6.3 specifies the regression test that guards it.

**Fail-closed coupling.** `RuntimeError` is the common failure currency: it is raised by
missing-URN validation, by resolver lookup failure (§3.2), and by
`sign_for_quorum()` when `is_kms_active` is false. All three converge on the single
`QUORUM_SIGNING_FAILED` branch, so no signing failure can produce a partial signature
list that reaches the wire.

---

## 5. Client-Side Distinct URN Enforcement

### 5.1 The docstring/code divergence

[`client.py`](../../src/integrations/actuator_01/client.py:112) documents the parameter as
`operator_urns: List of operator URNs (≥2 distinct)`. The original code checked only
`len(operator_urns) < 2` — a cardinality check, not a distinctness check. The list
`["urn:op:alice", "urn:op:alice"]` satisfied cardinality and passed validation, allowing a
**single operator to constitute their own quorum**. That is a dual-control bypass: the
entire purpose of a 2-of-N quorum is that two *different* principals approve.

### 5.2 Enforcement (as-built)

Three ordered guards in `submit_envelope()`, all before any network I/O:

```python
# Guard 1 — positional pairing is well-formed
if len(operator_urns) != len(signatures):
    raise RuntimeError(f"URN/signature count mismatch: ...")

# Guard 2 — cardinality
if len(operator_urns) < 2:
    raise RuntimeError(
        f"Insufficient quorum: {len(operator_urns)} URNs (minimum 2 required)"
    )

# Guard 3 — distinctness
if len(set(operator_urns)) < 2:
    raise RuntimeError(
        f"Quorum requires ≥2 distinct operator URNs, got {len(set(operator_urns))} distinct"
    )
```

### 5.3 Ordering rationale

The guards are ordered cheapest-and-most-fundamental first, and the ordering is
semantically load-bearing:

1. **Count mismatch first.** If the lists are not the same length, positional alignment is
   already meaningless and every downstream diagnostic would be misleading.
2. **Cardinality before distinctness.** A 1-element list should report "insufficient
   quorum" (the actionable problem) rather than "not enough distinct URNs" (a confusing
   restatement). Reversing these would degrade the error message for the most common case.
3. **Distinctness last.** It is the only guard requiring a set construction, and it is only
   meaningful once the list is known to be well-formed and large enough.

### 5.4 Why `< 2` distinct rather than "all distinct"

Guard 3 uses `len(set(...)) < 2`, not `len(set(...)) != len(...)`. This enforces the
documented contract (*≥2 distinct*) without over-constraining: a 3-URN list containing one
duplicate still carries two independent principals and satisfies dual control. Whether the
partner tolerates the redundant third entry is Archytan's policy to enforce, not the
client's to pre-empt. The client enforces exactly what its docstring promises — no more.

> **Design note.** A stricter "all URNs pairwise distinct" rule is a defensible adopter
> hardening, but it would make the client's behavior diverge from its stated contract and
> from the kernel's `required_quorum` semantics. If adopted, the docstring, this section,
> and [`test_submit_envelope_rejects_duplicate_urns`](../../tests/test_actuator_01_client.py:164)
> must change together.

### 5.5 Placement: why the client and not the adapter

Distinctness is enforced at the **transport boundary** rather than in `actuate()` because
the client is the last point common to *all* submission paths. Any future caller —
a replay tool, a conformance harness, a second orchestrator — inherits the guard for free.
Placing it only in the adapter would leave the client independently unsafe.

The adapter is therefore *not* required to pre-validate distinctness. When a clearance
carries duplicate approvers, `submit_envelope()` raises `RuntimeError`, which the adapter's
Step 5 catch-all converts into a fail-closed `UNEXPECTED_ERROR` receipt. This is correct
fail-closed behavior, though §8.1 notes the finding code is imprecise.

---

## 6. Mock Signer Architecture

### 6.1 The central requirement: identity-bearing signatures

The single most important test-infrastructure decision is that mock signatures must be a
**function of operator identity**. A constant mock cannot fail a misalignment test, because
all permutations of a constant list are equal. The mock must satisfy:

```
sign(urn_a, msg) ≠ sign(urn_b, msg)    for urn_a ≠ urn_b     (distinctness)
sign(urn, msg)   = sign(urn, msg)                            (determinism)
```

Distinctness makes misalignment *observable*; determinism makes it *assertable* across
separate adapter runs.

### 6.2 Two mock variants, two purposes

`KMSGovernanceSigner` is duck-typed here: the adapter path touches only `is_kms_active`
and `sign_raw()`, so a minimal stand-in suffices (annotated `# type: ignore[arg-type]`
at call sites). Two variants exist because they answer different questions.

**Variant A — `MockPerOperatorSigner`** ([`tests/test_actuator_01_adapter.py`](../../tests/test_actuator_01_adapter.py:58)):

```python
class MockPerOperatorSigner:
    is_kms_active = True

    def __init__(self, urn: str) -> None:
        self._urn = urn

    def sign_raw(self, message: bytes) -> bytes:
        return hashlib.sha512(self._urn.encode() + message).digest()[:64]
```

Binds **both** URN and message. This is the realistic model — a real signature depends on
the payload — and it is the correct default for distinctness and fail-closed tests.

**Variant B — `SimpleMockSigner`** ([`tests/test_actuator_01_adapter.py`](../../tests/test_actuator_01_adapter.py:246)):

```python
class SimpleMockSigner:
    is_kms_active = True

    def __init__(self, urn: str) -> None:
        self._urn = urn

    def sign_raw(self, message: bytes) -> bytes:
        return hashlib.sha256(self._urn.encode()).digest() + b"\x00" * 32
```

Binds URN **only**, deliberately ignoring `message`. This exists solely for the reordering
test (§6.3). Reordering `clearance.approvals` changes the canonical envelope bytes, so a
message-bound signature would differ between the forward and reversed runs for reasons
unrelated to ordering — the assertion would be untestable. Making the signature invariant
to payload isolates the one variable under test: **position**.

> Variant B is intentionally *less* realistic. It trades payload fidelity for the ability
> to observe permutation directly. Using it outside the reordering test would weaken
> coverage, since it cannot detect a signature computed over the wrong bytes.

### 6.3 The reordering test — the load-bearing assertion

This test is what the entire resolver seam exists to enable:

```python
# Run 1: approvals ordered [alice, bob]
# Run 2: approvals ordered [bob, alice]
assert captured_forward["sigs"][0] == captured_reversed["sigs"][1]
assert captured_forward["sigs"][1] == captured_reversed["sigs"][0]
```

Signatures must permute in **lockstep** with URNs. If the loop ever derived signatures
independently of URN order, both runs would emit the same signature sequence and these
assertions would fail. This is the direct regression guard for the §4.4 invariant, and it
is the property that was structurally unobservable before the resolver existed.

### 6.4 Capture strategy

Assertions are made against what reaches the transport boundary, not against adapter
internals. `submit_envelope` is replaced with an `AsyncMock(side_effect=...)` closure that
captures `operator_urns` and `signatures` into a `nonlocal` dict and returns a real
`httpx.Response`. Using a genuine `httpx.Response` (rather than a `MagicMock`) means
`classify_response()` executes its real parsing logic, so receipt-mapping assertions
exercise the production classifier rather than a stub.

### 6.5 Test file structure

[`tests/test_actuator_01_adapter.py`](../../tests/test_actuator_01_adapter.py) —
`pytestmark = [pytest.mark.unit, pytest.mark.local]`, fully hermetic, no live endpoint:

| Class | Responsibility |
|---|---|
| `TestPerOperatorSigning` | Resolver distinctness, default-resolver identity behavior, positional alignment under reordering |
| `TestFailClosedBranches` | All six `actuate()` error branches |
| `TestReceiptFieldMapping` | `ActuationReceipt` field population on success and failure |
| `TestHealthCheckAndCapabilities` | KMS-inactive fail-closed, client delegation, capability set copying |
| `TestFromEnv` | Missing-environment-variable validation and aggregated error messages |
| `TestAsyncContextManager` | `__aenter__`/`__aexit__` lifecycle and client closure |

Shared helper `make_valid_clearance(operator_urns)` builds a valid `ExecutionClearance`
and derives `approvals` from the URN list, so ordering tests need only pass a permuted
list. Failure-branch tests mutate one field of an otherwise-valid clearance, keeping each
test's intent to a single line of divergence.

---

## 7. Test Coverage Matrix

### 7.1 The six fail-closed branches in `actuate()`

| # | Finding code | Trigger | Retryable | `envelope_digest` | Induced by |
|---|---|---|---|---|---|
| 1 | `INVALID_CLEARANCE` | `InvalidClearanceError` — non-ALLOW decision, quorum shortfall, bad UUID, TTL overrun, malformed nonce | `False` | `None` | Set `decision="DENY"` |
| 2 | `ENVELOPE_TOO_LARGE` | `EnvelopeTooLargeError` — canonical bytes > 4096 | `False` | `None` | Patch `build_and_canonicalize` |
| 3 | `ASSERTION_BUILD_FAILED` | `AssertionBuildError` / `RuntimeError` in assertion signing | `False` | **populated** | Patch `build_assertion` |
| 4 | `QUORUM_SIGNING_FAILED` | Missing `approver_urn`, resolver failure, or KMS inactive | `False` | **populated** | Blank `approvals[0]["approver_urn"]` |
| 5 | `NETWORK_ERROR` / classified transient | `httpx.HTTPError` during submission | **`True`** | **populated** | `submit_envelope` raises `httpx.ConnectError` |
| 6 | `UNEXPECTED_ERROR` | Any non-`HTTPError` exception (catch-all) | `False` | **populated** | `submit_envelope` raises `ValueError` |

The `envelope_digest` column encodes a real invariant: branches 1–2 fail *before* the
digest exists, branches 3–6 fail *after*. Every branch asserts on this, so a refactor that
reorders pipeline steps cannot pass silently. Branch 5 is the only retryable outcome —
governance-terminal failures must never be retried.

### 7.2 What the resolver seam makes newly testable

| Property | Before | After | Test |
|---|---|---|---|
| Quorum signatures are pairwise distinct | **Untestable** — no seam to inject distinct keys | Covered | `test_distinct_signatures_with_resolver` |
| `signatures[i]` corresponds to `urns[i]` | **Untestable** — constant mock hides permutation | Covered | `test_signature_urn_positional_alignment` |
| Reordering approvals reorders both lists in lockstep | **Untestable** | Covered | `test_signature_urn_positional_alignment` |
| Default (no resolver) yields identical signatures — documented, not accidental | Undocumented behavior | Pinned | `test_default_resolver_uses_base_signer` |
| Resolver invoked once per approval with correct URN | N/A — no resolver | Covered | `test_distinct_signatures_with_resolver` |
| Duplicate URNs rejected at transport | **Not enforced** — bypass existed | Covered | `test_submit_envelope_rejects_duplicate_urns` |
| All six fail-closed branches | **No adapter tests existed** | Covered | `TestFailClosedBranches` |
| Receipt field mapping (success + failure) | **No adapter tests existed** | Covered | `TestReceiptFieldMapping` |
| `health_check` fail-closed on inactive KMS | **No adapter tests existed** | Covered | `TestHealthCheckAndCapabilities` |
| `from_env` missing-variable aggregation | **No adapter tests existed** | Covered | `TestFromEnv` |
| Context-manager closes client | **No adapter tests existed** | Covered | `TestAsyncContextManager` |

### 7.3 What remains untestable offline

Honesty about the boundary matters more than a green matrix:

| Property | Why offline testing cannot establish it |
|---|---|
| Archytan accepts CAGE-produced signatures | Requires the partner's registered public keys and live verifier |
| Signatures verify against *registered operator* keys | The URN→public-key registry lives at the partner, not in CAGE |
| Wire-format acceptance of headers and 120-byte assertion | Only a live endpoint can confirm parsing |
| Real KMS Ed25519 semantics under `sign_raw()` | Mocks assert structure, not cryptographic validity |
| Micro-TTL (30s) enforcement in practice | Requires live clock skew against the partner |

Offline tests establish that CAGE **produces structurally correct, positionally aligned,
identity-distinct** quorum evidence. They cannot establish that the partner accepts it.
Closing that gap requires an integration-marked conformance run against a live or
sandboxed Archytan endpoint (§8.2).

---

## 8. Implementation Status and Residual Gaps

### 8.1 As-built status

Audit of the working tree shows the core design is **already implemented**:

| Element | Location | Status |
|---|---|---|
| `SignerResolver` type alias | [`adapter.py:79`](../../src/integrations/actuator_01/adapter.py:79) | Implemented |
| `signer_resolver` constructor parameter | [`adapter.py:122`](../../src/integrations/actuator_01/adapter.py:122) | Implemented |
| Default resolver fallback | [`adapter.py:130`](../../src/integrations/actuator_01/adapter.py:130) | Implemented |
| Per-operator signing loop | [`adapter.py:297`](../../src/integrations/actuator_01/adapter.py:297) | Implemented |
| Distinct-URN guard | [`client.py:137`](../../src/integrations/actuator_01/client.py:137) | Implemented |
| Adapter test suite | [`tests/test_actuator_01_adapter.py`](../../tests/test_actuator_01_adapter.py) | Implemented (610 lines) |
| Client distinctness test | [`tests/test_actuator_01_client.py:164`](../../tests/test_actuator_01_client.py:164) | Implemented |

Remaining work is therefore **verification and gap closure**, not greenfield implementation.

### 8.2 Residual gaps

| ID | Gap | Severity | Proposed resolution |
|---|---|---|---|
| **G1** | `from_env()` does not accept or forward `signer_resolver`. Any adapter built via `from_env()` is permanently locked to single-key mode. | Medium | Add `signer_resolver: SignerResolver \| None = None` to `from_env()` and pass through to `cls(...)`. |
| **G2** | Duplicate approver URNs surface as `UNEXPECTED_ERROR` (catch-all) rather than a dedicated code. Fail-closed is preserved, but the finding is imprecise and hard to triage. | Medium | Catch `RuntimeError` from `submit_envelope` separately and emit `QUORUM_VALIDATION_FAILED`; or pre-validate distinctness in Step 4 while retaining the client guard per §5.5. |
| **G3** | No adapter-level test asserts that duplicate approvals fail closed end-to-end. Enforcement is proven only at the client. | Medium | Add `test_duplicate_approver_urns_fail_closed` to `TestFailClosedBranches`. |
| **G4** | No test asserts resolver-raises-on-unknown-URN maps to `QUORUM_SIGNING_FAILED`. §3.2's contract is documented but unverified. | Low | Add a resolver that raises `RuntimeError`; assert the finding code. |
| **G5** | No test asserts the resolver is called once per approval with exactly the expected URNs. | Low | Record calls in a list; assert equality with the approval URN sequence. |
| **G6** | Partner-side signature verification remains unproven (§7.3). | Accepted | Integration-marked conformance test against a sandboxed endpoint; out of scope for offline CI. |

G1 is the most consequential: it means the production construction path cannot use the
seam this design exists to provide.

### 8.3 Layer compliance

All changes are confined to Layer 3 (`src/integrations/actuator_01/`). No kernel file is
modified. The dependency direction is preserved — the adapter imports
`KMSGovernanceSigner` and the `ExecutionActuator` protocol *from* the kernel; nothing in
`src/gateway/` learns about actuator_01. `SignerResolver` is declared in the integration
package, not the kernel, because operator-key topology is a vendor-integration concern.
Gate G3 (`scripts/check_import_boundaries.py`) is unaffected.

### 8.4 Breaking-change assessment

Per AGENTS.md, breaking changes are acceptable when they buy structural clarity. **None
were required.** `signer_resolver` is keyword-optional and defaults to prior behavior;
existing call sites compile and behave identically. The client distinctness guard is
technically behavior-changing — previously-accepted duplicate-URN submissions now raise —
but that path was a dual-control bypass, so tightening it is a defect fix, not a
regression. No deprecation shim is owed.

Existing coverage in [`test_actuator_01_signatures.py`](../../tests/test_actuator_01_signatures.py)
is untouched: `sign_for_quorum()`'s signature and domain-tag construction are unchanged.

### 8.5 Implementation checklist

1. Verify as-built elements in §8.1 against the working tree.
2. Close **G1** — thread `signer_resolver` through `from_env()`; add a construction test.
3. Close **G2** — introduce a distinct finding code for quorum validation failures.
4. Close **G3**, **G4**, **G5** — add the three adapter tests.
5. Run `uv run pytest tests/test_actuator_01_*.py -v` — all must pass.
6. Run `uv run python scripts/check_import_boundaries.py --verbose` — Gate G3 clean.
7. Run `uv run ruff check . && uv run mypy src/`.
8. Cross-reference this document from
   [`actuator_01_kms_iam_model.md`](actuator_01_kms_iam_model.md) §3, which describes the
   seam this design realizes.

---

## 9. Summary

The defect was one loop passing a single signer N times. The fix is not a patch to that
loop but the introduction of a **seam**: `SignerResolver` makes operator-key topology an
injected concern, which simultaneously fixes the defect, expresses the security boundary
from the KMS IAM model, and — decisively — makes multi-party quorum semantics *observable
in tests* for the first time. The distinct-URN guard closes a dual-control bypass at the
transport boundary. The URN-keyed mock signer is what converts "we believe signatures are
aligned" into an assertion that fails when they are not.
