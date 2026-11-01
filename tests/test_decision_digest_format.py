# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Decision digests: one format and one meaning on every writer (POAM-2026-149).

Three writers put a decision-digest field into the evidence stream, whose
WORM-archived copy cannot be redacted: ``ExecutionClearance`` (actuation
receipts), ``QuarantineDirective`` (``WORKLOAD_QUARANTINE_RECEIPT`` and
actuator_03's signed wire body) and actuator_02's ``OcsfEventModel``
(``SANDBOX_OCSF_TELEMETRY``). These tests pin:

1. The shared validator (``seams.digests``): lowercase SHA-256 hex matched in
   full, an error that names the field and never echoes the value, and no
   kernel import.
2. Every writer refuses a seal (both seal formats contain ``.``) and any
   other non-digest, without echoing it.
3. A ``QuarantineDirective`` carries exactly one of
   ``governance_decision_digest`` (a clearance's seal digest) and
   ``refusal_proof_hash`` (a refusal receipt's proof hash), and serializes
   only that one.
4. The kernel's refusal-triggered quarantine records ``refusal_proof_hash``,
   fails closed without masking the DENY, and actuator_03's clearance bridge
   signs ``governance_decision_digest``.
5. The stream oracle's ``digest_format`` rule, in ``proof/`` and in the
   packaged copy, flags a bad value at any depth of any event type, and a
   refusal-triggered quarantine receipt follows its refusal.

Seals are minted by the production ``generate_seal`` in both formats.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import fakeredis
import fakeredis.aioredis
import pytest
import pytest_asyncio
from pydantic import ValidationError

import src.gateway.governance.kms_signer as ks
import src.gateway.governance.routing_seal as rs
from proof.stream_invariants import check_stream, compute_cage_audit_hash, jcs_bytes
from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.evidence import stream as es_module
from src.gateway.governance.evidence.stream import EvidenceStreamSink
from src.gateway.governance.governor import verdicts
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.quarantine_actuator import (
    SimulatedQuarantineActuator,
    dispatch_quarantine,
)
from src.gateway.governance.seams import digests
from src.gateway.governance.seams.actuation import ExecutionClearance
from src.gateway.governance.seams.digests import is_sha256_hex, require_sha256_hex
from src.gateway.governance.seams.quarantine import (
    QuarantineDirective,
    QuarantineTriggerReason,
)
from src.integrations.actuator_02.ocsf_ingestor import (
    OcsfEventModel,
    OcsfEvidenceIngestor,
)
from src.integrations.actuator_03.adapter import Actuator03Adapter
from src.integrations.actuator_03.constants import QUARANTINE_ASSERTION_DOMAIN_TAG

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE_SRC = _REPO_ROOT / "packages" / "cage-conformance" / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

import cage_conformance as cc  # noqa: E402
from cage_conformance.stream_invariants import (  # noqa: E402
    check_stream as packaged_check_stream,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_SINK = "src.gateway.governance.evidence.stream.get_evidence_sink"
_STREAM_KEY = "cage:test:decision-digest-stream"
_DIGEST = hashlib.sha256(b"decision").hexdigest()
_OTHER = hashlib.sha256(b"another decision").hexdigest()
_FIELDS = ("governance_decision_digest", "refusal_proof_hash")

#: Values every writer must refuse. "digest-abc-123" is the actuator_03
#: fixture the old QuarantineDirective accepted, and the old OCSF rule (any
#: 8-128 characters) accepted it too.
_NON_DIGESTS: list[Any] = [
    "",
    "digest-abc-123",
    _DIGEST.upper(),
    _DIGEST[:-1],
    _DIGEST + "0",
    "g" * 64,
    _DIGEST + "\n",
    " " + _DIGEST,
    None,
    64,
    _DIGEST.encode(),
]
_NON_DIGEST_IDS = [
    "empty",
    "old-fixture",
    "upper",
    "short",
    "long",
    "non-hex",
    "newline",
    "leading-space",
    "none",
    "int",
    "bytes",
]


@pytest.fixture(autouse=True)
def _test_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)


@pytest.fixture(params=["hmac", "jwt"])
async def seal(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """A real seal from ``generate_seal``, in each of its two formats."""
    provider = (
        ks.SoftwareEd25519Provider(key_id="decision-digest-k1")
        if request.param == "jwt"
        else None
    )
    monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=provider))
    minted = await rs.generate_seal(
        "execute_trade", {"symbol": "AAPL", "amount": 10.0}, record_hash="c" * 64
    )
    assert rs._is_jwt_seal(minted) is (request.param == "jwt")
    assert "." in minted
    return minted


class _CapturingSink:
    """An evidence sink that keeps every record it is handed."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def ingest(self, event: dict[str, Any]) -> str:
        self.events.append(event)
        return f"{len(self.events)}-0"

    def of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e.get("type") == event_type]

    def only(self, event_type: str) -> dict[str, Any]:
        matching = self.of_type(event_type)
        assert len(matching) == 1, [e.get("type") for e in self.events]
        return matching[0]


class _CapturingSigner:
    """actuator_03's signer seam, recording the exact bytes it is asked to sign."""

    def __init__(self) -> None:
        self.messages: list[bytes] = []

    @property
    def is_kms_active(self) -> bool:
        return False  # software stub, never a KMS key

    def sign_raw(self, message: bytes) -> bytes:
        self.messages.append(message)
        return hashlib.sha256(message).digest() * 2

    async def sign_raw_async(self, message: bytes) -> bytes:
        return self.sign_raw(message)

    def signed_body(self) -> dict[str, Any]:
        (message,) = self.messages
        assert message.startswith(QUARANTINE_ASSERTION_DOMAIN_TAG)
        body: dict[str, Any] = json.loads(
            message[len(QUARANTINE_ASSERTION_DOMAIN_TAG) :]
        )
        return body


def _directive(**digest: Any) -> QuarantineDirective:
    return QuarantineDirective(
        thread_id="thread-q-1",
        agent_svid="spiffe://cluster.local/ns/cage/sa/agent",
        sandbox_id="sbx-1",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=("CBF_BARRIER_VIOLATION",),
        issued_at=1785012000,
        correlation_id="corr-q-1",
        nonce="d" * 32,
        **digest,
    )


def _clearance(*, digest: Any, routing_seal: str | None = None) -> ExecutionClearance:
    return ExecutionClearance(
        thread_id="t-1",
        decision="ALLOW",
        decision_path="DIRECT",
        action="quarantine_workload",
        target="sbx-1",
        operator_urn="spiffe://cluster.local/ns/cage/sa/agent",
        issued_at=1785012000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="t-1",
        correlation_id_source="THREAD_DERIVED",
        governance_decision_digest=digest,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        params={"sandbox_id": "sbx-1"},
        routing_seal=routing_seal,
    )


def _hard_breach() -> list[Violation]:
    return [
        Violation(
            tier="CBF",
            code="CBF_BARRIER_VIOLATION",
            message="Barrier breached",
            kind=ViolationKind.HARD,
        )
    ]


def _breach_params() -> dict[str, Any]:
    return {
        "_caller_principal": "spiffe://cluster.local/ns/cage/sa/breach-agent",
        "thread_id": "thread-breach-1",
        "_quarantine_on_breach": True,
    }


def _ocsf(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "class_uid": 4001,
        "sandbox_id": "sbx-1",
        "thread_id": "thread-1",
        "governance_decision_digest": _DIGEST,
    }
    return event | overrides


def _chain(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Valid ``cage-audit/3.0`` records for ``payloads``, from genesis."""
    records: list[dict[str, Any]] = []
    prev_hash = ""
    for sequence, payload in enumerate(payloads):
        payload_json = jcs_bytes(payload).decode("utf-8")
        fields = {
            "event_type": str(payload["type"]),
            "control_id": "AU-3",
            "trace_id": "0123456789abcdef0123456789abcdef",
            "chain_id": "chain-1",
        }
        record_hash = compute_cage_audit_hash(
            prev_hash=prev_hash,
            sequence=sequence,
            payload_json=payload_json,
            **fields,
        )
        records.append(
            {
                "schema": "cage-audit/3.0",
                "sequence": str(sequence),
                "timestamp_utc": "2026-10-31T19:00:00+00:00",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "evidence_class": "GOVERNANCE",
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "payload_json": payload_json,
                **fields,
            }
        )
        prev_hash = record_hash
    return records


def _rules(records: list[dict[str, Any]], **kwargs: Any) -> list[str]:
    return [f.rule for f in check_stream(records, **kwargs)]


def _assert_not_echoed(seal: str, *texts: str) -> None:
    """Neither the seal nor its first 16 characters appear in any of ``texts``."""
    for text in texts:
        assert seal not in text, "a refusal echoed the seal"
        assert seal[:16] not in text, "a refusal echoed part of the seal"


# ---------------------------------------------------------------------------
# 1. The shared validator
# ---------------------------------------------------------------------------


def test_validator_accepts_a_sha256_hexdigest() -> None:
    assert is_sha256_hex(_DIGEST)
    assert require_sha256_hex(_DIGEST, field="some_field") == _DIGEST


@pytest.mark.parametrize("value", _NON_DIGESTS, ids=_NON_DIGEST_IDS)
def test_validator_refuses_a_non_digest_naming_the_field(value: Any) -> None:
    assert not is_sha256_hex(value)
    with pytest.raises(ValueError, match="SHA-256") as refused:
        require_sha256_hex(value, field="some_field")
    message = str(refused.value)
    assert message.startswith("some_field ")
    assert _DIGEST not in message, "the refusal echoed the refused value"


async def test_validator_refuses_a_seal_without_echoing_it(seal: str) -> None:
    with pytest.raises(ValueError) as refused:
        require_sha256_hex(seal, field="governance_decision_digest")
    _assert_not_echoed(seal, str(refused.value), repr(refused.value))


def test_digest_module_imports_only_the_standard_library() -> None:
    """The seam stays pure: any writer can use it without the kernel."""
    tree = ast.parse(Path(digests.__file__).read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import in the digest seam"
            roots.add((node.module or "").split(".")[0])
    assert roots <= set(sys.stdlib_module_names), sorted(roots)


# ---------------------------------------------------------------------------
# 2. ExecutionClearance applies the same rule
# ---------------------------------------------------------------------------


async def test_clearance_refuses_through_the_shared_validator(seal: str) -> None:
    with pytest.raises(ValueError) as refused:
        _clearance(digest=seal, routing_seal=seal)
    with pytest.raises(ValueError) as shared:
        require_sha256_hex(seal, field="governance_decision_digest")
    assert str(refused.value) == str(shared.value)
    assert seal not in str(refused.value)


# ---------------------------------------------------------------------------
# 3. QuarantineDirective: exactly one digest, each with one meaning
# ---------------------------------------------------------------------------


def test_directive_needs_exactly_one_digest() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        _directive()
    with pytest.raises(ValueError, match="exactly one"):
        _directive(governance_decision_digest=_DIGEST, refusal_proof_hash=_OTHER)
    # An empty string is set, not absent: it counts towards "both".
    with pytest.raises(ValueError, match="exactly one"):
        _directive(governance_decision_digest="", refusal_proof_hash=_OTHER)


@pytest.mark.parametrize("field", _FIELDS)
@pytest.mark.parametrize(
    "value",
    [v for v in _NON_DIGESTS if v is not None],  # None is "not set"
    ids=[
        i for v, i in zip(_NON_DIGESTS, _NON_DIGEST_IDS, strict=True) if v is not None
    ],
)
def test_directive_refuses_a_non_digest_in_either_field(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="SHA-256") as refused:
        _directive(**{field: value})
    assert str(refused.value).startswith(f"{field} ")


@pytest.mark.parametrize("field", _FIELDS)
async def test_directive_refuses_a_seal_in_either_field(seal: str, field: str) -> None:
    with pytest.raises(ValueError, match="SHA-256") as refused:
        _directive(**{field: seal})
    _assert_not_echoed(seal, str(refused.value))


def test_directive_serializes_only_the_field_that_is_set() -> None:
    by_clearance = _directive(governance_decision_digest=_DIGEST).to_dict()
    assert by_clearance["governance_decision_digest"] == _DIGEST
    assert "refusal_proof_hash" not in by_clearance

    by_refusal = _directive(refusal_proof_hash=_OTHER).to_dict()
    assert by_refusal["refusal_proof_hash"] == _OTHER
    assert "governance_decision_digest" not in by_refusal


def test_directive_is_keyword_only() -> None:
    """No value can land in another field's position (the healthcare defect)."""
    with pytest.raises(TypeError):
        QuarantineDirective(  # type: ignore[misc]
            "thread-q-1",
            "spiffe://cluster.local/ns/cage/sa/agent",
            "sbx-1",
            QuarantineTriggerReason.CRITICAL_CBF_BREACH,
            ("CBF_BARRIER_VIOLATION",),
            1785012000,
            "corr-q-1",
            "d" * 32,
        )


# ---------------------------------------------------------------------------
# 4. The writers: dispatch_quarantine, handle_deny, actuator_03, actuator_02
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "absent"),
    [
        ("refusal_proof_hash", "governance_decision_digest"),
        ("governance_decision_digest", "refusal_proof_hash"),
    ],
)
async def test_quarantine_receipt_records_the_digest_under_its_own_name(
    monkeypatch: pytest.MonkeyPatch, field: str, absent: str
) -> None:
    sink = _CapturingSink()
    monkeypatch.setattr(_SINK, lambda: sink)
    await dispatch_quarantine(
        _directive(**{field: _DIGEST}), actuator=SimulatedQuarantineActuator()
    )
    record = sink.only("WORKLOAD_QUARANTINE_RECEIPT")
    assert record[field] == _DIGEST
    assert absent not in record


async def test_refusal_triggered_quarantine_records_the_refusal_proof_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink = _CapturingSink()
    monkeypatch.setattr(_SINK, lambda: sink)
    monkeypatch.setenv("CAGE_QUARANTINE_ACTUATOR", "simulated")

    with pytest.raises(GovernanceError) as denied:
        await verdicts.handle_deny(
            action="transfer_funds",
            params=_breach_params(),
            violations=_hard_breach(),
            tier_failures=[],
        )

    assert denied.value.receipt is not None
    proof_hash = denied.value.receipt.proof_hash
    # Computed by RefusalReceipt.__post_init__, never supplied by the caller.
    assert is_sha256_hex(proof_hash)
    assert sink.only("GOVERNANCE_REFUSAL")["receipt"]["proof_hash"] == proof_hash
    quarantine = sink.only("WORKLOAD_QUARANTINE_RECEIPT")
    assert quarantine["refusal_proof_hash"] == proof_hash
    assert "governance_decision_digest" not in quarantine
    assert denied.value.payload["quarantined"] is True


async def test_an_invalid_refusal_hash_refuses_the_quarantine_not_the_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fault injection: if proof_hash were ever malformed, the DENY still stands."""
    sink = _CapturingSink()
    monkeypatch.setattr(_SINK, lambda: sink)
    monkeypatch.setenv("CAGE_QUARANTINE_ACTUATOR", "simulated")
    built = verdicts.build_refusal_receipt

    def _malformed(*args: Any, **kwargs: Any) -> Any:
        return dataclasses.replace(built(*args, **kwargs), proof_hash="not-a-digest")

    monkeypatch.setattr(verdicts, "build_refusal_receipt", _malformed)
    dispatched = AsyncMock()
    monkeypatch.setattr(
        "src.gateway.governance.quarantine_actuator.dispatch_quarantine", dispatched
    )

    with pytest.raises(GovernanceError) as denied:
        await verdicts.handle_deny(
            action="transfer_funds",
            params=_breach_params(),
            violations=_hard_breach(),
            tier_failures=[],
        )

    assert denied.value.payload["quarantined"] is False
    assert denied.value.payload["quarantine_error"] == "QUARANTINE_DIRECTIVE_INVALID"
    dispatched.assert_not_awaited()
    assert sink.of_type("WORKLOAD_QUARANTINE_RECEIPT") == []


async def test_actuator_03_bridge_signs_the_clearance_seal_digest(seal: str) -> None:
    signer = _CapturingSigner()
    adapter = Actuator03Adapter(endpoint="https://dpu.example.test", signer=signer)
    receipt = await adapter.actuate(
        _clearance(digest=rs.seal_digest(seal), routing_seal=seal)
    )
    # No mTLS client: refused after signing, before anything leaves the process.
    assert receipt.accepted is False
    body = signer.signed_body()
    assert body["governance_decision_digest"] == rs.seal_digest(seal)
    assert "refusal_proof_hash" not in body
    assert seal not in signer.messages[0].decode("utf-8")


async def test_actuator_03_signs_a_refusal_triggered_directive_with_its_refusal_hash() -> (
    None
):
    """The partner-visible wire change: the kernel's directive names its refusal."""
    signer = _CapturingSigner()
    adapter = Actuator03Adapter(endpoint="https://dpu.example.test", signer=signer)
    await adapter.quarantine_workload(_directive(refusal_proof_hash=_OTHER))
    body = signer.signed_body()
    assert body["refusal_proof_hash"] == _OTHER
    assert "governance_decision_digest" not in body


def test_ocsf_accepts_a_seal_digest_at_the_top_and_nested() -> None:
    nested = {"events": [{"governance_decision_digest": _DIGEST}]}
    model = OcsfEventModel.model_validate(_ocsf(metadata=nested))
    assert model.governance_decision_digest == _DIGEST


@pytest.mark.parametrize(
    "value",
    [v for v in _NON_DIGESTS if isinstance(v, str)],
    ids=[
        i
        for v, i in zip(_NON_DIGESTS, _NON_DIGEST_IDS, strict=True)
        if isinstance(v, str)
    ],
)
def test_ocsf_refuses_a_non_digest_without_echoing_it(value: str) -> None:
    with pytest.raises(ValidationError) as refused:
        OcsfEventModel.model_validate(_ocsf(governance_decision_digest=value))
    text = str(refused.value)
    assert "governance_decision_digest" in text
    if value.strip():
        assert value.strip() not in text, "the error echoed the refused value"
        assert value.strip() not in repr(refused.value)


async def test_ocsf_refuses_a_seal_without_echoing_it(seal: str) -> None:
    with pytest.raises(ValidationError) as refused:
        OcsfEventModel.model_validate(_ocsf(governance_decision_digest=seal))
    assert "governance_decision_digest" in str(refused.value)
    # pydantic truncates a long input it displays, so a full-value check alone
    # would pass even with hide_input_in_errors off; the prefix check would not.
    _assert_not_echoed(seal, str(refused.value), repr(refused.value))


@pytest.mark.parametrize("field", _FIELDS)
def test_ocsf_checks_digests_nested_in_metadata(field: str) -> None:
    metadata = {"process": {"children": [{field: "digest-abc-123"}]}}
    with pytest.raises(ValidationError) as refused:
        OcsfEventModel.model_validate(_ocsf(metadata=metadata))
    assert f"{field} inside metadata" in str(refused.value)
    assert "digest-abc-123" not in str(refused.value)


async def test_ocsf_record_carries_the_seal_digest() -> None:
    sink = _CapturingSink()
    await OcsfEvidenceIngestor(sink=sink).ingest_ocsf_event(_ocsf())
    assert sink.only("SANDBOX_OCSF_TELEMETRY")["governance_decision_digest"] == _DIGEST


# ---------------------------------------------------------------------------
# 5. The stream oracle: digest_format and the quarantine binding
# ---------------------------------------------------------------------------


def test_digest_format_passes_digests_at_every_depth() -> None:
    records = _chain(
        [
            {
                "type": "AUDIT_NOTE",
                "governance_decision_digest": _DIGEST,
                "nested": {"refusal_proof_hash": _OTHER},
                "items": [{"governance_decision_digest": _DIGEST}],
            }
        ]
    )
    assert check_stream(records) == []


_BAD_RECORDS = [
    pytest.param(
        {
            "type": "SANDBOX_OCSF_TELEMETRY",
            "governance_decision_digest": "digest-abc-123",
        },
        "governance_decision_digest",
        id="ignored-type-top-level",
    ),
    pytest.param(
        {
            "type": "AUDIT_NOTE",
            "metadata": {"process": {"refusal_proof_hash": "A" * 64}},
        },
        "metadata.process.refusal_proof_hash",
        id="nested-mapping",
    ),
    pytest.param(
        {
            "type": "AUDIT_NOTE",
            "events": [{"governance_decision_digest": _DIGEST + "\n"}],
        },
        "events[0].governance_decision_digest",
        id="nested-list-newline",
    ),
    pytest.param(
        {"type": "WORKLOAD_QUARANTINE_RECEIPT", "refusal_proof_hash": None},
        "refusal_proof_hash",
        id="non-str",
    ),
]


@pytest.mark.parametrize(("payload", "path"), _BAD_RECORDS)
def test_digest_format_flags_a_bad_value_anywhere(
    payload: dict[str, Any], path: str
) -> None:
    findings = [f for f in check_stream(_chain([payload])) if f.rule == "digest_format"]
    assert len(findings) == 1, findings
    assert findings[0].index == 0
    assert f"{payload['type']} {path} " in findings[0].detail


async def test_digest_format_never_echoes_the_value(seal: str) -> None:
    records = _chain([{"type": "AUDIT_NOTE", "refusal_proof_hash": seal}])
    (finding,) = check_stream(records)
    assert finding.rule == "digest_format"
    _assert_not_echoed(seal, finding.detail)


def test_actuation_digests_are_checked_by_both_rules() -> None:
    records = _chain(
        [
            {
                "type": "ACTUATION_RECEIPT",
                "action": "a",
                "governance_decision_digest": "x",
            }
        ]
    )
    assert set(_rules(records)) == {"digest_format", "no_direct_bind"}


def _refusal(proof_hash: str) -> dict[str, Any]:
    return {
        "type": "GOVERNANCE_REFUSAL",
        "controlId": "AC-3",
        "receipt": {"proof_hash": proof_hash},
    }


def _quarantine(proof_hash: str) -> dict[str, Any]:
    return {
        "type": "WORKLOAD_QUARANTINE_RECEIPT",
        "controlId": "SC-7",
        "refusal_proof_hash": proof_hash,
    }


def test_a_quarantine_receipt_follows_its_refusal() -> None:
    assert _rules(_chain([_refusal(_DIGEST), _quarantine(_DIGEST)])) == []
    assert _rules(_chain([_quarantine(_DIGEST)])) == ["refusal_evidence"]
    assert _rules(_chain([_quarantine(_DIGEST), _refusal(_DIGEST)])) == [
        "refusal_evidence"
    ]
    assert _rules(_chain([_refusal(_OTHER), _quarantine(_DIGEST)])) == [
        "refusal_evidence"
    ]
    # A slice that starts after genesis may hold the quarantine but not its
    # refusal, so the binding is checked only on a log read from genesis.
    assert _rules(_chain([_refusal(_DIGEST), _quarantine(_DIGEST)])[1:]) == []


def test_the_packaged_oracle_flags_the_same() -> None:
    payload = {
        "type": "SANDBOX_OCSF_TELEMETRY",
        "governance_decision_digest": "refused-value-xyz",
    }
    records = _chain([payload])
    assert [f.rule for f in packaged_check_stream(records)] == ["digest_format"]
    assert [f.rule for f in packaged_check_stream(_chain([_quarantine(_DIGEST)]))] == [
        "refusal_evidence"
    ]

    assert "digest_format" in cc.STREAM_RULES
    adapter = cc.AdapterUnderTest(
        provider_id="cage-kernel",
        adapter_author_org="Google LLC",
        counterparty_org="Example Deployer",
        adapter_version="5.0.0",
        adapter_commit="5b0055ad",
        contract_profile="stream-v1",
    )
    runner = cc.RunnerProvenance(
        runner_org="Google LLC",
        runner_identity="ci@example.com",
        cage_conformance_version=cc.__version__,
        timestamp_utc="2026-10-31T19:00:00+00:00",
    )
    report = cc.verify_stream(
        records,
        provenance=cc.build_provenance(adapter, runner),
        inputs=(cc.InputDigest.of_bytes("stream.jsonl", jcs_bytes(records)),),
    )
    failed = [a for a in report.assertions if not a.passed]
    assert [a.assertion_id for a in failed] == ["digest_format"]
    assert failed[0].title == cc.STREAM_RULES["digest_format"]
    assert "governance_decision_digest" in failed[0].detail
    assert "refused-value-xyz" not in failed[0].detail


# ---------------------------------------------------------------------------
# 6. End to end: the kernel's quarantine path writes a conformant stream
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def real_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[SimpleNamespace]:
    """A real ``EvidenceStreamSink`` on ``FakeRedis``."""
    server = fakeredis.FakeServer()
    redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    sink = EvidenceStreamSink(
        redis_url="redis://localhost:6379", stream_key=_STREAM_KEY
    )
    sink._redis = redis
    monkeypatch.setattr(es_module, "get_evidence_sink", lambda: sink)
    yield SimpleNamespace(sink=sink, redis=redis)
    await sink.stop()


async def test_a_kernel_quarantine_writes_a_conformant_stream(
    real_stream: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CAGE_QUARANTINE_ACTUATOR", "simulated")
    with pytest.raises(GovernanceError) as denied:
        await verdicts.handle_deny(
            action="transfer_funds",
            params=_breach_params(),
            violations=_hard_breach(),
            tier_failures=[],
        )
    assert denied.value.receipt is not None
    proof_hash = denied.value.receipt.proof_hash

    raw = await real_stream.redis.xrange(_STREAM_KEY)
    assert [fields["event_type"] for _id, fields in raw] == [
        "GOVERNANCE_REFUSAL",
        "WORKLOAD_QUARANTINE_RECEIPT",
    ]
    quarantine = json.loads(raw[1][1]["payload_json"])
    assert quarantine["refusal_proof_hash"] == proof_hash
    assert check_stream(raw, expected_refusal_hashes=[proof_hash]) == []
