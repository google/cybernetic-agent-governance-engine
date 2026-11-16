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

"""Unit tests for Gate 11 (scripts/check_producer_consumer_keys.py)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scripts.check_producer_consumer_keys import (
    DEFAULT_REPO_ROOT,
    MIN_ENVELOPE_CONSUMER_FILES,
    MIN_PRODUCED_EVENT_TYPES,
    MIN_STREAM_CONSUMER_FILES,
    MIN_VERIFIED_KEY_READS,
    MIN_VERIFIED_TEST_FIXTURE_RESPONSES,
    main,
    run_check,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


def test_live_repo_passes_with_zero_baseline_and_floors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Live repository passes Gate 11 with zero baseline file and non-vacuous floors."""
    assert not (DEFAULT_REPO_ROOT / ".key-drift-baseline").exists()

    violations, stats = run_check(DEFAULT_REPO_ROOT, enforce_floors=True, verbose=False)
    assert violations == [], "Unexpected Gate 11 violations:\n" + "\n".join(
        v.format() for v in violations
    )
    assert stats["produced_event_types"] >= MIN_PRODUCED_EVENT_TYPES
    assert stats["stream_consumer_files"] >= MIN_STREAM_CONSUMER_FILES
    assert stats["envelope_consumer_files"] >= MIN_ENVELOPE_CONSUMER_FILES
    assert stats["verified_key_reads"] >= MIN_VERIFIED_KEY_READS
    assert (
        stats["verified_test_fixture_responses"] >= MIN_VERIFIED_TEST_FIXTURE_RESPONSES
    )

    rc = main(["--repo-root", str(DEFAULT_REPO_ROOT), "--verbose"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "OK: Gate 11 passed" in captured.out


def test_planted_check8b_refusal_and_fence_mismatch_fails(tmp_path: Path) -> None:
    """Unproduced fence event types and Check 8b RefusalReceipt keys fail closed."""
    _write(
        tmp_path / "src/gateway/governance/contracts.py",
        """
        class RefusalReceipt:
            def to_dict(self) -> dict[str, object]:
                return {
                    "type": "GOVERNANCE_REFUSAL_RECEIPT",
                    "receipt_id": "r-1",
                    "violated_rule": "rule-1",
                    "proof_hash": "abc",
                }
        """,
    )
    _write(
        tmp_path / "src/gateway/governance/governor/verdicts.py",
        """
        def publish_refusal(sink, receipt):
            sink.ingest_sync(
                {
                    "type": "GOVERNANCE_REFUSAL",
                    "action": "execute_trade",
                    "violated_rule": "rule-1",
                    "receipt": receipt.to_dict(),
                },
                event_type="GOVERNANCE_REFUSAL",
            )
        """,
    )
    _write(
        tmp_path
        / "packages/cage-conformance/src/cage_conformance/stream_invariants.py",
        """
        _RECONCILIATION_FENCE_EVENT_TYPES = frozenset(
            {"CBF_FENCE_REJECTED", "RECONCILIATION_FENCE"}
        )

        def check_stream(records):
            for rec in records:
                event_type = rec["event_type"]
                payload = rec["payload"]
                if event_type in _RECONCILIATION_FENCE_EVENT_TYPES:
                    pass
                if event_type == "GOVERNANCE_REFUSAL":
                    _ = payload.get("violated_rule")
                    _ = payload.get("reconciliation_fence_epoch")
                    receipt = payload.get("receipt")
                    for key in ("reason", "audit_code"):
                        _ = receipt.get(key)
        """,
    )

    violations, _ = run_check(tmp_path, enforce_floors=False)
    kinds = {v.kind for v in violations}
    assert "unproduced-event-type" in kinds
    assert "unproduced-payload-key" in kinds
    assert "unproduced-receipt-key" in kinds

    details = "\n".join(v.format() for v in violations)
    assert "CBF_FENCE_REJECTED" in details
    assert "RECONCILIATION_FENCE" in details
    assert "reconciliation_fence_epoch" in details
    assert "reason" in details
    assert "audit_code" in details
    assert "violated_rule" not in [
        v.detail.split("'")[1] for v in violations if "'" in v.detail
    ]


def test_planted_compliance_bridge_metrics_mismatch_fails_without_webhook_false_positive(
    tmp_path: Path,
) -> None:
    """Stream-consuming compliance_bridge modules fail on unproduced events/keys."""
    _write(
        tmp_path / "src/gateway/governance/governor/sealing.py",
        """
        def consume(sink):
            sink.ingest(
                {
                    "type": "GOVERNANCE_SEAL_CONSUMED",
                    "seal_jti": "jti-1",
                    "control_id": "AC-3",
                },
                event_type="GOVERNANCE_SEAL_CONSUMED",
            )
        """,
    )
    # Standalone webhook module (no cage:evidence:stream reference) must NOT trigger.
    _write(
        tmp_path / "src/compliance_bridge/governance_webhook.py",
        """
        _ALL_EVENT_TYPES = frozenset({"CBF_VIOLATION", "OPA_DENY"})
        """,
    )
    # Evidence stream consumer referencing unproduced event names & payload keys MUST fail.
    _write(
        tmp_path / "src/compliance_bridge/metrics.py",
        """
        STREAM_KEY = "cage:evidence:stream"
        _PASS_EVENT_TYPES = frozenset({"SEAL_CONSUMED", "EXECUTION_ACTUATED"})

        def aggregate(payload: dict[str, object], event_type: str) -> None:
            if event_type == "GOVERNANCE_SEAL_CONSUMED":
                _ = payload.get("seal_jti")
                _ = payload.get("iso_control")
        """,
    )

    violations, _ = run_check(tmp_path, enforce_floors=False)
    files = {v.file for v in violations}
    assert "src/compliance_bridge/governance_webhook.py" not in files
    assert "src/compliance_bridge/metrics.py" in files

    details = "\n".join(v.format() for v in violations)
    assert "SEAL_CONSUMED" in details
    assert "EXECUTION_ACTUATED" in details
    assert "iso_control" in details


def test_planted_dead_envelope_preview_fields_fail(tmp_path: Path) -> None:
    """Client SDK reads of unpopulated GovernanceEnvelope sub-block keys fail closed."""
    _write(
        tmp_path / "src/gateway/governance/governance_envelope.py",
        """
        class IssuerMetadata:
            def to_dict(self):
                return {"id": "cage", "version": "1.0"}

        class SubjectMetadata:
            def to_dict(self):
                return {"action": "read_portfolio", "params_hash": "sha256:1"}

        class GovernanceContext:
            def to_dict(self):
                return {"decision": "ALLOW", "evaluated_at": "2026-01-01T00:00:00Z"}

        class EnvelopeSignature:
            def to_dict(self):
                return {"algorithm": "ECDSA_P256_SHA256", "kid": "k1", "value": "sig"}

        class GovernanceEnvelope:
            def to_dict(self):
                return {
                    "envelope_id": "env-1",
                    "schema_version": "1.0",
                    "issuer": {},
                    "subject": {},
                    "governance_context": {},
                    "signature": {},
                }
        """,
    )
    _write(
        tmp_path / "packages/cage-client/src/cage_client/core.py",
        """
        def inspect_envelope(envelope):
            _ = envelope.subject.get("action")
            _ = envelope.subject.get("record_hash")
            _ = envelope.governance_context.get("controls_satisfied")
        """,
    )

    violations, _ = run_check(tmp_path, enforce_floors=False)
    assert len(violations) == 2
    assert all(v.kind == "unproduced-envelope-key" for v in violations)
    details = "\n".join(v.format() for v in violations)
    assert "record_hash" in details
    assert "controls_satisfied" in details


def test_function_scoped_lazy_import_producer_is_recognized(tmp_path: Path) -> None:
    """Producer constants imported lazily inside functions (Gate G3 pattern) resolve cleanly."""
    _write(
        tmp_path / "src/gateway/governance/schemas/thresholds.py",
        """
        RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE = "RECONCILIATION_DISCREPANCY_FENCE"
        """,
    )
    _write(
        tmp_path / "src/gateway/governance/reconciliation/daemon.py",
        """
        def emit_fence(stream):
            from src.gateway.governance.schemas.thresholds import (
                RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE,
            )
            stream.append_record(
                event_type=RECONCILIATION_DISCREPANCY_FENCE_EVENT_TYPE,
                payload={"fence_epoch": 3, "agent_id": "a-1"},
            )
        """,
    )
    _write(
        tmp_path / "proof/stream_invariants.py",
        """
        def check_stream(records):
            for rec in records:
                event_type = rec["event_type"]
                payload = rec["payload"]
                if event_type == "RECONCILIATION_DISCREPANCY_FENCE":
                    _ = payload.get("fence_epoch")
                    _ = payload.get("agent_id")
        """,
    )

    violations, stats = run_check(tmp_path, enforce_floors=False)
    assert violations == []
    assert stats["produced_event_types"] == 1
    assert stats["verified_key_reads"] == 2


def test_corpus_floors_fail_closed_on_empty_tree(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Running without --no-floors on an empty tree fails closed on all 5 floors."""
    rc = main(["--repo-root", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err.count("[corpus-floor]") == 5


def test_planted_gateway_test_fixture_mismatches_fail_closed(tmp_path: Path) -> None:
    """Contract 5 catches un-evidenced 403s, HTTP 202, unproduced envelope keys, and SSE message chunks."""
    _write(
        tmp_path / "src/gateway/server/governance_middleware.py",
        """
        async def validate_action_endpoint(request, body):
            refusal_content = {
                "schema_version": "2.0.0",
                "verdict": "DENIED",
                "violations": ["rule"],
            }
            refusal_content["refusal_receipt"] = {}
            refusal_content["proof_hash"] = "sha256:abc"
            return refusal_content

        async def policy_precheck_endpoint(request, body):
            return JSONResponse(
                status_code=200,
                content={
                    "schema_version": "1.0.0",
                    "action": body.action,
                    "decision": "ALLOW",
                    "dry_run": True,
                    "advisory": True,
                },
            )
        """,
    )
    _write(
        tmp_path / "src/gateway/governance/governance_envelope.py",
        """
        class GovernanceEnvelope:
            def to_dict(self):
                return {
                    "envelope_version": "3.0",
                    "envelope_type": "cage_governance_decision",
                    "envelope_id": "e-1",
                    "issued_at": "t0",
                    "expires_at": "t1",
                    "issuer": {},
                    "subject": {},
                    "governance_context": {},
                    "payload": {},
                    "external_attestations": [],
                    "signature": {},
                }
        """,
    )
    _write(
        tmp_path / "src/gateway/governance/governor/governor.py",
        """
        class SymbolicGovernor:
            async def _evaluate_dry_run(self, action, params):
                return {
                    "verdict": "ALLOW",
                    "violations": [],
                    "latency_ms": 1.0,
                }
        """,
    )
    _write(
        tmp_path / "src/integrations/inference_stub/server.py",
        """
        async def _stream_sse_chunks(model_id, decision):
            base = {
                "id": "cmpl-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": model_id,
            }
            chunk = {
                **base,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
            return chunk
        """,
    )
    _write(
        tmp_path / "tests/test_planted_gateway_fixtures.py",
        """
        import httpx
        import pytest
        from cage_client import CageClient, CageGatewayError

        async def test_positive_403_without_proof_hash_is_flagged():
            return httpx.Response(403, json={"verdict": "DENIED", "violations": ["limit"]})

        async def test_negative_403_asserting_gateway_error_is_allowed():
            resp = httpx.Response(403, json={"verdict": "DENIED"})
            with pytest.raises(CageGatewayError):
                raise CageGatewayError("missing proof_hash")
            return resp

        async def test_http_202_defer_is_flagged():
            return httpx.Response(202, json={"ticket_id": "t-1"})

        async def test_fictional_nested_governance_payload_is_flagged():
            return httpx.Response(
                200,
                json={"envelope_version": "3.0", "payload": {"governance": {"verdict": "ALLOW"}}},
            )

        async def test_sse_chunk_with_non_streaming_message_is_flagged():
            bad_sse = 'data: {"id":"1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}'
            return bad_sse
        """,
    )

    violations, stats = run_check(tmp_path, enforce_floors=False)
    kinds = [v.kind for v in violations]
    assert "unproduced-refusal-fixture" in kinds
    assert "unproduced-fixture-status" in kinds
    assert "unproduced-envelope-fixture" in kinds
    assert "unproduced-sse-chunk-fixture" in kinds
    # Negative test asserting CageGatewayError on line 10 must NOT be flagged.
    flagged_lines = {v.line for v in violations}
    assert 10 not in flagged_lines
    assert stats["verified_test_fixture_responses"] >= 5
