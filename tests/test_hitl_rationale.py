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

"""
HITL Rationale — Compliance Evidence Chain Tests
=================================================

Verifies:
  1. ApprovalResumeRequest rejects empty/missing rationale.
  2. approval_node propagates rationale into approval_decision.
  3. rejection_node surfaces rationale in the human-facing message.
  4. PlaygroundTelemetry.record_approval() writes a valid hash-linked record.
  5. record_approval() records survive chain verification (tamper-evidence).
  6. The evidence record contains all required ISO 42001 / NIST fields.
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# 1. ApprovalResumeRequest — mandatory rationale validation
# ---------------------------------------------------------------------------


class TestApprovalResumeRequest:
    """Unit tests for the Pydantic model validation."""

    def _load(self):
        from src.governed_financial_advisor.server import ApprovalResumeRequest

        return ApprovalResumeRequest

    def test_valid_request_accepted(self):
        Model = self._load()
        req = Model(
            approved=True,
            reviewer="alice@example.com",
            rationale="Trade aligns with client risk profile and current market conditions.",
        )
        assert req.rationale.startswith("Trade aligns")
        assert req.reviewer == "alice@example.com"
        assert req.approved is True
        assert req.comment == ""  # default

    def test_missing_rationale_raises(self):
        Model = self._load()
        with pytest.raises((ValidationError, ValueError, TypeError)):
            Model(approved=True, reviewer="alice@example.com")  # no rationale

    def test_empty_rationale_raises(self):
        Model = self._load()
        with pytest.raises((ValidationError, ValueError)):
            Model(approved=True, reviewer="alice@example.com", rationale="")

    def test_whitespace_only_rationale_raises(self):
        Model = self._load()
        with pytest.raises((ValidationError, ValueError)):
            Model(approved=True, reviewer="alice@example.com", rationale="   ")

    def test_comment_is_optional(self):
        Model = self._load()
        req = Model(
            approved=False,
            reviewer="bob@example.com",
            rationale="Trade exceeds client drawdown tolerance per IPS.",
        )
        assert req.comment == ""

    def test_comment_accepted_alongside_rationale(self):
        Model = self._load()
        req = Model(
            approved=False,
            reviewer="bob@example.com",
            rationale="Trade exceeds client drawdown tolerance.",
            comment="Escalated to senior PM.",
        )
        assert req.comment == "Escalated to senior PM."


# ---------------------------------------------------------------------------
# 2. approval_node — rationale propagated into approval_decision
# ---------------------------------------------------------------------------


class TestApprovalNodeRationale:
    """Tests the approval_node processes and forwards the rationale field."""

    def _call_node_with_decision(self, decision: dict) -> "Command":
        """Simulate what happens when interrupt() returns `decision`."""
        from src.governed_financial_advisor.graph.nodes.approval_node import (
            approval_node,
        )

        with patch(
            "src.governed_financial_advisor.graph.nodes.approval_node.interrupt",
            return_value=decision,
        ):
            state = {
                "execution_plan": {"ticker": "AAPL", "quantity": 100},
                "evaluation_result": {"decision": "APPROVED"},
            }
            return approval_node(state)

    def test_rationale_present_in_approval_decision_on_approve(self):
        cmd = self._call_node_with_decision(
            {
                "approved": True,
                "reviewer": "carol@example.com",
                "rationale": "Confirmed against IPS; risk score 0.45 < threshold.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        decision = cmd.update["approval_decision"]
        assert (
            decision["rationale"]
            == "Confirmed against IPS; risk score 0.45 < threshold."
        )
        assert decision["reviewer"] == "carol@example.com"
        assert decision["approved"] is True
        # TOCTOU remediation: approved path now routes to post_hitl_rehydrate,
        # not directly to executor. The re-hydration and re-validation nodes
        # are mandatory before actuation.
        assert cmd.goto == "post_hitl_rehydrate"

    def test_rationale_present_in_approval_decision_on_reject(self):
        cmd = self._call_node_with_decision(
            {
                "approved": False,
                "reviewer": "dave@example.com",
                "rationale": "Client has requested no equity exposure this quarter.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        decision = cmd.update["approval_decision"]
        assert (
            decision["rationale"]
            == "Client has requested no equity exposure this quarter."
        )
        assert decision["approved"] is False
        assert cmd.goto == "rejection"

    def test_empty_rationale_stored_but_does_not_crash(self):
        """Backward compat: node stores empty rationale without crashing.
        Validation is the API layer's responsibility; the node is not the gate."""
        cmd = self._call_node_with_decision(
            {
                "approved": True,
                "reviewer": "legacy@example.com",
                # rationale absent — simulates old client
            }
        )
        decision = cmd.update["approval_decision"]
        assert decision.get("rationale", "") == ""


# ---------------------------------------------------------------------------
# 3. rejection_node — rationale shown in rejection message
# ---------------------------------------------------------------------------


class TestRejectionNodeRationale:
    def test_rationale_appears_in_rejection_message(self):
        from src.governed_financial_advisor.graph.nodes.approval_node import (
            rejection_node,
        )

        state = {
            "approval_decision": {
                "approved": False,
                "reviewer": "eve@example.com",
                "rationale": "Portfolio already at maximum allocation for tech sector.",
                "comment": "",
                "timestamp": "2026-05-19T12:00:00+00:00",
            }
        }
        result = rejection_node(state)
        messages = result["messages"]
        content = (
            messages[0][1] if isinstance(messages[0], tuple) else messages[0].content
        )
        assert "Portfolio already at maximum allocation" in content
        assert "Rationale:" in content

    def test_comment_fallback_when_no_rationale(self):
        from src.governed_financial_advisor.graph.nodes.approval_node import (
            rejection_node,
        )

        state = {
            "approval_decision": {
                "approved": False,
                "reviewer": "legacy@example.com",
                "rationale": "",
                "comment": "Old-style comment field.",
                "timestamp": "2026-05-19T12:00:00+00:00",
            }
        }
        result = rejection_node(state)
        messages = result["messages"]
        content = (
            messages[0][1] if isinstance(messages[0], tuple) else messages[0].content
        )
        assert "Old-style comment field." in content


# ---------------------------------------------------------------------------
# 4 & 5. PlaygroundTelemetry.record_approval() — evidence chain integrity
# ---------------------------------------------------------------------------


class TestRecordApproval:
    """Tests the new record_approval() method on PlaygroundTelemetry."""

    def _make_tel(self, tmp_dir: Path):
        """Construct a PlaygroundTelemetry that writes into tmp_dir."""
        from examples import telemetry as tel_module

        # Redirect all file paths to the temp directory
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        chain_path = tmp_dir / f"evidence_chain_{date_str}.ndjson"
        view_path = tmp_dir / f"view_access_log_{date_str}.ndjson"

        with (
            patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
            patch.object(tel_module, "_VIEW_ACCESS_LOG_PATH", view_path),
            patch.object(tel_module, "_EVIDENCE_DIR", tmp_dir),
        ):
            return tel_module.PlaygroundTelemetry(), chain_path, view_path, tel_module

    def test_approval_record_written_to_chain(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tel, chain_path, _, tel_module = self._make_tel(tmp)

            with (
                patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
                patch.object(tel_module, "_EVIDENCE_DIR", tmp),
            ):
                record_hash = tel.record_approval(
                    thread_id="thread-abc-123",
                    approved=True,
                    reviewer="frank@example.com",
                    rationale="Verified risk profile; P&L within limits.",
                )

            assert chain_path.exists()
            lines = chain_path.read_text().strip().splitlines()
            assert len(lines) == 1
            rec = json.loads(lines[0])

            assert rec["event_type"] == "hitl_approval"
            assert rec["thread_id"] == "thread-abc-123"
            assert rec["decision"] == "APPROVED"
            assert rec["reviewer"] == "frank@example.com"
            assert rec["rationale"] == "Verified risk profile; P&L within limits."
            assert rec["record_hash"] == record_hash
            assert "A.8.4" in rec["iso_controls"]
            assert "A.7.2" in rec["iso_controls"]
            assert "GOVERN-5" in rec["nist_controls"]
            assert rec["iso_42001_clause"] == "6.1"

    def test_rejection_record_decision_field(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tel, chain_path, _, tel_module = self._make_tel(tmp)

            with (
                patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
                patch.object(tel_module, "_EVIDENCE_DIR", tmp),
            ):
                tel.record_approval(
                    thread_id="thread-xyz-789",
                    approved=False,
                    reviewer="grace@example.com",
                    rationale="Client has opted out of any equity positions.",
                )

            rec = json.loads(chain_path.read_text().strip().splitlines()[0])
            assert rec["decision"] == "REJECTED"

    def test_consecutive_records_are_hash_chained(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tel, chain_path, _, tel_module = self._make_tel(tmp)

            with (
                patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
                patch.object(tel_module, "_EVIDENCE_DIR", tmp),
            ):
                h1 = tel.record_approval(
                    thread_id="t1",
                    approved=True,
                    reviewer="h@x.com",
                    rationale="First approval.",
                )
                h2 = tel.record_approval(
                    thread_id="t2",
                    approved=False,
                    reviewer="h@x.com",
                    rationale="Second rejection.",
                )

            lines = chain_path.read_text().strip().splitlines()
            r1 = json.loads(lines[0])
            r2 = json.loads(lines[1])

            assert r1["record_hash"] == h1
            assert r2["prev_hash"] == h1  # chain links
            assert r2["record_hash"] == h2

    def test_chain_verify_passes_after_approval_records(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tel, chain_path, _, tel_module = self._make_tel(tmp)

            with (
                patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
                patch.object(tel_module, "_EVIDENCE_DIR", tmp),
            ):
                tel.record_approval(
                    thread_id="t-verify",
                    approved=True,
                    reviewer="ivan@example.com",
                    rationale="Trade within client mandate.",
                )
                valid, count = tel.verify_chain()

            assert valid is True
            assert count == 1

    def test_tampered_rationale_breaks_chain(self):
        """Modifying rationale post-write invalidates the hash chain."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tel, chain_path, _, tel_module = self._make_tel(tmp)

            with (
                patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
                patch.object(tel_module, "_EVIDENCE_DIR", tmp),
            ):
                tel.record_approval(
                    thread_id="t-tamper",
                    approved=True,
                    reviewer="judy@example.com",
                    rationale="Original rationale.",
                )

            # Tamper with the rationale
            lines = chain_path.read_text().splitlines()
            rec = json.loads(lines[0])
            rec["rationale"] = "TAMPERED rationale."
            chain_path.write_text(json.dumps(rec) + "\n")

            with (
                patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
                patch.object(tel_module, "_EVIDENCE_DIR", tmp),
            ):
                valid, _ = tel.verify_chain()

            assert valid is False


pytestmark = [pytest.mark.unit, pytest.mark.local]
