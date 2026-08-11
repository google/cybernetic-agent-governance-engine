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
tests/test_compliance_bridge_tier1.py

Tier-1 roadmap implementation tests:
  1.1 — ISO_CONTROL_MAP is the single source of truth (no dual-maintenance)
  1.2 — GET /v1/controls discovery endpoint
  1.3 — GET /v1/audit/status/{audit_id} poll endpoint
  1.4 — CAGE_ROUTING_SEAL_SECRET guard (POAM-012)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_OSCAL_YAML = """
assessment-results:
  uuid: "tier1-test-001"
  metadata:
    last-modified: "2026-05-18T00:00:00Z"
  results:
    - uuid: "result-tier1-001"
      findings:
        - uuid: "finding-tier1-001"
          title: "A.5.2 validation"
          target:
            type: objective-id
            target-id: "A.5.2"
            status:
              state: "satisfied"
"""


@pytest.fixture(scope="module")
def client():
    """TestClient with Langfuse patched — required for app import.

    The ``require_internal_token`` dependency (C-07) is overridden so that
    unit tests are not blocked by auth and can focus on business-logic.
    """
    with patch("src.compliance_bridge.main.Langfuse") as MockLF:
        mock_lf = MagicMock()
        MockLF.return_value = mock_lf
        from fastapi.testclient import TestClient

        # Reset audit status store between tests
        from src.compliance_bridge import main as bridge_main
        from src.compliance_bridge.auth import require_internal_token
        from src.compliance_bridge.main import app

        bridge_main._audit_status.clear()
        app.dependency_overrides[require_internal_token] = lambda: "test-token"
        try:
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c
        finally:
            app.dependency_overrides.pop(require_internal_token, None)


# ---------------------------------------------------------------------------
# 1.1  ISO_CONTROL_MAP — single source of truth
# ---------------------------------------------------------------------------


class TestIsoControlMapSingleSource:
    """Verify that the canonical ISO_CONTROL_MAP lives only in types.py."""

    def test_types_exports_iso_control_map(self):
        from src.compliance_bridge.types import ISO_CONTROL_MAP

        assert isinstance(ISO_CONTROL_MAP, dict)
        assert len(ISO_CONTROL_MAP) >= 9, "Expected at least 9 entries"

    def test_langfuse_utils_imports_from_types(self):
        """langfuse_utils must re-export the canonical map, not define its own."""
        from src.compliance_bridge.types import ISO_CONTROL_MAP as canonical
        from src.governed_financial_advisor.utils.langfuse_utils import (
            ISO_CONTROL_MAP as lf_map,
        )

        # Must be the exact same object (imported, not copied)
        assert lf_map is canonical, (
            "langfuse_utils.ISO_CONTROL_MAP is not the same object as "
            "src.compliance_bridge.types.ISO_CONTROL_MAP — dual-maintenance detected!"
        )

    def test_all_map_values_are_supported_controls(self):
        from src.compliance_bridge.types import ISO_CONTROL_MAP, SUPPORTED_CONTROLS

        for event, control_id in ISO_CONTROL_MAP.items():
            assert control_id in SUPPORTED_CONTROLS, (
                f"ISO_CONTROL_MAP[{event!r}]={control_id!r} is not in SUPPORTED_CONTROLS"
            )

    def test_canonical_map_includes_causal_gatekeeper(self):
        from src.compliance_bridge.types import ISO_CONTROL_MAP

        assert "causal_gatekeeper" in ISO_CONTROL_MAP
        assert ISO_CONTROL_MAP["causal_gatekeeper"] == "A.6.2"

    def test_canonical_map_includes_network_controls(self):
        # linkerd_mtls and cilium_l7_egress are US_FED-only (NIST SC-8 / SC-7).
        # They are no longer in the universal ISO_CONTROL_MAP; use
        # get_iso_control_map("US_FED") to obtain the region-merged view.
        from src.compliance_bridge.types import get_iso_control_map

        us_fed_map = get_iso_control_map("US_FED")
        assert "linkerd_mtls" in us_fed_map
        assert "cilium_l7_egress" in us_fed_map


# ---------------------------------------------------------------------------
# 1.2  GET /v1/controls — discovery endpoint
# ---------------------------------------------------------------------------


class TestControlsDiscoveryEndpoint:
    def test_returns_200(self, client):
        resp = client.get("/v1/controls")
        assert resp.status_code == 200

    def test_response_has_controls_list(self, client):
        data = client.get("/v1/controls").json()
        assert "controls" in data
        assert "total" in data
        assert isinstance(data["controls"], list)

    def test_total_matches_controls_length(self, client):
        data = client.get("/v1/controls").json()
        assert data["total"] == len(data["controls"])

    def test_each_control_has_required_fields(self, client):
        data = client.get("/v1/controls").json()
        required = {"control_id", "name", "iso_clause", "score_name", "critical"}
        for entry in data["controls"]:
            assert required.issubset(entry.keys()), (
                f"Control entry missing fields: {required - entry.keys()}"
            )

    def test_critical_controls_flagged(self, client):
        from src.compliance_bridge.types import CRITICAL_CONTROLS

        data = client.get("/v1/controls").json()
        for entry in data["controls"]:
            expected = entry["control_id"] in CRITICAL_CONTROLS
            assert entry["critical"] == expected, (
                f"control_id={entry['control_id']!r}: expected critical={expected}, "
                f"got {entry['critical']}"
            )

    def test_a52_present_and_correct(self, client):
        data = client.get("/v1/controls").json()
        a52 = next((c for c in data["controls"] if c["control_id"] == "A.5.2"), None)
        assert a52 is not None
        assert a52["name"] == "Social Impact Assessment"
        assert "42001" in a52["iso_clause"]
        assert a52["critical"] is False

    def test_sc4_is_critical(self, client):
        data = client.get("/v1/controls").json()
        sc4 = next((c for c in data["controls"] if c["control_id"] == "SC-4"), None)
        assert sc4 is not None
        assert sc4["critical"] is True

    def test_all_supported_controls_present(self, client):
        # When CAGE_DEPLOYMENT_REGION is not set the endpoint returns universal
        # (ISO 42001) controls only.  SUPPORTED_CONTROLS now includes all
        # jurisdictional controls too, so compare against the universal subset.
        from src.compliance_bridge.types import get_control_meta

        universal_ids = set(get_control_meta("").keys())
        data = client.get("/v1/controls").json()
        returned_ids = {c["control_id"] for c in data["controls"]}
        assert universal_ids <= returned_ids, (
            f"Expected universal controls {universal_ids} to be a subset of returned {returned_ids}"
        )


# ---------------------------------------------------------------------------
# 1.3  GET /v1/audit/status/{audit_id}
# ---------------------------------------------------------------------------


class TestAuditStatusEndpoint:
    def test_unknown_audit_id_returns_404(self, client):
        resp = client.get("/v1/audit/status/nonexistent-audit-xyz")
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "AUDIT_NOT_FOUND"

    def test_ingest_then_status_returns_done(self, client):
        mock_result = {
            "status": "ok",
            "audit_id": "status-test-001",
            "findings_count": 1,
            "artifact_key": None,
            "ingested": 1,
            "alerted": False,
            "alert_targets": [],
            "remediation_sent": False,
            "remediation_text": None,
            "advisor_error": None,
        }
        with patch(
            "src.compliance_bridge.main.run_audit_workflow",
            new=AsyncMock(return_value=mock_result),
        ):
            ingest_resp = client.post(
                "/v1/audit/ingest",
                json={"oscal_yaml": VALID_OSCAL_YAML, "audit_id": "status-test-001"},
            )
        assert ingest_resp.status_code == 200

        status_resp = client.get("/v1/audit/status/status-test-001")
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["phase"] == "done"
        assert data["audit_id"] == "status-test-001"

    def test_failed_ingest_sets_error_status(self, client):
        with patch(
            "src.compliance_bridge.main.run_audit_workflow",
            new=AsyncMock(side_effect=ValueError("YAML syntax error: bad")),
        ):
            client.post(
                "/v1/audit/ingest",
                json={"oscal_yaml": "bad: yaml:", "audit_id": "error-audit-001"},
            )

        status_resp = client.get("/v1/audit/status/error-audit-001")
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["phase"] == "error"
        assert data["error"] == "OSCAL_PARSE_ERROR"

    def test_status_store_lru_eviction(self):
        """Inserting more than _AUDIT_STATUS_MAXSIZE entries evicts the oldest."""
        from src.compliance_bridge.main import (
            _AUDIT_STATUS_MAXSIZE,
            _audit_status,
            _set_audit_status,
        )

        _audit_status.clear()
        for i in range(_AUDIT_STATUS_MAXSIZE + 5):
            _set_audit_status(f"audit-{i}", {"phase": "done"})
        assert len(_audit_status) == _AUDIT_STATUS_MAXSIZE
        # The first 5 entries should have been evicted
        assert "audit-0" not in _audit_status
        assert "audit-4" not in _audit_status
        # The latest entry must be present
        assert f"audit-{_AUDIT_STATUS_MAXSIZE + 4}" in _audit_status


# ---------------------------------------------------------------------------
# 1.4  CAGE_ROUTING_SEAL_SECRET guard (POAM-012)
# ---------------------------------------------------------------------------


class TestCageRoutingSealGuard:
    """
    The lifespan guard should raise RuntimeError when:
      - ENVIRONMENT is a production-like value (not dev/test/ci)
      - AND CAGE_ROUTING_SEAL_SECRET is absent or matches a known dev default
    """

    def _attempt_startup(self, env: str, secret: str) -> bool:
        """Returns True if the app started without error, False if RuntimeError raised."""
        env_vars = {
            "ENVIRONMENT": env,
            "CAGE_ROUTING_SEAL_SECRET": secret,
            # Disable Tier 3 guards so these tests focus only on the seal-secret guard
            "CMEK_CHECK_DISABLED": "1",
            "LULA_SCHEDULER_DISABLED": "1",
            "EVIDENCE_SLA_DISABLED": "1",
        }
        with patch("src.compliance_bridge.main.Langfuse") as MockLF:
            MockLF.return_value = MagicMock()
            from fastapi.testclient import TestClient

            from src.compliance_bridge.main import app

            try:
                with patch.dict(os.environ, env_vars, clear=False):
                    with TestClient(app, raise_server_exceptions=True):
                        pass
                return True
            except RuntimeError:
                return False

    def test_dev_environment_no_secret_ok(self):
        """development + no secret must start without error."""
        assert self._attempt_startup("development", "") is True

    def test_ci_environment_no_secret_ok(self):
        assert self._attempt_startup("ci", "") is True

    def test_test_environment_no_secret_ok(self):
        assert self._attempt_startup("test", "") is True

    def test_production_with_strong_secret_ok(self):
        assert (
            self._attempt_startup("production", "hunter2-very-long-random-secret")
            is True
        )

    def test_production_with_empty_secret_raises(self):
        assert self._attempt_startup("production", "") is False

    def test_production_with_changeme_raises(self):
        assert self._attempt_startup("production", "changeme") is False

    def test_staging_with_dev_default_raises(self):
        assert self._attempt_startup("staging", "secret") is False
