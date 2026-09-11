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
tests/test_oscal_endpoint_cer_wiring.py — Runtime wiring tests for B6 CER index injection.

This module tests the FastAPI endpoint path directly to verify CER links actually
appear in the exported OSCAL document at runtime. This is the regression guard that
would have caught the original defect (built infrastructure never reached from endpoint).
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.compliance_bridge.disclosure import Disclosure

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test 1: Endpoint emits CER links when resolver configured and index injected
# ---------------------------------------------------------------------------


@patch.dict(
    os.environ, {"PROVIDER_02_RESOLVER_URL": "https://resolver.example.com/api"}
)
@patch("src.compliance_bridge.main.get_compliance_metrics")
def test_endpoint_emits_cer_links_when_resolver_configured(
    mock_get_metrics: MagicMock,
) -> None:
    """When PROVIDER_02_RESOLVER_URL is set, the endpoint injects a CER index
    and emits link[rel='evidence'] entries.

    This is the critical regression test: it exercises the real call path in
    main.py, not just the exporter in isolation. A passing exporter test coexisted
    with zero runtime links before B6 wiring.
    """
    # Arrange: Mock Langfuse to return passing metrics for A.5.3
    mock_metrics = MagicMock()
    mock_metrics.model_dump.return_value = {
        "control_id": "A.5.3",
        "safety_rate": 0.98,
        "evidence_age_seconds": 120,
        "status": "PASS",
    }
    mock_get_metrics.return_value = mock_metrics

    # Arrange: Patch Provider02CERIndex at its source (function-scope lazy import)
    with patch(
        "src.integrations.provider_02.cer_index.Provider02CERIndex"
    ) as MockIndex:
        mock_index_instance = MagicMock()
        mock_index_instance.uri_for_control.return_value = (
            "https://verify.provider-02.example.com/cer/sha256:abc123def456"
        )
        mock_index_instance.disclosure_for_control.return_value = Disclosure.PUBLIC
        MockIndex.return_value = mock_index_instance

        # Act: Call the endpoint
        from src.compliance_bridge.main import app

        client = TestClient(app)
        response = client.get(
            "/v1/oscal/assessment-results?window_hours=24&format=json"
        )

        # Assert: Response is successful
        assert response.status_code == 200
        data = response.json()
        assert "document" in data

        # Assert: CER link is present in findings
        findings = data["document"]["assessment-results"]["results"][0]["findings"]
        a53_finding = next(
            (f for f in findings if f["target"]["target-id"] == "A.5.3"), None
        )
        assert a53_finding is not None, "A.5.3 finding must be present"
        assert "links" in a53_finding, "links[] array must be present"
        assert len(a53_finding["links"]) >= 1, "At least one link must be present"

        # Assert: Link has correct rel and href
        cer_link = next(
            (lnk for lnk in a53_finding["links"] if lnk.get("rel") == "evidence"), None
        )
        assert cer_link is not None, "link[rel='evidence'] must be present"
        assert (
            cer_link["href"]
            == "https://verify.provider-02.example.com/cer/sha256:abc123def456"
        )
        assert "Provider 02 CER" in cer_link["text"]


# ---------------------------------------------------------------------------
# Test 2: Endpoint produces byte-identical output when resolver not configured
# ---------------------------------------------------------------------------


@patch.dict(os.environ, {"PROVIDER_02_RESOLVER_URL": "", "CAGE_ENV": "development"})
@patch("src.compliance_bridge.main.get_compliance_metrics")
def test_endpoint_no_cer_links_without_resolver_configured(
    mock_get_metrics: MagicMock,
) -> None:
    """When PROVIDER_02_RESOLVER_URL is not set, _build_cer_index() returns None
    and the output is byte-identical to the original behavior (no CER links).

    This preserves backward compatibility with deployments that do not use
    Provider 02 attestation.
    """
    # Arrange: Mock Langfuse to return passing metrics for A.5.3
    mock_metrics = MagicMock()
    mock_metrics.model_dump.return_value = {
        "control_id": "A.5.3",
        "safety_rate": 0.98,
        "evidence_age_seconds": 120,
        "status": "PASS",
    }
    mock_get_metrics.return_value = mock_metrics

    # Act: Call the endpoint
    from src.compliance_bridge.main import app

    client = TestClient(app)
    response = client.get("/v1/oscal/assessment-results?window_hours=24&format=json")

    # Assert: Response is successful
    assert response.status_code == 200
    data = response.json()
    assert "document" in data

    # Assert: No CER links are present
    findings = data["document"]["assessment-results"]["results"][0]["findings"]
    a53_finding = next(
        (f for f in findings if f["target"]["target-id"] == "A.5.3"), None
    )
    assert a53_finding is not None, "A.5.3 finding must be present"
    assert "links" not in a53_finding, (
        "links[] array must NOT be present when no resolver configured"
    )


# ---------------------------------------------------------------------------
# Test 3: Index construction failure degrades safely (warning logged)
# ---------------------------------------------------------------------------


@patch.dict(
    os.environ, {"PROVIDER_02_RESOLVER_URL": "https://resolver.example.com/api"}
)
@patch("src.compliance_bridge.main.get_compliance_metrics")
@patch("src.compliance_bridge.main.logger")
def test_endpoint_degrades_safely_on_index_construction_failure(
    mock_logger: MagicMock,
    mock_get_metrics: MagicMock,
) -> None:
    """If Provider02CERIndex construction raises, _build_cer_index() logs a warning
    and returns None. The endpoint continues and exports a valid OSCAL document
    without CER links.

    This fail-safe pattern ensures OSCAL export never breaks due to CER index
    unavailability.
    """
    # Arrange: Mock Langfuse to return passing metrics
    mock_metrics = MagicMock()
    mock_metrics.model_dump.return_value = {
        "control_id": "A.5.3",
        "safety_rate": 0.98,
        "evidence_age_seconds": 120,
        "status": "PASS",
    }
    mock_get_metrics.return_value = mock_metrics

    # Arrange: Patch Provider02CERIndex to raise on construction
    with patch(
        "src.integrations.provider_02.cer_index.Provider02CERIndex"
    ) as MockIndex:
        MockIndex.side_effect = RuntimeError("CER index construction failed")

        # Act: Call the endpoint
        from src.compliance_bridge.main import app

        client = TestClient(app)
        response = client.get(
            "/v1/oscal/assessment-results?window_hours=24&format=json"
        )

        # Assert: Response is still successful
        assert response.status_code == 200
        data = response.json()
        assert "document" in data

        # Assert: Warning was logged
        warning_calls = [
            call
            for call in mock_logger.warning.call_args_list
            if "Failed to construct Provider02CERIndex" in str(call)
        ]
        assert len(warning_calls) >= 1, (
            "Warning must be logged when index construction fails"
        )

        # Assert: No CER links are present (degraded mode)
        findings = data["document"]["assessment-results"]["results"][0]["findings"]
        a53_finding = next(
            (f for f in findings if f["target"]["target-id"] == "A.5.3"), None
        )
        assert a53_finding is not None
        assert "links" not in a53_finding, (
            "links[] must NOT be present when index construction fails"
        )
