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
Cybernetic Loop Regression Tests.

Guards the three-node signal path:

  Langfuse score event
    → POST /v1/webhooks/langfuse          (event filter + threshold gate)
    → _submit_kfp_run()                   (KFP dry-run in CI)
    → KFP: trigger_nemo_refinement()      (calls /v1/nemo/apply-refinement)
    → POST /v1/nemo/apply-refinement      (hot-reloads NeMo rails singleton)

Regression risks guarded:
- R-LOOP-1: KFP component must NOT call /v1/refinement/trigger (infinite loop).
- R-LOOP-2: Langfuse webhook must not act on non-score events.
- R-LOOP-3: Langfuse webhook must not act when safety_rate >= threshold.
- R-LOOP-4: apply-refinement must reload the global rails singleton.
- R-LOOP-5: apply-refinement must return 500 (not 200) on reload failure.
"""

from __future__ import annotations

import importlib
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_server_app():
    """Import the FastAPI app with NeMo / Redis mocked out."""
    with (
        patch(
            "src.gateway.governance.nemo.manager.load_rails", return_value=MagicMock()
        ),
        patch(
            "src.governed_financial_advisor.graph.graph.create_graph",
            return_value=MagicMock(),
        ),
        patch("src.governed_financial_advisor.utils.telemetry.configure_telemetry"),
        patch(
            "opentelemetry.instrumentation.langchain.LangchainInstrumentor.instrument"
        ),
    ):
        import src.governed_financial_advisor.server as srv

        importlib.reload(srv)
        return srv.app


# ---------------------------------------------------------------------------
# R-LOOP-1: KFP pipeline component uses the correct endpoint
# ---------------------------------------------------------------------------


class TestKfpComponentEndpoint:
    """The trigger_nemo_refinement KFP component must call /v1/nemo/apply-refinement."""

    def _get_source(self) -> str:
        pipeline_mod = importlib.import_module(
            "src.governed_financial_advisor.pipelines.green_stack_pipeline"
        )
        component = pipeline_mod.trigger_nemo_refinement
        # KFP @component wraps the function in a PythonComponent object.
        # Use python_func to get the original unwrapped function for source inspection.
        if hasattr(component, "python_func"):
            return inspect.getsource(component.python_func)
        elif hasattr(component, "__wrapped__"):
            return inspect.getsource(component.__wrapped__)
        return inspect.getsource(component)

    def test_calls_apply_refinement_not_trigger(self):
        """R-LOOP-1: must NOT reference /v1/refinement/trigger."""
        src = self._get_source()
        assert "/v1/refinement/trigger" not in src, (
            "trigger_nemo_refinement still calls /v1/refinement/trigger — "
            "this creates an infinite loop / 422. Use /v1/nemo/apply-refinement."
        )

    def test_calls_correct_endpoint(self):
        """R-LOOP-1: must reference /v1/nemo/propose-refinement or /v1/nemo/apply-refinement."""
        src = self._get_source()
        assert (
            "/v1/nemo/propose-refinement" in src or "/v1/nemo/apply-refinement" in src
        ), "trigger_nemo_refinement does not call the correct NeMo refinement endpoint."

    def test_payload_has_correct_fields(self):
        """R-LOOP-1: payload must include control_id, verdict, and source fields."""
        src = self._get_source()
        assert "control_id" in src
        assert "verdict" in src
        assert "source" in src

    def test_no_old_trigger_field(self):
        """R-LOOP-1: old {\"trigger\": \"governance_refinement\"} payload must be gone."""
        src = self._get_source()
        assert '"trigger"' not in src or "governance_refinement" not in src, (
            "Old trigger payload shape still present in trigger_nemo_refinement."
        )

    def test_returns_no_action_on_pass(self):
        """PASS verdict must short-circuit without making any HTTP call."""
        pipeline_mod = importlib.import_module(
            "src.governed_financial_advisor.pipelines.green_stack_pipeline"
        )
        # Call the raw function (without KFP wrapping).
        # KFP v2 @dsl.component exposes .python_func; functools.wraps sets __wrapped__.
        component = pipeline_mod.trigger_nemo_refinement
        if hasattr(component, "python_func"):
            fn = component.python_func
        elif hasattr(component, "__wrapped__"):
            fn = component.__wrapped__
        else:
            fn = component
        result = fn(verdict="PASS: safety_rate=0.99", backend_url="http://localhost")
        assert result == "NO_ACTION"


# ---------------------------------------------------------------------------
# R-LOOP-2 / R-LOOP-3: Langfuse webhook filtering
# ---------------------------------------------------------------------------


class TestLangfuseWebhook:
    """POST /v1/webhooks/langfuse must filter events correctly."""

    @pytest.fixture(autouse=True)
    def reset_cooldown(self):
        import src.governed_financial_advisor.server as srv

        srv._last_refinement_triggered_at = 0.0
        yield
        srv._last_refinement_triggered_at = 0.0

    @pytest.fixture
    def client(self):
        with (
            patch(
                "src.gateway.governance.nemo.manager.load_rails",
                return_value=MagicMock(),
            ),
            patch(
                "src.governed_financial_advisor.graph.graph.create_graph",
                return_value=MagicMock(),
            ),
            patch("src.governed_financial_advisor.utils.telemetry.configure_telemetry"),
            patch(
                "opentelemetry.instrumentation.langchain.LangchainInstrumentor.instrument"
            ),
        ):
            import src.governed_financial_advisor.server as srv

            return TestClient(srv.app, raise_server_exceptions=True)

    def test_non_score_event_ignored(self, client):
        """R-LOOP-2: trace-created events must be acknowledged but not acted on."""
        resp = client.post(
            "/v1/webhooks/langfuse",
            json={
                "type": "trace-created",
                "name": "",
                "value": 0.0,
                "traceId": "abc",
                "data": {},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_wrong_score_name_ignored(self, client):
        """R-LOOP-2: score events with an unrecognised name must be ignored."""
        resp = client.post(
            "/v1/webhooks/langfuse",
            json={
                "type": "score-created",
                "name": "some_other_metric",
                "value": 0.5,
                "traceId": "abc",
                "data": {},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_above_threshold_not_triggered(self, client):
        """R-LOOP-3: safety_rate >= threshold must NOT trigger KFP."""
        resp = client.post(
            "/v1/webhooks/langfuse",
            json={
                "type": "score-created",
                "name": "iso_42001_safety_rate",
                "value": 0.99,
                "traceId": "abc",
                "data": {},
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "threshold_ok"
        assert "kfp" not in body, "KFP must not be triggered when rate >= threshold"

    def test_below_threshold_triggers_kfp(self, client):
        """R-LOOP-3: safety_rate < threshold must trigger a KFP dry_run."""
        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            return_value={"run_id": None, "status": "dry_run", "kfp_endpoint": ""},
        ):
            resp = client.post(
                "/v1/webhooks/langfuse",
                json={
                    "type": "score-created",
                    "name": "iso_42001_safety_rate",
                    "value": 0.80,
                    "traceId": "trace-xyz",
                    "data": {},
                },
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "triggered"
        assert body["kfp"]["status"] == "dry_run"

    def test_trace_id_forwarded_to_kfp(self, client):
        """Trace ID from the Langfuse event must be forwarded to _submit_kfp_run."""
        captured: list = []

        def _fake_submit(pipeline_id, trigger_reason, trace_ids):
            captured.append(trace_ids)
            return {"run_id": None, "status": "dry_run", "kfp_endpoint": ""}

        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            side_effect=_fake_submit,
        ):
            client.post(
                "/v1/webhooks/langfuse",
                json={
                    "type": "score-created",
                    "name": "iso_42001_safety_rate",
                    "value": 0.50,
                    "traceId": "my-trace-123",
                    "data": {},
                },
            )
        assert captured and "my-trace-123" in captured[0]


# ---------------------------------------------------------------------------
# R-LOOP-4 / R-LOOP-5: POST /v1/nemo/apply-refinement
# ---------------------------------------------------------------------------


class TestApplyRefinement:
    """POST /v1/nemo/apply-refinement must reload the rails singleton."""

    @pytest.fixture
    def client(self):
        with (
            patch(
                "src.gateway.governance.nemo.manager.load_rails",
                return_value=MagicMock(),
            ),
            patch(
                "src.governed_financial_advisor.graph.graph.create_graph",
                return_value=MagicMock(),
            ),
            patch("src.governed_financial_advisor.utils.telemetry.configure_telemetry"),
            patch(
                "opentelemetry.instrumentation.langchain.LangchainInstrumentor.instrument"
            ),
        ):
            import src.governed_financial_advisor.server as srv

            return TestClient(srv.app, raise_server_exceptions=False)

    @pytest.fixture(autouse=True)
    def enable_auto_apply(self, monkeypatch):
        """Enable legacy auto-apply for these tests (they test reload mechanics)."""
        import src.governed_financial_advisor.server as srv

        monkeypatch.setattr(srv, "_NEMO_AUTO_APPLY", True)

    def test_successful_reload(self, client):
        """R-LOOP-4: successful reload must return {status: applied, reload: true}."""
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.reload_nemo_rails",
            new_callable=AsyncMock,
        ):
            resp = client.post(
                "/v1/nemo/apply-refinement",
                json={
                    "control_id": "A.5.2",
                    "verdict": "FAIL: safety_rate=0.80 < threshold=0.95",
                    "source": "kfp-governance-loop",
                },
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "applied"
        assert body["reload"] is True
        assert body["control_id"] == "A.5.2"
        assert body["source"] == "kfp-governance-loop"

    def test_reload_failure_returns_500(self, client):
        """R-LOOP-5: if reload_nemo_rails() raises, the endpoint must return 500."""
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.reload_nemo_rails",
            side_effect=RuntimeError("Colang parse error"),
        ):
            resp = client.post(
                "/v1/nemo/apply-refinement",
                json={
                    "control_id": "A.5.2",
                    "verdict": "FAIL: safety_rate=0.50",
                    "source": "test",
                },
            )
        assert resp.status_code == 500
        assert "reload failed" in resp.json()["detail"].lower()

    def test_minimum_required_fields(self, client):
        """Source field is optional; omitting it must not cause a 422."""
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.reload_nemo_rails",
            new_callable=AsyncMock,
        ):
            resp = client.post(
                "/v1/nemo/apply-refinement",
                json={"control_id": "A.9.2", "verdict": "FAIL"},
            )
        assert resp.status_code == 200

    def test_missing_required_fields_returns_422(self, client):
        """control_id and verdict are mandatory; omitting them must return 422."""
        resp = client.post("/v1/nemo/apply-refinement", json={"source": "test"})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# R-LOOP-6: Cooldown gate — policy flapping prevention
# ---------------------------------------------------------------------------


class TestWebhookCooldown:
    """POST /v1/webhooks/langfuse must enforce a cooldown window between triggers."""

    _SCORE_BELOW_THRESHOLD = {
        "type": "score-created",
        "name": "iso_42001_safety_rate",
        "value": 0.80,
        "traceId": "trace-cooldown",
        "data": {},
    }

    @pytest.fixture(autouse=True)
    def reset_cooldown(self):
        """Reset the module-level cooldown clock before every test."""
        import src.governed_financial_advisor.server as srv

        srv._last_refinement_triggered_at = 0.0
        yield
        srv._last_refinement_triggered_at = 0.0

    @pytest.fixture
    def client(self):
        with (
            patch(
                "src.gateway.governance.nemo.manager.load_rails",
                return_value=MagicMock(),
            ),
            patch(
                "src.governed_financial_advisor.graph.graph.create_graph",
                return_value=MagicMock(),
            ),
            patch("src.governed_financial_advisor.utils.telemetry.configure_telemetry"),
            patch(
                "opentelemetry.instrumentation.langchain.LangchainInstrumentor.instrument"
            ),
        ):
            import src.governed_financial_advisor.server as srv

            return TestClient(srv.app, raise_server_exceptions=True)

    def test_first_trigger_accepted(self, client):
        """R-LOOP-6: First below-threshold event must be accepted (cooldown not yet armed)."""
        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            return_value={"run_id": None, "status": "dry_run", "kfp_endpoint": ""},
        ):
            resp = client.post(
                "/v1/webhooks/langfuse", json=self._SCORE_BELOW_THRESHOLD
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "triggered"

    def test_second_trigger_during_cooldown_blocked(self, client):
        """R-LOOP-6: Second event during the cooldown window must return status=cooldown."""

        _fake_kfp = {"run_id": None, "status": "dry_run", "kfp_endpoint": ""}

        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            return_value=_fake_kfp,
        ):
            # First trigger — arms the cooldown
            resp1 = client.post(
                "/v1/webhooks/langfuse", json=self._SCORE_BELOW_THRESHOLD
            )
        assert resp1.json()["status"] == "triggered"

        # Second trigger — cooldown is active (timestamp was set above, no time has passed)
        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            return_value=_fake_kfp,
        ) as mock_kfp:
            resp2 = client.post(
                "/v1/webhooks/langfuse", json=self._SCORE_BELOW_THRESHOLD
            )
            mock_kfp.assert_not_called()

        assert resp2.status_code == 200
        body = resp2.json()
        assert body["status"] == "cooldown", f"Expected cooldown, got: {body}"
        assert "seconds_remaining" in body
        assert body["seconds_remaining"] > 0

    def test_trigger_allowed_after_cooldown_expires(self, client):
        """R-LOOP-6: A trigger must be accepted once the cooldown window has passed."""
        import time

        import src.governed_financial_advisor.server as srv

        _fake_kfp = {"run_id": None, "status": "dry_run", "kfp_endpoint": ""}

        # Simulate first trigger having fired well in the past (cooldown expired)
        srv._last_refinement_triggered_at = time.monotonic() - (
            srv._REFINEMENT_COOLDOWN_SECONDS + 1
        )

        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            return_value=_fake_kfp,
        ):
            resp = client.post(
                "/v1/webhooks/langfuse", json=self._SCORE_BELOW_THRESHOLD
            )

        assert resp.json()["status"] == "triggered"

    def test_cooldown_response_includes_seconds_remaining(self, client):
        """R-LOOP-6: Cooldown response must include a non-negative seconds_remaining field."""
        import time

        import src.governed_financial_advisor.server as srv

        # Arm cooldown 60 seconds ago — should have ~240 s remaining with 300 s window
        srv._last_refinement_triggered_at = time.monotonic() - 60

        resp = client.post("/v1/webhooks/langfuse", json=self._SCORE_BELOW_THRESHOLD)
        body = resp.json()
        assert body["status"] == "cooldown"
        # Generous bounds to avoid flakiness from monotonic clock drift in CI
        assert 200 <= body["seconds_remaining"] <= 300

    def test_kfp_not_called_during_cooldown(self, client):
        """R-LOOP-6: _submit_kfp_run must NOT be invoked during the cooldown window."""
        import time

        import src.governed_financial_advisor.server as srv

        # Arm cooldown at present time (0 seconds elapsed)
        srv._last_refinement_triggered_at = time.monotonic()

        with patch("src.governed_financial_advisor.server._submit_kfp_run") as mock_kfp:
            client.post("/v1/webhooks/langfuse", json=self._SCORE_BELOW_THRESHOLD)
            mock_kfp.assert_not_called()


# ---------------------------------------------------------------------------
# R-LOOP-7: Minimum-sample guard — statistically insignificant bursts
# ---------------------------------------------------------------------------


class TestWebhookMinSamples:
    """POST /v1/webhooks/langfuse must defer triggers with insufficient sample size."""

    @pytest.fixture(autouse=True)
    def reset_cooldown(self):
        import src.governed_financial_advisor.server as srv

        srv._last_refinement_triggered_at = 0.0
        yield
        srv._last_refinement_triggered_at = 0.0

    @pytest.fixture
    def client(self):
        with (
            patch(
                "src.gateway.governance.nemo.manager.load_rails",
                return_value=MagicMock(),
            ),
            patch(
                "src.governed_financial_advisor.graph.graph.create_graph",
                return_value=MagicMock(),
            ),
            patch("src.governed_financial_advisor.utils.telemetry.configure_telemetry"),
            patch(
                "opentelemetry.instrumentation.langchain.LangchainInstrumentor.instrument"
            ),
        ):
            import src.governed_financial_advisor.server as srv

            return TestClient(srv.app, raise_server_exceptions=True)

    def test_small_sample_deferred(self, client):
        """R-LOOP-7: sample_size < min_samples must return status=deferred."""
        resp = client.post(
            "/v1/webhooks/langfuse",
            json={
                "type": "score-created",
                "name": "iso_42001_safety_rate",
                "value": 0.80,
                "traceId": "trace-small",
                "data": {"sample_size": 3},  # below default min of 10
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "deferred"
        assert body["reason"] == "insufficient_samples"
        assert body["sample_size"] == 3

    def test_sufficient_sample_triggers(self, client):
        """R-LOOP-7: sample_size >= min_samples must proceed to trigger (or cooldown)."""
        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            return_value={"run_id": None, "status": "dry_run", "kfp_endpoint": ""},
        ):
            resp = client.post(
                "/v1/webhooks/langfuse",
                json={
                    "type": "score-created",
                    "name": "iso_42001_safety_rate",
                    "value": 0.80,
                    "traceId": "trace-big",
                    "data": {"sample_size": 50},  # above default min of 10
                },
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "triggered"

    def test_absent_sample_size_not_deferred(self, client):
        """R-LOOP-7: if sample_size is absent the guard is skipped (Langfuse omits it)."""
        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            return_value={"run_id": None, "status": "dry_run", "kfp_endpoint": ""},
        ):
            resp = client.post(
                "/v1/webhooks/langfuse",
                json={
                    "type": "score-created",
                    "name": "iso_42001_safety_rate",
                    "value": 0.50,
                    "traceId": "trace-no-meta",
                    "data": {},  # no sample_size key
                },
            )
        assert resp.status_code == 200
        # Must be triggered or cooldown — never deferred
        assert resp.json()["status"] in ("triggered", "cooldown")

    def test_sample_size_appended_to_trigger_reason(self, client):
        """R-LOOP-7: when sample_size is known it should appear in the KFP trigger_reason."""
        captured: list = []

        def _fake_submit(pipeline_id, trigger_reason, trace_ids):
            captured.append(trigger_reason)
            return {"run_id": None, "status": "dry_run", "kfp_endpoint": ""}

        with patch(
            "src.governed_financial_advisor.server._submit_kfp_run",
            side_effect=_fake_submit,
        ):
            client.post(
                "/v1/webhooks/langfuse",
                json={
                    "type": "score-created",
                    "name": "iso_42001_safety_rate",
                    "value": 0.70,
                    "traceId": "trace-meta",
                    "data": {"sample_size": 42},
                },
            )
        assert captured and "n=42" in captured[0]
