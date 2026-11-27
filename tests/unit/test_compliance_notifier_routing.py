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

"""Unit tests for POAM-2026-230 compliance-bridge notifier validity & observed delivery."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.compliance_bridge.notifier import (
    ConsoleNotifier,
    MockNotifier,
    NotifierConfigError,
    PubSubNotifier,
    create_notifier,
    is_external_notifier_configured,
    send_notifier_heartbeat,
    validate_notifier_config,
)
from src.compliance_bridge.sla_monitor import _maybe_emit_notifier_heartbeat
from src.compliance_bridge.types import OscalFinding

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _finding(control_id: str = "CA-7", result: str = "FAIL") -> OscalFinding:
    return OscalFinding(
        control_id=control_id,
        result=result,
        finding_id=f"finding-{control_id.lower()}",
        evidence_age_s=12.5,
    )


class TestNotifierStartupValidation:
    """Property 1b: Enforcing postures fail closed on unset, console, mock, or incomplete config."""

    @pytest.mark.parametrize("posture", ["staging", "prod", "production"])
    @pytest.mark.parametrize("bad_channel", ["", "console", "mock", "unknown-sink"])
    def test_enforcing_posture_refuses_non_external_or_unknown_channels(
        self, monkeypatch: pytest.MonkeyPatch, posture: str, bad_channel: str
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", posture)
        monkeypatch.setenv("TESTING", "1")
        if bad_channel:
            monkeypatch.setenv("ALERT_CHANNEL", bad_channel)
        else:
            monkeypatch.delenv("ALERT_CHANNEL", raising=False)

        with pytest.raises(NotifierConfigError):
            validate_notifier_config()

        with pytest.raises(NotifierConfigError):
            create_notifier()

    def test_enforcing_pubsub_requires_well_formed_topic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("ALERT_CHANNEL", "pubsub")
        monkeypatch.delenv("COMPLIANCE_ALERT_PUBSUB_TOPIC", raising=False)
        with pytest.raises(NotifierConfigError, match="COMPLIANCE_ALERT_PUBSUB_TOPIC"):
            validate_notifier_config()

        monkeypatch.setenv("COMPLIANCE_ALERT_PUBSUB_TOPIC", "cage-staging-alerts")
        with pytest.raises(
            NotifierConfigError, match="projects/<project-id>/topics/<topic-name>"
        ):
            validate_notifier_config()

        monkeypatch.setenv(
            "COMPLIANCE_ALERT_PUBSUB_TOPIC",
            "projects/cage-test-01/topics/cage-staging-alerts",
        )
        assert validate_notifier_config() == "pubsub"
        assert is_external_notifier_configured() is True

    @pytest.mark.parametrize("channel", ["slack", "webhook"])
    def test_webhook_and_slack_require_https_url(
        self, monkeypatch: pytest.MonkeyPatch, channel: str
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("ALERT_CHANNEL", channel)
        monkeypatch.setenv(
            "COMPLIANCE_ALERT_WEBHOOK_URL", "http://insecure.example.org/hook"
        )
        with pytest.raises(NotifierConfigError, match="https://"):
            validate_notifier_config()

        monkeypatch.setenv(
            "COMPLIANCE_ALERT_WEBHOOK_URL", "https://hooks.example.org/alert"
        )
        assert validate_notifier_config() == channel

    def test_dev_posture_allows_console_and_reports_external_unconfigured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "dev")
        monkeypatch.delenv("ALERT_CHANNEL", raising=False)
        assert validate_notifier_config() == "console"
        assert is_external_notifier_configured() is False
        notifier = create_notifier()
        assert isinstance(notifier, ConsoleNotifier)


class TestPubSubAndObservedDelivery:
    """Property 2 & Remediation #6: Observed destination ack governs boolean return."""

    @pytest.mark.asyncio
    async def test_console_notifier_always_returns_false(self) -> None:
        notifier = ConsoleNotifier()
        assert await notifier.send_critical_alert([_finding()], "audit-1") is False
        assert (
            await notifier.send_remediation_followup(
                control_id="CA-7",
                audit_id="audit-1",
                model_name="none",
                remediation_text="fix",
                trace_ids=["tr-1"],
            )
            is False
        )

    @pytest.mark.asyncio
    async def test_pubsub_notifier_publishes_envelope_and_verifies_message_ids(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("ALERT_CHANNEL", "pubsub")
        monkeypatch.setenv(
            "COMPLIANCE_ALERT_PUBSUB_TOPIC",
            "projects/cage-test-01/topics/cage-staging-alerts",
        )
        captured: list[dict[str, Any]] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            captured.append(
                {
                    "url": str(request.url),
                    "auth": request.headers.get("Authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(200, json={"messageIds": ["9876543210"]})

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            with (
                patch(
                    "src.compliance_bridge.notifier._fetch_pubsub_access_token_sync",
                    return_value="ya29.fake-test-token",
                ),
                patch(
                    "src.compliance_bridge.notifier._get_notifier_http_client",
                    new=AsyncMock(return_value=client),
                ),
            ):
                notifier = PubSubNotifier(
                    topic="projects/cage-test-01/topics/cage-staging-alerts"
                )
                ok = await notifier.send_critical_alert(
                    [_finding("AU-12", "FAIL")], "a-42"
                )
                hb_ok, hb_id = await send_notifier_heartbeat("hb-test-01")

        assert ok is True
        assert hb_ok is True
        assert hb_id == "hb-test-01"
        assert len(captured) == 2
        assert (
            captured[0]["url"]
            == "https://pubsub.googleapis.com/v1/projects/cage-test-01/topics/cage-staging-alerts:publish"
        )
        assert captured[0]["auth"] == "Bearer ya29.fake-test-token"
        assert captured[0]["body"]["messages"][0]["attributes"]["alert_type"] == (
            "critical_failure"
        )

        hb_msg = captured[1]["body"]["messages"][0]
        assert hb_msg["attributes"]["source"] == "compliance-bridge"
        assert hb_msg["attributes"]["alert_type"] == "heartbeat"
        decoded = json.loads(base64.b64decode(hb_msg["data"]).decode("utf-8"))
        assert decoded["source"] == "compliance-bridge"
        assert decoded["alert_type"] == "heartbeat"

    @pytest.mark.asyncio
    async def test_pubsub_notifier_returns_false_on_empty_message_ids_or_http_error(
        self,
    ) -> None:
        notifier = PubSubNotifier(
            topic="projects/cage-test-01/topics/cage-staging-alerts"
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _req: httpx.Response(200, json={"messageIds": []})
            )
        ) as empty_client:
            with (
                patch(
                    "src.compliance_bridge.notifier._fetch_pubsub_access_token_sync",
                    return_value="ya29.fake-test-token",
                ),
                patch(
                    "src.compliance_bridge.notifier._get_notifier_http_client",
                    new=AsyncMock(return_value=empty_client),
                ),
            ):
                assert (
                    await notifier.send_critical_alert([_finding()], "a-empty") is False
                )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _req: httpx.Response(403, json={"error": "permission_denied"})
            )
        ) as err_client:
            with (
                patch(
                    "src.compliance_bridge.notifier._fetch_pubsub_access_token_sync",
                    return_value="ya29.fake-test-token",
                ),
                patch(
                    "src.compliance_bridge.notifier._get_notifier_http_client",
                    new=AsyncMock(return_value=err_client),
                ),
            ):
                assert (
                    await notifier.send_critical_alert([_finding()], "a-403") is False
                )

    @pytest.mark.asyncio
    async def test_mock_notifier_simulated_failure_propagates_false(self) -> None:
        failing_mock = MockNotifier(simulate_delivery_failure=True)
        assert await failing_mock.send_critical_alert([_finding()], "a-fail") is False
        assert failing_mock.alert_count == 1

    @pytest.mark.asyncio
    async def test_sla_heartbeat_cadence_and_retry_on_failed_delivery(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("ALERT_CHANNEL", "pubsub")
        monkeypatch.setenv(
            "COMPLIANCE_ALERT_PUBSUB_TOPIC",
            "projects/cage-test-01/topics/cage-staging-alerts",
        )
        monkeypatch.setenv("ALERT_HEARTBEAT_INTERVAL_SECONDS", "3600")

        mock_loop = MagicMock()
        mock_loop.time.return_value = 1000.0

        with (
            patch(
                "src.compliance_bridge.sla_monitor.asyncio.get_running_loop",
                return_value=mock_loop,
            ),
            patch(
                "src.compliance_bridge.sla_monitor.send_notifier_heartbeat",
                new=AsyncMock(return_value=(False, "hb-fail")),
            ),
        ):
            # Failed delivery must preserve None so next tick retries immediately.
            assert await _maybe_emit_notifier_heartbeat(None) is None

        hb_ok_mock = AsyncMock(return_value=(True, "hb-ok"))
        with (
            patch(
                "src.compliance_bridge.sla_monitor.asyncio.get_running_loop",
                return_value=mock_loop,
            ),
            patch(
                "src.compliance_bridge.sla_monitor.send_notifier_heartbeat",
                new=hb_ok_mock,
            ),
        ):
            mock_loop.time.return_value = 1060.0
            updated = await _maybe_emit_notifier_heartbeat(None)
            assert updated == 1060.0
            assert hb_ok_mock.await_count == 1

            # Within 3600s interval -> suppressed.
            mock_loop.time.return_value = 2000.0
            assert await _maybe_emit_notifier_heartbeat(updated) == 1060.0
            assert hb_ok_mock.await_count == 1

            # Past 3600s interval -> next heartbeat emitted.
            mock_loop.time.return_value = 4700.0
            assert await _maybe_emit_notifier_heartbeat(updated) == 4700.0
            assert hb_ok_mock.await_count == 2

    @pytest.mark.asyncio
    async def test_lifespan_fails_closed_in_staging_when_notifier_is_console(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.compliance_bridge.main import app, lifespan

        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("ALERT_CHANNEL", "console")

        with patch(
            "src.compliance_bridge.main.validate_langfuse_credentials",
            return_value=MagicMock(),
        ):
            with pytest.raises(NotifierConfigError, match="POAM-2026-230"):
                async with lifespan(app):
                    pass
