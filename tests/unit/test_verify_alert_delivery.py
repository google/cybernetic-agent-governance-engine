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

"""Unit tests for scripts/verify_alert_delivery.py (POAM-2026-230 Properties 2-4)."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest

from scripts import verify_alert_delivery as verifier
from scripts.verify_alert_delivery import AlertVerificationError

pytestmark = [pytest.mark.unit, pytest.mark.local]

CHANNEL_ID = "projects/cage-test-01/notificationChannels/12345"
SUB_PATH = "projects/cage-test-01/subscriptions/cage-staging-alerts-verify"


def _make_policies(
    count: int = 9, include_heartbeat: bool = True
) -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = []
    for idx in range(count):
        is_hb = include_heartbeat and idx == count - 1
        policies.append(
            {
                "name": f"projects/cage-test-01/alertPolicies/{idx}",
                "displayName": (
                    "cage-staging - Alert Pipeline Synthetic Heartbeat (No Action Required)"
                    if is_hb
                    else f"cage-staging - Policy {idx}"
                ),
                "enabled": True,
                "notificationChannels": [CHANNEL_ID],
                "userLabels": (
                    {"alert_kind": "heartbeat", "owner": "secops"}
                    if is_hb
                    else {"owner": "secops"}
                ),
            }
        )
    return policies


def _b64_json(obj: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


class TestRuntimePolicyVerification:
    def test_valid_policies_and_enabled_channel_pass(self) -> None:
        def _fake_http(
            method: str,
            url: str,
            _token: str,
            payload: Any = None,
            timeout: float = 30.0,
        ) -> dict[str, Any]:
            assert method == "GET"
            if "/alertPolicies" in url:
                return {"alertPolicies": _make_policies(9, include_heartbeat=True)}
            if url.endswith(CHANNEL_ID):
                return {
                    "name": CHANNEL_ID,
                    "displayName": "cage-staging-alerts-pubsub",
                    "type": "pubsub",
                    "enabled": True,
                }
            raise AssertionError(f"Unexpected URL {url}")

        with patch.object(verifier, "_http_json", side_effect=_fake_http):
            report = verifier.verify_runtime_alert_policies(
                project="cage-test-01",
                cluster_name="cage-staging",
                token="tok",
                min_policies=9,
                expected_channels=[CHANNEL_ID],
            )
        assert report["policy_count"] == 9
        assert report["channels"][0]["enabled"] is True

    def test_channel_set_drift_or_disabled_channel_fails_closed(self) -> None:
        drifted = _make_policies(9)
        drifted[0]["notificationChannels"] = [
            "projects/cage-test-01/notificationChannels/99999"
        ]
        with patch.object(
            verifier,
            "_http_json",
            return_value={"alertPolicies": drifted},
        ):
            with pytest.raises(AlertVerificationError, match="Channel-set drift"):
                verifier.verify_runtime_alert_policies(
                    project="cage-test-01",
                    cluster_name="cage-staging",
                    token="tok",
                )

        # Disabled channel at runtime must also fail closed.
        def _disabled_ch(
            method: str, url: str, _tok: str, **_kw: Any
        ) -> dict[str, Any]:
            if "/alertPolicies" in url:
                return {"alertPolicies": _make_policies(9)}
            return {"name": CHANNEL_ID, "displayName": "ch", "enabled": False}

        with patch.object(verifier, "_http_json", side_effect=_disabled_ch):
            with pytest.raises(AlertVerificationError, match="enabled=False"):
                verifier.verify_runtime_alert_policies(
                    project="cage-test-01",
                    cluster_name="cage-staging",
                    token="tok",
                )


class TestNonDestructiveSubscriptionInspection:
    def test_preserves_operational_alerts_and_keeps_newest_periodic_bridge_heartbeat(
        self,
    ) -> None:
        now_epoch = 1_800_000_000.0
        now_iso = datetime.fromtimestamp(now_epoch, tz=timezone.utc).isoformat()
        older_iso = datetime.fromtimestamp(
            now_epoch - 3600.0, tz=timezone.utc
        ).isoformat()

        messages = [
            # 1. Real operational Cloud Monitoring incident -> MUST BE NACKED (preserved)
            {
                "ackId": "ack-real-mon",
                "message": {
                    "publishTime": now_iso,
                    "data": _b64_json(
                        {
                            "incident": {
                                "incident_id": "inc-real-1",
                                "policy_name": "cage-staging - Lula Compliance Audit Failure",
                                "policy_user_labels": {"owner": "secops"},
                                "state": "open",
                                "started_at": int(now_epoch),
                            }
                        }
                    ),
                },
            },
            # 2. Real operational compliance_bridge critical alert -> MUST BE NACKED (preserved)
            {
                "ackId": "ack-real-bridge",
                "message": {
                    "publishTime": now_iso,
                    "data": _b64_json(
                        {
                            "source": "compliance_bridge",
                            "alert_type": "critical_findings",
                            "severity": "critical",
                        }
                    ),
                },
            },
            # 3. Synthetic Cloud Monitoring heartbeat -> MUST BE ACKED + recorded
            {
                "ackId": "ack-synth-mon",
                "message": {
                    "publishTime": now_iso,
                    "data": _b64_json(
                        {
                            "incident": {
                                "incident_id": "inc-hb-1",
                                "policy_name": "cage-staging - Alert Pipeline Synthetic Heartbeat",
                                "policy_user_labels": {"alert_kind": "heartbeat"},
                                "state": "open",
                                "started_at": int(now_epoch),
                            }
                        }
                    ),
                },
            },
            # 4. Newer periodic bridge heartbeat -> MUST BE NACKED so repeated runs stay idempotent
            {
                "ackId": "ack-bridge-hb-newest",
                "message": {
                    "publishTime": now_iso,
                    "data": _b64_json(
                        {
                            "source": "compliance_bridge",
                            "alert_type": "heartbeat",
                            "timestamp": now_iso,
                        }
                    ),
                },
            },
            # 5. Older superseded periodic bridge heartbeat -> MUST BE ACKED (GC)
            {
                "ackId": "ack-bridge-hb-older",
                "message": {
                    "publishTime": older_iso,
                    "data": _b64_json(
                        {
                            "source": "compliance_bridge",
                            "alert_type": "heartbeat",
                            "timestamp": older_iso,
                        }
                    ),
                },
            },
        ]

        acked: list[str] = []
        nacked: list[str] = []
        leased: list[str] = []
        pulls = [0]

        def _fake_http(
            method: str,
            url: str,
            _token: str,
            payload: Any = None,
            timeout: float = 30.0,
        ) -> dict[str, Any]:
            assert method == "POST"
            if url.endswith(":pull"):
                pulls[0] += 1
                return {"receivedMessages": messages if pulls[0] == 1 else []}
            if url.endswith(":acknowledge"):
                acked.extend(payload["ackIds"])
                return {}
            if url.endswith(":modifyAckDeadline"):
                if payload["ackDeadlineSeconds"] > 0:
                    leased.extend(payload["ackIds"])
                else:
                    nacked.extend(payload["ackIds"])
                return {}
            raise AssertionError(f"Unexpected URL {url}")

        with patch.object(verifier, "_http_json", side_effect=_fake_http):
            res = verifier.inspect_subscription_batch(
                subscription_path=SUB_PATH,
                token="tok",
                trip_started_epoch=now_epoch - 5.0,
            )

        assert res["monitoring_heartbeat_observed"] is True
        assert res["monitoring_incident_id"] == "inc-hb-1"
        assert res["freshest_bridge_heartbeat_epoch"] == pytest.approx(now_epoch)
        assert res["operational_messages_preserved"] == 2
        assert len(leased) == 5
        assert set(acked) == {"ack-synth-mon", "ack-bridge-hb-older"}
        assert set(nacked) == {
            "ack-real-mon",
            "ack-real-bridge",
            "ack-bridge-hb-newest",
        }

    def test_multi_batch_drain_reaches_tail_heartbeat_behind_operational_backlog(
        self,
    ) -> None:
        now_epoch = 1795400500.0
        now_iso = datetime.fromtimestamp(now_epoch, tz=timezone.utc).isoformat()

        batch_1 = [
            {
                "ackId": f"ack-backlog-{i}",
                "message": {
                    "messageId": f"msg-backlog-{i}",
                    "publishTime": now_iso,
                    "data": _b64_json(
                        {
                            "incident": {
                                "incident_id": f"inc-op-{i}",
                                "policy_name": "cage-staging - Lula Compliance Audit Failure",
                                "policy_user_labels": {"control": "ca-7"},
                                "state": "open",
                                "started_at": int(now_epoch) - 3600,
                            }
                        }
                    ),
                },
            }
            for i in range(35)
        ]
        batch_2 = [
            {
                "ackId": "ack-tail-mon",
                "message": {
                    "messageId": "msg-tail-mon",
                    "publishTime": now_iso,
                    "data": _b64_json(
                        {
                            "incident": {
                                "incident_id": "0.ofc950vlgew1",
                                "policy_name": "cage-staging - Alert Pipeline Synthetic Heartbeat",
                                "policy_user_labels": {"alert_kind": "heartbeat"},
                                "state": "open",
                                "started_at": int(now_epoch),
                            }
                        }
                    ),
                },
            },
            {
                "ackId": "ack-tail-bridge",
                "message": {
                    "messageId": "msg-tail-bridge",
                    "publishTime": now_iso,
                    "data": _b64_json(
                        {
                            "source": "compliance-bridge",
                            "alert_type": "heartbeat",
                            "timestamp": now_iso,
                        }
                    ),
                },
            },
        ]

        pulls = [0]
        acked: list[str] = []
        released: list[str] = []

        def _fake_http(
            method: str,
            url: str,
            _token: str,
            payload: Any = None,
            timeout: float = 30.0,
        ) -> dict[str, Any]:
            if url.endswith(":pull"):
                pulls[0] += 1
                if pulls[0] == 1:
                    return {"receivedMessages": batch_1}
                if pulls[0] == 2:
                    return {"receivedMessages": batch_2}
                return {"receivedMessages": []}
            if url.endswith(":acknowledge"):
                acked.extend(payload["ackIds"])
                return {}
            if url.endswith(":modifyAckDeadline"):
                if payload["ackDeadlineSeconds"] == 0:
                    released.extend(payload["ackIds"])
                return {}
            raise AssertionError(f"Unexpected URL {url}")

        with patch.object(verifier, "_http_json", side_effect=_fake_http):
            res = verifier.inspect_subscription_batch(
                subscription_path=SUB_PATH,
                token="tok",
                trip_started_epoch=now_epoch - 5.0,
            )

        assert pulls[0] == 3
        assert res["monitoring_heartbeat_observed"] is True
        assert res["monitoring_incident_id"] == "0.ofc950vlgew1"
        assert res["freshest_bridge_heartbeat_epoch"] == pytest.approx(now_epoch)
        assert res["operational_messages_preserved"] == 35
        assert acked == ["ack-tail-mon"]
        assert len(released) == 36
        assert "ack-tail-bridge" in released

    def test_verify_end_to_end_resets_metric_in_finally_on_timeout(self) -> None:
        writes: list[int] = []
        clock = [100.0]

        def _advance_clock() -> float:
            val = clock[0]
            clock[0] += 8.0
            return val

        with (
            patch.object(
                verifier,
                "write_heartbeat_metric",
                side_effect=lambda **kw: writes.append(kw["value"]),
            ),
            patch.object(
                verifier,
                "inspect_subscription_batch",
                return_value={
                    "monitoring_heartbeat_observed": False,
                    "monitoring_incident_id": None,
                    "ondemand_bridge_probe_observed": False,
                    "freshest_bridge_heartbeat_epoch": None,
                    "operational_messages_preserved": 0,
                },
            ),
            patch.object(verifier.time, "sleep", return_value=None),
            patch.object(verifier.time, "time", side_effect=_advance_clock),
        ):
            with pytest.raises(AlertVerificationError, match="Timed out"):
                verifier.verify_end_to_end_delivery(
                    project="cage-test-01",
                    subscription="cage-staging-alerts-verify",
                    token="tok",
                    timeout_seconds=15,
                    poll_interval_seconds=1,
                )

        assert writes == [1, 0], "Metric must be tripped to 1 and reset to 0 in finally"

    def test_validate_https_url_rejects_non_https(self) -> None:
        with pytest.raises(AlertVerificationError, match="Refusing non-HTTPS"):
            verifier._validate_https_url(
                "http://monitoring.googleapis.com/v3/projects/x"
            )
