#!/usr/bin/env python3
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

"""End-to-end Cloud Monitoring & compliance-bridge alert delivery verifier (POAM-2026-230).

Pure Python stdlib script (zero third-party imports) safe to execute in minimal
OIDC-authenticated GitHub Actions jobs without installing PyPI dependencies
(POAM-2026-115 / POAM-2026-221).

Verifies all runtime properties of POAM-2026-230 against CAGE's reference-architecture
terminal sink (GCP Cloud Pub/Sub):
  1. Runtime Policy & Channel Validity (Property 1 / 2):
     - Lists all Cloud Monitoring AlertPolicy resources for ``--cluster-name``.
     - Asserts at least ``--min-policies`` (default: 9) exist, every policy has
       ``enabled == True`` and non-empty ``notificationChannels``, every policy
       shares the exact same channel set, and every referenced NotificationChannel
       exists with ``enabled == True``.
  2. Cloud Monitoring Heartbeat Delivery at Destination (Property 3a):
     - Writes ``custom.googleapis.com/cage/alert_heartbeat_probe = 1`` to trip
       ``google_monitoring_alert_policy.alert_pipeline_heartbeat`` (a dedicated
       ``WARNING`` policy labeled ``alert_kind=heartbeat``, never a real operational
       alarm).
     - Polls ``--subscription`` until the resulting incident notification arrives,
       returning all real operational alert messages untouched via
       ``modifyAckDeadline(ackDeadlineSeconds=0)`` so real alerts are never consumed.
     - Resets ``custom.googleapis.com/cage/alert_heartbeat_probe = 0`` in a
       ``finally`` block so the synthetic incident closes cleanly.
  3. Compliance-Bridge Notifier Delivery at Destination (Property 3b):
     - Asserts that a fresh ``source="compliance_bridge"``, ``alert_type="heartbeat"``
       envelope emitted by the in-cluster ``compliance-bridge`` SLA monitor arrived
       in ``--subscription`` within ``--max-bridge-heartbeat-age-seconds`` (keeping
       the newest heartbeat unacknowledged for idempotency while garbage-collecting
       superseded older heartbeats), and optionally emits an on-demand tagged
       ``--emit-bridge-heartbeat-topic`` probe and observes its arrival.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

HEARTBEAT_METRIC_TYPE = "custom.googleapis.com/cage/alert_heartbeat_probe"
MONITORING_API_BASE = "https://monitoring.googleapis.com/v3"
PUBSUB_API_BASE = "https://pubsub.googleapis.com/v1"
METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)


class AlertVerificationError(RuntimeError):
    """Raised when any runtime binding or destination-delivery check fails."""


def _validate_https_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise AlertVerificationError(
            f"Refusing non-HTTPS API URL (scheme={parsed.scheme!r}): {url!r}"
        )
    return url


def _http_json(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    validated_url = _validate_https_url(url)
    body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if body_bytes is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"

    req = urllib.request.Request(
        validated_url,
        data=body_bytes,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310  # HTTPS scheme and non-empty netloc validated by _validate_https_url
            raw = resp.read().decode("utf-8", errors="replace").strip()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:400]
        raise AlertVerificationError(
            f"HTTP {exc.code} calling {method} {validated_url}: {err_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise AlertVerificationError(
            f"Network error calling {method} {validated_url}: {exc}"
        ) from exc


def resolve_gcp_access_token() -> str:
    """Resolve an OAuth2 Bearer token from CI env, GCE metadata, or gcloud."""
    env_token = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "").strip()
    if env_token:
        return env_token

    parsed_meta = urllib.parse.urlparse(METADATA_TOKEN_URL)
    if (
        parsed_meta.scheme == "http"
        and parsed_meta.netloc == "metadata.google.internal"
    ):
        req = urllib.request.Request(
            METADATA_TOKEN_URL,
            headers={"Metadata-Flavor": "Google"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:  # nosec B310  # Pinned metadata.google.internal HTTP scheme/host verified immediately above
                data = json.loads(resp.read().decode("utf-8"))
                tok = str(data.get("access_token", "")).strip()
                if tok:
                    return tok
        except Exception:
            pass

    try:
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        tok = proc.stdout.strip()
        if tok:
            return tok
    except Exception as exc:
        raise AlertVerificationError(
            "Unable to acquire GCP OAuth2 access token from GOOGLE_OAUTH_ACCESS_TOKEN, "
            f"metadata.google.internal, or `gcloud auth print-access-token`: {exc}"
        ) from exc

    raise AlertVerificationError("Empty GCP OAuth2 access token.")


def _normalize_subscription(project: str, subscription: str) -> str:
    sub = subscription.strip()
    if sub.startswith("projects/"):
        return sub
    return f"projects/{project}/subscriptions/{sub}"


def _normalize_topic(project: str, topic: str) -> str:
    top = topic.strip()
    if top.startswith("projects/"):
        return top
    return f"projects/{project}/topics/{top}"


def verify_runtime_alert_policies(
    *,
    project: str,
    cluster_name: str,
    token: str,
    min_policies: int = 9,
    expected_channels: list[str] | None = None,
) -> dict[str, Any]:
    """Verify all cluster AlertPolicies are enabled, bound, and share active channels."""
    policies: list[dict[str, Any]] = []
    page_token = ""
    while True:
        query = {"pageSize": "200"}
        if page_token:
            query["pageToken"] = page_token
        url = (
            f"{MONITORING_API_BASE}/projects/{urllib.parse.quote(project, safe='')}"
            f"/alertPolicies?{urllib.parse.urlencode(query)}"
        )
        resp = _http_json("GET", url, token)
        policies.extend(resp.get("alertPolicies", []))
        page_token = str(resp.get("nextPageToken", "")).strip()
        if not page_token:
            break

    prefix = f"{cluster_name} - "
    cluster_policies = [
        p for p in policies if str(p.get("displayName", "")).startswith(prefix)
    ]
    if len(cluster_policies) < min_policies:
        raise AlertVerificationError(
            f"Expected at least {min_policies} AlertPolicies prefixed {prefix!r} in "
            f"project {project!r}, found {len(cluster_policies)}: "
            f"{[p.get('displayName') for p in cluster_policies]}"
        )

    channel_sets: dict[str, frozenset[str]] = {}
    heartbeat_policy: dict[str, Any] | None = None

    for policy in cluster_policies:
        display_name = str(policy.get("displayName", "<unnamed>"))
        enabled_val = policy.get("enabled", False)
        if isinstance(enabled_val, dict):
            enabled_val = bool(enabled_val.get("value", False))
        if enabled_val is not True:
            raise AlertVerificationError(
                f"AlertPolicy {display_name!r} is disabled in project {project!r}."
            )
        channels = frozenset(
            str(ch).strip()
            for ch in policy.get("notificationChannels", [])
            if str(ch).strip()
        )
        if not channels:
            raise AlertVerificationError(
                f"AlertPolicy {display_name!r} has zero notificationChannels bound!"
            )
        channel_sets[display_name] = channels
        labels = policy.get("userLabels") or {}
        if labels.get("alert_kind") == "heartbeat":
            heartbeat_policy = policy

    if heartbeat_policy is None:
        raise AlertVerificationError(
            f"Missing synthetic heartbeat policy (userLabels.alert_kind='heartbeat') "
            f"among {len(cluster_policies)} policies for {cluster_name!r}."
        )

    distinct_sets = set(channel_sets.values())
    if len(distinct_sets) != 1:
        raise AlertVerificationError(
            f"Channel-set drift across AlertPolicies for {cluster_name!r}: "
            f"{ {k: sorted(v) for k, v in channel_sets.items()} }"
        )

    common_channels = next(iter(distinct_sets))
    if expected_channels:
        expected_set = frozenset(c.strip() for c in expected_channels if c.strip())
        if common_channels != expected_set:
            raise AlertVerificationError(
                f"Runtime AlertPolicy channels {sorted(common_channels)} do not match "
                f"expected channels {sorted(expected_set)}."
            )

    verified_channels: list[dict[str, Any]] = []
    for channel_name in sorted(common_channels):
        if not channel_name.startswith("projects/"):
            raise AlertVerificationError(
                f"Malformed NotificationChannel resource name: {channel_name!r}"
            )
        ch_url = f"{MONITORING_API_BASE}/{channel_name}"
        ch_obj = _http_json("GET", ch_url, token)
        ch_enabled = ch_obj.get("enabled", True)
        if isinstance(ch_enabled, dict):
            ch_enabled = bool(ch_enabled.get("value", False))
        if ch_enabled is not True:
            raise AlertVerificationError(
                f"Bound NotificationChannel {channel_name!r} "
                f"({ch_obj.get('displayName')!r}) has enabled={ch_enabled!r}!"
            )
        verified_channels.append(
            {
                "name": ch_obj.get("name", channel_name),
                "display_name": ch_obj.get("displayName", ""),
                "type": ch_obj.get("type", ""),
                "enabled": True,
            }
        )

    return {
        "policy_count": len(cluster_policies),
        "heartbeat_policy_name": heartbeat_policy.get("name", ""),
        "heartbeat_policy_display_name": heartbeat_policy.get("displayName", ""),
        "channels": verified_channels,
    }


def write_heartbeat_metric(
    *,
    project: str,
    token: str,
    value: int,
    probe_id: str = "default",
) -> None:
    """Write an INT64 gauge point to custom.googleapis.com/cage/alert_heartbeat_probe."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    url = (
        f"{MONITORING_API_BASE}/projects/{urllib.parse.quote(project, safe='')}"
        "/timeSeries"
    )
    payload = {
        "timeSeries": [
            {
                "metric": {
                    "type": HEARTBEAT_METRIC_TYPE,
                    "labels": {
                        "probe_source": "verify_alert_delivery",
                        "probe_id": probe_id,
                    },
                },
                "resource": {
                    "type": "global",
                    "labels": {"project_id": project},
                },
                "points": [
                    {
                        "interval": {"endTime": now_iso},
                        "value": {"int64Value": str(int(value))},
                    }
                ],
            }
        ]
    }
    _http_json("POST", url, token, payload=payload)


def publish_synthetic_bridge_probe(
    *,
    topic_path: str,
    token: str,
    probe_id: str,
) -> str:
    """Publish a synthetic compliance_bridge heartbeat message to Pub/Sub."""
    envelope = {
        "source": "compliance-bridge",
        "alert_type": "heartbeat",
        "severity": "info",
        "audit_id": f"heartbeat-ondemand-{probe_id}",
        "probe_id": probe_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings_count": 1,
        "findings": [
            {
                "control_id": "CA-7-HEARTBEAT",
                "finding_id": f"heartbeat-ondemand-{probe_id}",
                "result": "PASS",
                "assessment_status": "heartbeat",
                "evidence_age_s": 0.0,
            }
        ],
    }
    encoded = base64.b64encode(
        json.dumps(envelope, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    url = f"{PUBSUB_API_BASE}/{topic_path}:publish"
    resp = _http_json(
        "POST",
        url,
        token,
        payload={
            "messages": [
                {
                    "data": encoded,
                    "attributes": {
                        "source": "compliance-bridge",
                        "alert_type": "heartbeat",
                        "probe_id": probe_id,
                    },
                }
            ]
        },
    )
    msg_ids = resp.get("messageIds")
    if not isinstance(msg_ids, list) or not msg_ids:
        raise AlertVerificationError(
            f"Pub/Sub publish on {topic_path!r} returned no messageIds: {resp!r}"
        )
    return str(msg_ids[0])


def _parse_iso_epoch(raw: str) -> float | None:
    if not raw:
        return None
    try:
        cleaned = raw.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        return datetime.fromisoformat(cleaned).timestamp()
    except ValueError:
        return None


def _ack_messages(subscription_path: str, token: str, ack_ids: list[str]) -> None:
    if not ack_ids:
        return
    url = f"{PUBSUB_API_BASE}/{subscription_path}:acknowledge"
    for offset in range(0, len(ack_ids), 200):
        _http_json(
            "POST", url, token, payload={"ackIds": ack_ids[offset : offset + 200]}
        )


def _modify_ack_deadline(
    subscription_path: str, token: str, ack_ids: list[str], seconds: int
) -> None:
    if not ack_ids:
        return
    url = f"{PUBSUB_API_BASE}/{subscription_path}:modifyAckDeadline"
    for offset in range(0, len(ack_ids), 200):
        _http_json(
            "POST",
            url,
            token,
            payload={
                "ackIds": ack_ids[offset : offset + 200],
                "ackDeadlineSeconds": seconds,
            },
        )


def _nack_messages(subscription_path: str, token: str, ack_ids: list[str]) -> None:
    _modify_ack_deadline(subscription_path, token, ack_ids, 0)


def _retain_newest_periodic(
    entries: list[tuple[float, str]],
    nack_ids: list[str],
    ack_ids: list[str],
) -> float | None:
    """Keep the newest periodic heartbeat unacked and ack older duplicates."""
    if not entries:
        return None
    entries.sort(key=lambda pair: pair[0], reverse=True)
    freshest_epoch, newest_ack_id = entries[0]
    nack_ids.append(newest_ack_id)
    for _older_epoch, older_ack_id in entries[1:]:
        ack_ids.append(older_ack_id)
    return freshest_epoch


def inspect_subscription_batch(
    *,
    subscription_path: str,
    token: str,
    trip_started_epoch: float,
    expected_ondemand_probe_id: str | None = None,
    expected_violation_head_sha: str | None = None,
    max_batches: int = 10,
) -> dict[str, Any]:
    """Drain up to ``max_batches`` Pub/Sub pulls, acking only synthetic probes.

    Pub/Sub ``pull(returnImmediately=True)`` frequently returns partial shards
    (~20-30 messages) even when ``maxMessages=50``. Holding temporary 45s ack
    leases across ``max_batches`` consecutive pulls before releasing all
    operational messages (``ackDeadlineSeconds=0``) in ``finally`` guarantees
    new heartbeats at the tail of an unacked operational backlog are observed
    without consuming real alerts.
    """
    pull_url = f"{PUBSUB_API_BASE}/{subscription_path}:pull"
    ack_ids: list[str] = []
    nack_ids: list[str] = []
    seen_message_ids: set[str] = set()
    monitoring_heartbeat_observed = False
    monitoring_incident_id: str | None = None
    ondemand_bridge_probe_observed = False
    periodic_bridge_heartbeats: list[tuple[float, str]] = []
    periodic_reconciler_heartbeats: list[tuple[float, str]] = []
    main_check_violation_observed = False
    main_check_violation_count = 0
    main_check_violation_head_shas: list[str] = []
    expected_violation_norm = (expected_violation_head_sha or "").strip().lower()
    expected_violation_observed = False
    operational_preserved = 0

    try:
        for _ in range(max(1, max_batches)):
            resp = _http_json(
                "POST",
                pull_url,
                token,
                payload={"returnImmediately": True, "maxMessages": 50},
                timeout=20.0,
            )
            received = resp.get("receivedMessages") or []
            if not received:
                break

            batch_lease_ids = [
                str(it.get("ackId", "")).strip()
                for it in received
                if str(it.get("ackId", "")).strip()
            ]
            # Extend lease across the multi-batch scan so subsequent pulls fetch
            # remaining queued messages rather than repeating the first shard.
            _modify_ack_deadline(subscription_path, token, batch_lease_ids, 45)

            new_in_batch = 0
            for item in received:
                ack_id = str(item.get("ackId", "")).strip()
                msg = item.get("message") or {}
                msg_id = str(msg.get("messageId", "")).strip() or ack_id
                if msg_id in seen_message_ids:
                    if ack_id:
                        nack_ids.append(ack_id)
                    continue
                seen_message_ids.add(msg_id)
                new_in_batch += 1

                raw_b64 = str(msg.get("data", "")).strip()
                publish_epoch = _parse_iso_epoch(str(msg.get("publishTime", ""))) or 0.0

                payload: dict[str, Any] | None = None
                if raw_b64:
                    try:
                        decoded = base64.b64decode(raw_b64).decode(
                            "utf-8", errors="replace"
                        )
                        parsed = json.loads(decoded)
                        if isinstance(parsed, dict):
                            payload = parsed
                    except Exception:
                        payload = None

                if payload is None:
                    if ack_id:
                        nack_ids.append(ack_id)
                        operational_preserved += 1
                    continue

                # Case 1: Cloud Monitoring AlertPolicy notification envelope
                incident = payload.get("incident")
                if isinstance(incident, dict):
                    user_labels = incident.get("policy_user_labels") or {}
                    policy_name = str(incident.get("policy_name", ""))
                    is_synthetic_hb = (
                        user_labels.get("alert_kind") == "heartbeat"
                        or "Synthetic Heartbeat" in policy_name
                    )
                    if is_synthetic_hb:
                        started_at = float(incident.get("started_at") or 0)
                        state = str(incident.get("state", "")).lower()
                        if state == "open" and (
                            started_at >= trip_started_epoch - 120.0
                            or publish_epoch >= trip_started_epoch - 10.0
                        ):
                            monitoring_heartbeat_observed = True
                            monitoring_incident_id = str(
                                incident.get("incident_id", "")
                            )
                        # Ack all synthetic Cloud Monitoring heartbeat messages (open/close/stale)
                        # so synthetic delivery checks never clutter the subscription.
                        if ack_id:
                            ack_ids.append(ack_id)
                    else:
                        if ack_id:
                            nack_ids.append(ack_id)
                            operational_preserved += 1
                    continue

                # Case 2: compliance-bridge notifier envelope
                if (
                    payload.get("source") in ("compliance-bridge", "compliance_bridge")
                    and payload.get("alert_type") == "heartbeat"
                ):
                    probe_id = str(payload.get("probe_id", "")).strip()
                    msg_epoch = (
                        _parse_iso_epoch(str(payload.get("timestamp", "")))
                        or publish_epoch
                    )
                    if (
                        expected_ondemand_probe_id
                        and probe_id == expected_ondemand_probe_id
                    ):
                        ondemand_bridge_probe_observed = True
                        if ack_id:
                            ack_ids.append(ack_id)
                    elif probe_id:
                        # Stale on-demand probe from an earlier run -> ack to keep queue clean.
                        if ack_id:
                            ack_ids.append(ack_id)
                    else:
                        # Periodic SLA-monitor heartbeat from compliance-bridge pod:
                        # keep only the newest unacked so repeated verification runs are idempotent!
                        if ack_id:
                            periodic_bridge_heartbeats.append((msg_epoch, ack_id))
                    continue

                # Case 3: main-result-reconciler envelopes (POAM-2026-171)
                if payload.get("source") == "main_result_reconciler":
                    alert_type = str(payload.get("alert_type", "")).strip()
                    if alert_type == "main_check_violation":
                        main_check_violation_observed = True
                        main_check_violation_count += 1
                        head_sha = str(payload.get("head_sha", "")).strip()
                        if head_sha and head_sha not in main_check_violation_head_shas:
                            main_check_violation_head_shas.append(head_sha)
                        if expected_violation_norm:
                            viol_shas = [
                                str(v.get("sha", "")).strip().lower()
                                for v in (payload.get("violations") or [])
                                if isinstance(v, dict)
                            ]
                            if head_sha.lower().startswith(
                                expected_violation_norm
                            ) or any(
                                s.startswith(expected_violation_norm) for s in viol_shas
                            ):
                                expected_violation_observed = True
                        if ack_id:
                            nack_ids.append(ack_id)
                            operational_preserved += 1
                        continue
                    if alert_type == "heartbeat":
                        msg_epoch = (
                            _parse_iso_epoch(str(payload.get("last_checked", "")))
                            or publish_epoch
                        )
                        if ack_id:
                            periodic_reconciler_heartbeats.append((msg_epoch, ack_id))
                        continue

                # Everything else is an operational alert -> preserve in queue!
                if ack_id:
                    nack_ids.append(ack_id)
                    operational_preserved += 1

            if new_in_batch == 0:
                break

        freshest_bridge_epoch = _retain_newest_periodic(
            periodic_bridge_heartbeats, nack_ids, ack_ids
        )
        freshest_reconciler_epoch = _retain_newest_periodic(
            periodic_reconciler_heartbeats, nack_ids, ack_ids
        )
    finally:
        if ack_ids:
            _ack_messages(subscription_path, token, ack_ids)
        if nack_ids:
            _nack_messages(subscription_path, token, nack_ids)

    return {
        "monitoring_heartbeat_observed": monitoring_heartbeat_observed,
        "monitoring_incident_id": monitoring_incident_id,
        "ondemand_bridge_probe_observed": ondemand_bridge_probe_observed,
        "freshest_bridge_heartbeat_epoch": freshest_bridge_epoch,
        "freshest_reconciler_heartbeat_epoch": freshest_reconciler_epoch,
        "main_check_violation_observed": main_check_violation_observed,
        "main_check_violation_count": main_check_violation_count,
        "main_check_violation_head_shas": main_check_violation_head_shas,
        "expected_violation_observed": expected_violation_observed,
        "operational_messages_preserved": operational_preserved,
    }


def verify_end_to_end_delivery(
    *,
    project: str,
    subscription: str,
    token: str,
    timeout_seconds: int = 360,
    poll_interval_seconds: int = 10,
    require_bridge_heartbeat: bool = True,
    max_bridge_heartbeat_age_seconds: int = 25200,
    emit_bridge_heartbeat_topic: str = "",
    expected_violation_head_sha: str = "",
) -> dict[str, Any]:
    """Trip Cloud Monitoring synthetic heartbeat + verify arrival on Pub/Sub."""
    subscription_path = _normalize_subscription(project, subscription)
    ondemand_probe_id: str | None = None
    if emit_bridge_heartbeat_topic.strip():
        ondemand_probe_id = uuid.uuid4().hex[:12]
        topic_path = _normalize_topic(project, emit_bridge_heartbeat_topic)
        publish_synthetic_bridge_probe(
            topic_path=topic_path,
            token=token,
            probe_id=ondemand_probe_id,
        )

    expected_violation_sha = expected_violation_head_sha.strip()
    monitoring_probe_id = uuid.uuid4().hex[:12]
    trip_started_epoch = time.time()
    last_metric_write = 0.0
    monitoring_ok = False
    monitoring_incident_id: str | None = None
    ondemand_ok = ondemand_probe_id is None
    freshest_bridge_epoch: float | None = None
    freshest_reconciler_epoch: float | None = None
    main_check_violation_observed = False
    main_check_violation_count = 0
    main_check_violation_head_shas: list[str] = []
    expected_violation_ok = not expected_violation_sha

    try:
        deadline = trip_started_epoch + max(timeout_seconds, 15)
        while time.time() < deadline:
            now = time.time()
            if now - last_metric_write >= 55.0:
                write_heartbeat_metric(
                    project=project,
                    token=token,
                    value=1,
                    probe_id=monitoring_probe_id,
                )
                last_metric_write = now

            batch = inspect_subscription_batch(
                subscription_path=subscription_path,
                token=token,
                trip_started_epoch=trip_started_epoch,
                expected_ondemand_probe_id=ondemand_probe_id,
                expected_violation_head_sha=expected_violation_sha or None,
            )
            if batch["monitoring_heartbeat_observed"]:
                monitoring_ok = True
                monitoring_incident_id = batch["monitoring_incident_id"]
            if batch["ondemand_bridge_probe_observed"]:
                ondemand_ok = True
            if batch["freshest_bridge_heartbeat_epoch"] is not None:
                if (
                    freshest_bridge_epoch is None
                    or batch["freshest_bridge_heartbeat_epoch"] > freshest_bridge_epoch
                ):
                    freshest_bridge_epoch = batch["freshest_bridge_heartbeat_epoch"]
            reconciler_epoch = batch.get("freshest_reconciler_heartbeat_epoch")
            if reconciler_epoch is not None:
                if (
                    freshest_reconciler_epoch is None
                    or reconciler_epoch > freshest_reconciler_epoch
                ):
                    freshest_reconciler_epoch = reconciler_epoch
            if batch.get("main_check_violation_observed"):
                main_check_violation_observed = True
            main_check_violation_count = max(
                main_check_violation_count,
                int(batch.get("main_check_violation_count") or 0),
            )
            for sha in batch.get("main_check_violation_head_shas") or []:
                if sha not in main_check_violation_head_shas:
                    main_check_violation_head_shas.append(sha)
            if batch.get("expected_violation_observed"):
                expected_violation_ok = True

            bridge_fresh_ok = not require_bridge_heartbeat or (
                freshest_bridge_epoch is not None
                and (time.time() - freshest_bridge_epoch)
                <= max_bridge_heartbeat_age_seconds
            )
            if (
                monitoring_ok
                and ondemand_ok
                and bridge_fresh_ok
                and expected_violation_ok
            ):
                break

            time.sleep(max(poll_interval_seconds, 1))
    finally:
        # Always reset the synthetic probe gauge to 0 so the heartbeat policy closes.
        write_heartbeat_metric(
            project=project,
            token=token,
            value=0,
            probe_id=monitoring_probe_id,
        )

    if not monitoring_ok:
        raise AlertVerificationError(
            f"Timed out after {timeout_seconds}s waiting for Cloud Monitoring "
            f"alert_pipeline_heartbeat notification on {subscription_path!r}."
        )

    if not ondemand_ok:
        raise AlertVerificationError(
            f"On-demand compliance-bridge Pub/Sub probe ({ondemand_probe_id}) was "
            f"not observed on {subscription_path!r} within {timeout_seconds}s."
        )

    if not expected_violation_ok:
        raise AlertVerificationError(
            f"Expected main_result_reconciler main_check_violation envelope for SHA "
            f"{expected_violation_sha!r} was not observed on {subscription_path!r} "
            f"within {timeout_seconds}s (seen={main_check_violation_head_shas!r})."
        )

    bridge_age_seconds: float | None = None
    if freshest_bridge_epoch is not None:
        bridge_age_seconds = round(max(0.0, time.time() - freshest_bridge_epoch), 2)

    reconciler_age_seconds: float | None = None
    if freshest_reconciler_epoch is not None:
        reconciler_age_seconds = round(
            max(0.0, time.time() - freshest_reconciler_epoch), 2
        )

    if require_bridge_heartbeat:
        if bridge_age_seconds is None:
            raise AlertVerificationError(
                f"No periodic compliance_bridge heartbeat message found on "
                f"{subscription_path!r} (expected within "
                f"{max_bridge_heartbeat_age_seconds}s)."
            )
        if bridge_age_seconds > max_bridge_heartbeat_age_seconds:
            raise AlertVerificationError(
                f"Freshest compliance_bridge heartbeat on {subscription_path!r} is "
                f"{bridge_age_seconds:.1f}s old, exceeding max age "
                f"{max_bridge_heartbeat_age_seconds}s."
            )

    return {
        "subscription": subscription_path,
        "monitoring_heartbeat_delivered": True,
        "monitoring_incident_id": monitoring_incident_id,
        "ondemand_bridge_probe_delivered": ondemand_probe_id is not None,
        "periodic_bridge_heartbeat_age_seconds": bridge_age_seconds,
        "periodic_reconciler_heartbeat_age_seconds": reconciler_age_seconds,
        "main_check_violation_observed": main_check_violation_observed,
        "main_check_violation_count": main_check_violation_count,
        "main_check_violation_head_shas": main_check_violation_head_shas,
        "expected_main_check_violation_sha": expected_violation_sha or None,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify CAGE Cloud Monitoring AlertPolicy bindings and end-to-end "
            "heartbeat delivery to the terminal Pub/Sub subscription (POAM-2026-230)."
        )
    )
    parser.add_argument("--project", required=True, help="GCP project ID.")
    parser.add_argument(
        "--cluster-name",
        default="cage-staging",
        help="Cluster prefix on AlertPolicy displayName (default: cage-staging).",
    )
    parser.add_argument(
        "--subscription",
        required=True,
        help="Pub/Sub subscription name or full projects/<p>/subscriptions/<s> path.",
    )
    parser.add_argument(
        "--min-policies",
        type=int,
        default=9,
        help="Minimum number of cluster AlertPolicies required (default: 9).",
    )
    parser.add_argument(
        "--expected-channel",
        action="append",
        default=[],
        help="Optional expected NotificationChannel resource name (repeatable).",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=360,
        help="Max seconds to wait for heartbeat incident delivery (default: 360).",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=int,
        default=10,
        help="Seconds between Pub/Sub pull checks (default: 10).",
    )
    parser.add_argument(
        "--skip-bridge-heartbeat",
        action="store_true",
        help="Skip asserting freshness of the in-cluster periodic compliance-bridge heartbeat.",
    )
    parser.add_argument(
        "--max-bridge-heartbeat-age-seconds",
        type=int,
        default=25200,
        help="Max age in seconds for the periodic compliance-bridge heartbeat (default: 25200 = 7h).",
    )
    parser.add_argument(
        "--emit-bridge-heartbeat-topic",
        default="",
        help="Optional Pub/Sub topic to publish an immediate on-demand bridge probe.",
    )
    parser.add_argument(
        "--expect-main-check-violation-sha",
        default="",
        help=(
            "Optional git commit SHA (prefix or full) expected in a "
            "main_result_reconciler main_check_violation envelope on the queue."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        token = resolve_gcp_access_token()
        policy_report = verify_runtime_alert_policies(
            project=args.project,
            cluster_name=args.cluster_name,
            token=token,
            min_policies=args.min_policies,
            expected_channels=args.expected_channel or None,
        )
        delivery_report = verify_end_to_end_delivery(
            project=args.project,
            subscription=args.subscription,
            token=token,
            timeout_seconds=args.timeout_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
            require_bridge_heartbeat=not args.skip_bridge_heartbeat,
            max_bridge_heartbeat_age_seconds=args.max_bridge_heartbeat_age_seconds,
            emit_bridge_heartbeat_topic=args.emit_bridge_heartbeat_topic,
            expected_violation_head_sha=args.expect_main_check_violation_sha,
        )
    except AlertVerificationError as exc:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": str(exc),
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "status": "PASS",
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "runtime_policies": policy_report,
                "delivery": delivery_report,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
