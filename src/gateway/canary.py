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

"""Synthetic in-mesh governed liveness canary (SI-4 / AU-5).

Executes one non-mutating governed request per minute from inside the Linkerd
service mesh under its own dedicated Kubernetes ServiceAccount
(``cage-gateway-canary-sa``), resolving the structural ambiguity between:
  1. a genuinely idle cluster (where ``gateway-canary`` still succeeds once per
     minute, keeping ``rate(cage_gateway_gated_requests_total{outcome="permitted"}[5m]) > 0``), and
  2. a total-denial outage where external callers stopped retrying (where
     ``gateway-canary`` is refused or unreachable, driving ``rate(permitted)`` to
     ``0`` and paging ``google_monitoring_alert_policy.gateway_zero_permitted_requests``).

Because ``cage-gateway-canary-sa`` is authenticated via ``CAGE_CANARY_CLIENT_IDENTITIES``,
every custody-chain record emitted during a canary request is stamped server-side
with ``"canary": true`` by :class:`~src.gateway.governance.evidence.stream.EvidenceStreamSink`
and excluded by ``compliance-bridge`` from Lula volume thresholds and ``safety_rate``
(``A.5.2``, ``A.5.3``, ``A.9.2``, etc.) so CAGE never self-satisfies compliance
controls from traffic it generates itself.

This module is domain-agnostic kernel code (Layer 1).
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from urllib.parse import urlparse

import httpx

from src.gateway.governance.contracts import CanaryProbe
from src.gateway.governance.plugin_loader import active_domain_config

logger = logging.getLogger("Gateway.Canary")

DEFAULT_GATEWAY_URL = "http://gateway.governance-stack.svc.cluster.local:8080"
DEFAULT_INTERVAL_SECONDS = 60.0
DEFAULT_TIMEOUT_SECONDS = 10.0


def validate_gateway_base_url(raw_url: str) -> str:
    """Validate that ``raw_url`` uses ``http`` or ``https`` with a non-empty host."""
    cleaned = raw_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"CAGE_GATEWAY_CANARY_URL must be an http:// or https:// URL, got {raw_url!r}"
        )
    return cleaned


async def run_canary_probe_once(
    client: httpx.AsyncClient,
    base_url: str,
    probe: CanaryProbe,
) -> bool:
    """Execute one governed canary probe and return True iff admitted as ALLOW."""
    target = f"{validate_gateway_base_url(base_url)}{probe.route}"
    payload = {
        "action": probe.action,
        "params": dict(probe.params),
    }
    try:
        resp = await client.post(target, json=payload)
    except Exception as exc:
        logger.warning("CANARY_PROBE_UNREACHABLE url=%s error=%s", target, exc)
        return False

    if resp.status_code != 200:
        logger.warning(
            "CANARY_PROBE_BLOCKED url=%s status=%d",
            target,
            resp.status_code,
        )
        return False

    try:
        body = resp.json()
    except ValueError:
        logger.warning("CANARY_PROBE_INVALID_JSON url=%s", target)
        return False

    if not isinstance(body, dict):
        return False

    if probe.route == "/governance/policy-precheck":
        ok = body.get("decision") == "ALLOW"
    else:
        gov = body.get("payload", {}).get("governance", {})
        verdict = gov.get("verdict") if isinstance(gov, dict) else None
        ok = verdict in ("ALLOW", None)

    if not ok:
        logger.warning("CANARY_PROBE_DENIED url=%s action=%s", target, probe.action)
    return ok


async def run_canary_loop(
    *,
    base_url: str | None = None,
    interval_seconds: float | None = None,
    timeout_seconds: float | None = None,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Continuously run the active domain's governed canary probe once per interval."""
    resolved_url = validate_gateway_base_url(
        base_url
        if base_url is not None
        else os.environ.get("CAGE_GATEWAY_CANARY_URL", DEFAULT_GATEWAY_URL)
    )
    resolved_interval = (
        float(interval_seconds)
        if interval_seconds is not None
        else float(
            os.environ.get(
                "CAGE_CANARY_INTERVAL_SECONDS", str(DEFAULT_INTERVAL_SECONDS)
            )
        )
    )
    if resolved_interval < 5.0:
        raise ValueError(
            f"CAGE_CANARY_INTERVAL_SECONDS must be >= 5.0s, got {resolved_interval}"
        )
    resolved_timeout = (
        float(timeout_seconds)
        if timeout_seconds is not None
        else float(
            os.environ.get(
                "CAGE_CANARY_REQUEST_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)
            )
        )
    )

    probe = active_domain_config().canary_probe
    if probe is None:
        raise RuntimeError(
            "Active CAGE_DOMAIN declares no CanaryProbe; refusing to start gateway-canary."
        )

    shutdown = stop_event if stop_event is not None else asyncio.Event()
    logger.info(
        "Starting gateway-canary loop: url=%s%s action=%s interval=%.1fs",
        resolved_url,
        probe.route,
        probe.action,
        resolved_interval,
    )

    async with httpx.AsyncClient(timeout=resolved_timeout) as client:
        while not shutdown.is_set():
            await run_canary_probe_once(client, resolved_url, probe)
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=resolved_interval)
            except TimeoutError:
                continue


def _main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    stop_event = asyncio.Event()

    async def _runner() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:  # pragma: no cover - Windows fallback
                pass
        await run_canary_loop(stop_event=stop_event)

    asyncio.run(_runner())


if __name__ == "__main__":
    _main()
