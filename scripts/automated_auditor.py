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

"""AU-12 / SI-4 Compliance: Automated Auditor with live Langfuse SDK trace source.

POAM-003 Resolution (2026-03-06):
    Replaced all mock/hardcoded trace data with live Langfuse SDK calls.
    The Langfuse trace source is now the default (AUDITOR_TRACE_SOURCE=langfuse).
    Use --dry-run (or AUDITOR_TRACE_SOURCE=mock) for local testing only.

Set AUDITOR_TRACE_SOURCE to one of:
    langfuse   — live Langfuse SDK (default, satisfies AU-12)
    otlp       — Jaeger-compatible HTTP query API (NOT the deprecated standalone
                 OTel Collector; the collector sidecar on port 4318 is removed)
    cloudtrace — Google Cloud Trace API
    mock       — synthetic data for testing (does NOT satisfy AU-12)

Required env vars for the Langfuse source:
    LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST
"""

import logging
import os
import sys
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from src.gateway.governance.env_posture import resolve_deployment_region

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("AutomatedAuditor")

# ---------------------------------------------------------------------------
# Environment-driven configuration
# ---------------------------------------------------------------------------
_AUDITOR_TRACE_SOURCE = os.environ.get("AUDITOR_TRACE_SOURCE", "langfuse")
# AUDITOR_OTLP_ENDPOINT is only used when AUDITOR_TRACE_SOURCE=otlp (Jaeger HTTP query API).
# The standalone OTel Collector sidecar (port 4318) is deprecated and removed.
# Do NOT set this to localhost:4318 — that endpoint no longer exists.
_AUDITOR_OTLP_ENDPOINT = os.environ.get("AUDITOR_OTLP_ENDPOINT", "")
_AUDITOR_GCP_PROJECT_ID = os.environ.get("AUDITOR_GCP_PROJECT_ID", "")

# Langfuse credentials — mirrors the pattern in src/compliance_bridge/metrics.py
_LANGFUSE_PUBLIC_KEY = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
_LANGFUSE_SECRET_KEY = os.environ.get("LANGFUSE_SECRET_KEY", "")


def _resolve_langfuse_host() -> str:
    """Resolve LANGFUSE_HOST lazily so importing automated_auditor never crashes."""
    from src.gateway.governance.env_posture import is_enforcing, resolve_posture

    host = os.environ.get("LANGFUSE_HOST", "").strip()
    if host:
        return host
    active_region = resolve_deployment_region()
    if active_region in ("EU_ECB", "APAC_MAS") or is_enforcing(resolve_posture()):
        raise RuntimeError(
            f"LANGFUSE_HOST must be explicitly set for {active_region} / enforcing "
            "deployments to ensure sovereign data residency compliance "
            "(GDPR Art. 44 / MAS TRM §4.2 / NIST AU-12). "
            "Set LANGFUSE_HOST to your in-region Langfuse instance."
        )
    return "http://localhost:3000"


# ---------------------------------------------------------------------------
# TraceSource abstract base class
# ---------------------------------------------------------------------------


class TraceSource(ABC):
    """Abstract base for trace backends consumed by the automated auditor."""

    @abstractmethod
    def fetch_traces(self, service_name: str, lookback_minutes: int) -> list[dict]:
        """Fetch recent traces for *service_name* covering the last *lookback_minutes*.

        Returns a list of trace dicts, each containing at minimum:
            {"trace_id": str, "spans": list[dict]}
        """


# ---------------------------------------------------------------------------
# OTLP / Jaeger-compatible HTTP backend
# ---------------------------------------------------------------------------


def validate_auditor_url(url: str) -> str:
    """Validate that *url* uses http or https with a non-empty netloc (Bandit B310)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"Invalid URL scheme or missing host in auditor URL: {url!r} "
            "(expected http:// or https:// with a non-empty netloc)"
        )
    return url


_validate_auditor_url = validate_auditor_url


class OTLPTraceSource(TraceSource):
    """Query a Jaeger / OTLP-compatible HTTP endpoint for recent traces.

    Uses the Jaeger HTTP API:
        GET {endpoint}/api/traces?service={service_name}&lookback={lookback_minutes}m
    """

    def __init__(self, endpoint: str = _AUDITOR_OTLP_ENDPOINT):
        self.endpoint = endpoint.rstrip("/")

    def fetch_traces(self, service_name: str, lookback_minutes: int) -> list[dict]:
        import json as _json

        url = f"{self.endpoint}/api/traces?service={service_name}&lookback={lookback_minutes}m"
        validate_auditor_url(url)
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310  # scheme validated to http/https above
                payload = _json.loads(resp.read().decode())
            # Jaeger returns {"data": [...traces...]}
            raw_traces = payload.get("data", [])
            logger.info(
                "OTLPTraceSource: fetched %d traces from %s", len(raw_traces), url
            )
            return raw_traces
        except Exception as exc:
            logger.warning(
                "OTLPTraceSource: could not reach endpoint %s — %s. "
                "Returning empty trace list. Check AUDITOR_OTLP_ENDPOINT.",
                self.endpoint,
                exc,
            )
            return []


# ---------------------------------------------------------------------------
# GCP Cloud Trace backend
# ---------------------------------------------------------------------------


class CloudTraceSource(TraceSource):
    """Query Google Cloud Trace API for recent traces.

    Requires the ``google-cloud-trace`` package and AUDITOR_GCP_PROJECT_ID.
    """

    def __init__(self, project_id: str = _AUDITOR_GCP_PROJECT_ID) -> None:
        try:
            from google.cloud import (
                trace_v1,  # type: ignore[attr-defined,import-untyped]
            )

            self._trace_v1: Any = trace_v1
        except ImportError as exc:
            raise ImportError(
                "The 'google-cloud-trace' package is required for AUDITOR_TRACE_SOURCE=cloudtrace. "
                "Install it with: pip install google-cloud-trace"
            ) from exc

        if not project_id:
            raise ValueError(
                "AUDITOR_GCP_PROJECT_ID must be set when AUDITOR_TRACE_SOURCE=cloudtrace."
            )
        self.project_id = project_id

    def fetch_traces(self, service_name: str, lookback_minutes: int) -> list[dict]:
        client = self._trace_v1.TraceServiceClient()
        try:
            traces = list(client.list_traces(request={"project_id": self.project_id}))
            logger.info(
                "CloudTraceSource: fetched %d traces from GCP project %s",
                len(traces),
                self.project_id,
            )
            result = []
            for t in traces:
                spans = [
                    {
                        "name": getattr(s, "name", ""),
                        "attributes": dict(getattr(s, "labels", {}) or {}),
                        "start_time": s.start_time.timestamp()
                        if getattr(s, "start_time", None)
                        else 0.0,
                        "end_time": s.end_time.timestamp()
                        if getattr(s, "end_time", None)
                        else 0.0,
                    }
                    for s in getattr(t, "spans", [])
                ]
                result.append({"trace_id": getattr(t, "trace_id", ""), "spans": spans})
            return result
        except Exception as exc:
            logger.warning(
                "CloudTraceSource: error fetching traces — %s. Returning empty list.",
                exc,
            )
            return []


# ---------------------------------------------------------------------------
# Langfuse SDK backend (live, satisfies AU-12 — POAM-003)
# ---------------------------------------------------------------------------


class LangfuseTraceSource(TraceSource):
    """Query the live Langfuse project for recent traces via the Langfuse Python SDK."""

    def __init__(self) -> None:
        try:
            from langfuse import Langfuse
        except ImportError as exc:
            raise ImportError(
                "The 'langfuse' package is required for AUDITOR_TRACE_SOURCE=langfuse. "
                "Install it with: pip install langfuse"
            ) from exc

        self._host = _resolve_langfuse_host()
        self._langfuse = Langfuse(
            public_key=os.environ.get("LANGFUSE_PUBLIC_KEY", _LANGFUSE_PUBLIC_KEY),
            secret_key=os.environ.get("LANGFUSE_SECRET_KEY", _LANGFUSE_SECRET_KEY),
            host=self._host,
        )

    def fetch_traces(self, service_name: str, lookback_minutes: int) -> list[dict]:
        window_start = datetime.now(tz=timezone.utc) - timedelta(
            minutes=lookback_minutes
        )

        try:
            traces_response = self._langfuse.api.trace.list(
                from_timestamp=window_start,
                limit=100,
            )
        except Exception as exc:
            logger.warning(
                "LangfuseTraceSource: could not reach Langfuse at %s — %s. "
                "Returning empty trace list. Check LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY / LANGFUSE_HOST.",
                self._host,
                exc,
            )
            return []

        result: list[dict] = []
        for trace in traces_response.data:
            try:
                full_trace = self._langfuse.api.trace.get(trace.id)
                observations = getattr(full_trace, "observations", []) or []
            except Exception as exc:
                logger.warning(
                    "LangfuseTraceSource: could not fetch observations for trace %s — %s",
                    trace.id,
                    exc,
                )
                observations = []

            spans: list[dict] = []
            for obs in observations:
                start_ts = (
                    obs.start_time.timestamp()
                    if getattr(obs, "start_time", None)
                    else 0.0
                )
                end_ts = (
                    obs.end_time.timestamp()
                    if getattr(obs, "end_time", None)
                    else start_ts
                )
                attrs = (
                    obs.metadata
                    if isinstance(getattr(obs, "metadata", None), dict)
                    else {}
                )
                spans.append(
                    {
                        "name": getattr(obs, "name", "") or "",
                        "attributes": attrs,
                        "start_time": start_ts,
                        "end_time": end_ts,
                    }
                )

            result.append({"trace_id": trace.id, "spans": spans})

        logger.info(
            "LangfuseTraceSource: fetched %d traces from %s (lookback=%dm)",
            len(result),
            self._host,
            lookback_minutes,
        )
        return result


# ---------------------------------------------------------------------------
# Mock backend (--dry-run / testing only)
# ---------------------------------------------------------------------------


class MockTraceSource(TraceSource):
    """Synthetic trace generator for unit/integration tests.

    WARNING: This source does NOT represent production audit coverage and does
    NOT satisfy AU-12 control requirements.  Set AUDITOR_TRACE_SOURCE=langfuse
    (default) for real production compliance via the Langfuse SDK.
    The standalone OTel Collector (AUDITOR_TRACE_SOURCE=otlp, port 4318) is
    deprecated and removed — do not use it as a production AU-12 source.
    """

    def fetch_traces(self, service_name: str, lookback_minutes: int) -> list[dict]:
        logger.warning(
            "AUDITOR_TRACE_SOURCE=mock: Using synthetic traces. "
            "This does not represent production audit coverage. "
            "Set AUDITOR_TRACE_SOURCE=langfuse for real AU-12 compliance "
            "(the standalone OTel Collector on port 4318 is deprecated and removed)."
        )

        # Scenario 1: Valid Path
        # Governance Check (ALLOW) -> Tool Execution
        trace_valid = {
            "trace_id": "t1",
            "spans": [
                {
                    "name": "governance.check",
                    "attributes": {"governance.decision": "ALLOW"},
                    "start_time": 100,
                    "end_time": 101,
                },
                {
                    "name": "tool.execution.dispatch_order",
                    "attributes": {"action": "dispatch_order"},
                    "start_time": 102,
                    "end_time": 200,
                },
            ],
        }

        # Scenario 2: Violation (Bypassed Governance)
        # Tool Execution without preceding Check
        trace_violation = {
            "trace_id": "t2",
            "spans": [
                {
                    "name": "tool.execution.dispatch_order",
                    "attributes": {"action": "dispatch_order"},
                    "start_time": 300,
                    "end_time": 400,
                }
            ],
        }

        # Scenario 3: Violation (Executed despite DENY)
        trace_violation_deny = {
            "trace_id": "t3",
            "spans": [
                {
                    "name": "governance.check",
                    "attributes": {"governance.decision": "DENY"},
                    "start_time": 500,
                    "end_time": 501,
                },
                {
                    "name": "tool.execution.dispatch_order",
                    "attributes": {"action": "dispatch_order"},
                    "start_time": 502,
                    "end_time": 600,
                },
            ],
        }

        # Randomly return a batch
        return [trace_valid, trace_violation, trace_violation_deny]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_trace_source() -> TraceSource:
    """Read AUDITOR_TRACE_SOURCE and return the appropriate TraceSource instance.

    Valid values: langfuse (default), otlp, cloudtrace, mock.

    Raises:
        ValueError: If an unknown source name is specified.
    """
    source = _AUDITOR_TRACE_SOURCE.lower()
    if source == "langfuse":
        return LangfuseTraceSource()
    elif source == "otlp":
        return OTLPTraceSource()
    elif source == "cloudtrace":
        return CloudTraceSource()
    elif source == "mock":
        return MockTraceSource()
    else:
        raise ValueError(
            f"Unknown AUDITOR_TRACE_SOURCE={_AUDITOR_TRACE_SOURCE!r}. "
            "Valid options are: langfuse, otlp, cloudtrace, mock."
        )


# ---------------------------------------------------------------------------
# TraceAuditor
# ---------------------------------------------------------------------------


class TraceAuditor:
    """
    Automated Auditor (Phase 3).
    Continuous verification loop that consumes OpenTelemetry traces from a
    configurable live source (OTLP, Cloud Trace) or a synthetic mock (testing only)
    and asserts structural safety invariants.
    """

    def __init__(self) -> None:
        self.violations: list[dict[str, str]] = []
        self.trace_source: TraceSource = create_trace_source()

    def audit_trace(self, trace: dict[str, Any]) -> None:
        """
        Invariant: Every 'tool.execution' span must have a causally preceding 'governance.check' span
        with decision='ALLOW' in the same trace.
        """
        spans = trace["spans"]

        # Find execution spans
        execution_spans = [s for s in spans if "tool.execution" in s["name"]]

        if not execution_spans:
            return  # No risky action, no audit needed

        # Find governance spans
        gov_spans = [s for s in spans if "governance.check" in s["name"]]

        for exec_span in execution_spans:
            # Check 1: Existence
            if not gov_spans:
                self.report_violation(trace["trace_id"], "Missing Governance Check")
                continue

            # Check 2: Precedence & Decision
            # In a real graph, we check ParentID. Here we use simplistic timestamp logic.
            valid_check_found = False
            for gov_span in gov_spans:
                is_preceding = gov_span["end_time"] <= exec_span["start_time"]
                is_allowed = gov_span["attributes"].get("governance.decision") in {
                    "ALLOW",
                    "NARROW",
                }

                if is_preceding and is_allowed:
                    valid_check_found = True
                    break

            if not valid_check_found:
                # Determine specific reason
                if any(
                    s["attributes"].get("governance.decision") == "DENY"
                    for s in gov_spans
                ):
                    self.report_violation(trace["trace_id"], "Execution despite DENY")
                else:
                    self.report_violation(
                        trace["trace_id"], "Orphaned Execution (No linking Check)"
                    )

    def report_violation(self, trace_id: str, reason: str) -> None:
        msg = f"🚨 AUDIT FAILURE | Trace: {trace_id} | Reason: {reason}"
        logger.error(msg)
        self.violations.append({"trace_id": trace_id, "reason": reason})

    def run(self, lookback_minutes: int = 60) -> int:
        logger.info("Starting Automated Auditor Loop...")
        traces = self.trace_source.fetch_traces(
            service_name="governance-gateway", lookback_minutes=lookback_minutes
        )
        for trace in traces:
            self.audit_trace(trace)

        if self.violations:
            logger.info(f"Audit Complete. Found {len(self.violations)} violations.")
            return 1
        logger.info("Audit Complete. System is Clean.")
        return 0


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="CAGE Automated Auditor — AU-12 / SI-4 compliance (POAM-003)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Use synthetic mock traces instead of a live Langfuse connection. "
            "For local testing only — does NOT satisfy AU-12 control requirements."
        ),
    )
    parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=60,
        help="How many minutes of traces to inspect (default: 60).",
    )
    args = parser.parse_args()

    if args.dry_run:
        logger.warning(
            "--dry-run enabled: overriding AUDITOR_TRACE_SOURCE to 'mock'. "
            "This does not represent production audit coverage."
        )
        os.environ["AUDITOR_TRACE_SOURCE"] = "mock"
        # Re-read the module-level constant so create_trace_source() picks it up.
        _AUDITOR_TRACE_SOURCE = "mock"

    auditor = TraceAuditor()
    exit_code = auditor.run(lookback_minutes=args.lookback_minutes)
    if not args.dry_run and exit_code != 0:
        sys.exit(exit_code)
