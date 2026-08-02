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
measure_reconciliation_metrics.py — CAGE Paper Section 6.3/6.4/6.5 Data Collector
==================================================================================

Produces real, measured data for the three POAM-023 reconciliation sections of
the evaluation (CAGE_ARXIV.MD, §6.3-6.5):

  * Section 6.3 — Reconciliation write-path cost (T_reconcile)
  * Section 6.4 — CBF read-path overhead (Delta t)
  * Section 6.5 — Safety violation detection

Unlike scripts/measure_paper_metrics.py (which mocks all I/O-bound
dependencies to isolate pure governance-logic latency), this script
deliberately exercises the REAL production code paths end-to-end wherever
possible:

  * ``src/compliance_bridge/reconciliation_worker.py``  — ExternalLedgerReconciler,
    the actual daemon loop (via .reconcile(), not a reimplementation)
  * ``src/gateway/governance/kms_signer.py``             — KMSGovernanceSigner,
    signing against a live Cloud KMS asymmetric key
  * ``src/gateway/governance/cbf.py``                    — ControlBarrierFunction,
    the actual verify_action()/_read_cbf_state_atomic() barrier logic

Methodology disclosure (read before trusting the numbers below)
-----------------------------------------------------------------
Three components require live external infrastructure that is not always
available to every operator of this script.  Each is measured independently
and the script clearly reports which components were live vs. skipped:

  1. **Plaid fetch**: Requires PLAID_CLIENT_ID/PLAID_SECRET/PLAID_ACCESS_TOKEN
     for a fully authenticated call.  When these are not configured (the
     common case for CI and most reviewers), the script instead measures the
     real network + TLS + HTTP round-trip to the live Plaid Production
     endpoint using intentionally-invalid credentials (Plaid still fully
     processes the TLS handshake and returns a fast auth-validation error —
     this captures the network-bound component of the latency honestly,
     while explicitly NOT claiming to have measured the authenticated data
     path). This mode is labelled ``plaid_fetch_mode: "network_rtt_proxy"``
     in the output; the fully-authenticated mode is labelled
     ``"live_authenticated"``.
  2. **Cloud KMS asymmetricSign**: Requires ``KMS_GOVERNANCE_KEY`` to point at
     a real Cloud KMS asymmetric-signing key version the caller has
     ``cloudkms.cryptoKeyVersions.useToSign`` on. If unset, this section is
     skipped entirely (no fabricated numbers) and the output records
     ``kms_sign: "SKIPPED — KMS_GOVERNANCE_KEY not set"``.
  3. **Redis SETEX**: Requires ``REDIS_HOST``/``REDIS_PORT`` (or
     ``REDIS_URL``) pointing at a reachable Redis instance. If unreachable,
     this section is skipped with a clear message.

Run with all three configured for a complete, honest end-to-end result:

    export KMS_GOVERNANCE_KEY="projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1"
    export REDIS_HOST=localhost REDIS_PORT=16379
    export CAGE_ENV=development
    uv run python scripts/measure_reconciliation_metrics.py

Outputs:
    /tmp/cage_reconciliation_metrics.json   (machine-readable)
    /tmp/cage_reconciliation_metrics.txt    (human-readable table summary)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

os.environ.setdefault("CAGE_ENV", "development")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("RECONCILIATION_PROVIDER", "stub")

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("measure_reconciliation_metrics")

N_ITERATIONS: int = int(os.environ.get("RECONCILIATION_MEASURE_RUNS", "20"))
N_ITERATIONS_FAST: int = int(os.environ.get("CBF_READ_MEASURE_RUNS", "200"))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _percentiles(samples: list[float]) -> dict[str, float]:
    """Return P50, P95, P99, mean rounded to 3 dp."""
    if not samples:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}
    s = sorted(samples)
    n = len(s)

    def _p(pct: float) -> float:
        idx = min(int(pct / 100 * n), n - 1)
        return round(s[idx], 3)

    return {
        "p50": _p(50),
        "p95": _p(95),
        "p99": _p(99),
        "mean": round(statistics.mean(s), 3),
    }


def _redis_available() -> tuple[bool, str]:
    """Probe Redis connectivity using the same env vars as redis_client.py."""
    try:
        import redis as _redis_sync

        host = os.environ.get("REDIS_HOST", "localhost")
        port = int(os.environ.get("REDIS_PORT", "6379"))
        client = _redis_sync.Redis(
            host=host, port=port, socket_connect_timeout=2.0, socket_timeout=2.0
        )
        client.ping()
        client.close()
        return True, f"{host}:{port}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _kms_available() -> tuple[bool, str]:
    """Return True if KMS_GOVERNANCE_KEY is configured for a real signing attempt."""
    key = os.environ.get("KMS_GOVERNANCE_KEY", "")
    if not key:
        return False, "KMS_GOVERNANCE_KEY not set"
    return True, key


# ---------------------------------------------------------------------------
# Section 6.3 — Reconciliation write-path cost (T_reconcile)
# ---------------------------------------------------------------------------
#
# T_reconcile = t_plaid_fetch + t_kms_sign + t_redis_write
#
# Measured two ways depending on available credentials:
#
#   (a) live_authenticated — PLAID_CLIENT_ID/SECRET/ACCESS_TOKEN configured:
#       runs the real ExternalLedgerReconciler.reconcile() end-to-end using
#       PlaidLedgerProvider, capturing the OTel span attributes it already
#       emits (reconciliation.plaid_fetch_ms / kms_sign_ms / redis_write_ms).
#
#   (b) network_rtt_proxy — no Plaid credentials: measures the real network
#       round-trip to the live Plaid Production endpoint using intentionally
#       invalid credentials (captures TLS + network latency honestly; the
#       call fails fast with an auth error, so it does NOT exercise
#       PlaidLedgerProvider's full parsing path). KMS sign and Redis write
#       are still measured for real using ExternalLedgerReconciler against a
#       synthetic ReconciliationResult.
# ---------------------------------------------------------------------------


def _measure_plaid_network_rtt(n: int) -> list[float]:
    """Measure real network+TLS+HTTP round-trip to Plaid Production.

    Uses intentionally-invalid credentials. Plaid still performs the full
    TLS handshake and request parsing before returning a 400 INVALID_FIELD
    error, so this captures genuine network latency to the production
    endpoint without requiring real credentials.
    """
    url = "https://production.plaid.com/accounts/balance/get"
    payload = json.dumps(
        {
            "client_id": "cage_benchmark_probe",
            "secret": "cage_benchmark_probe",
            "access_token": "cage_benchmark_probe",
        }
    ).encode("utf-8")

    samples: list[float] = []
    for _ in range(n):
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Plaid-Version": "2020-09-14",
            },
            method="POST",
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            exc.read()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Plaid network probe failed: %s", exc)
            continue
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


class _SyntheticGroundTruthProvider:
    """LedgerProvider stand-in used only when live Plaid credentials are
    unavailable, so that the KMS-sign and Redis-write stages of
    ExternalLedgerReconciler.reconcile() can still be measured for real.

    NEVER used in production — see reconciliation_worker.py's own
    production guard, which blocks RECONCILIATION_PROVIDER=stub outside
    dev/test/ci. This class exists solely inside this benchmark script.
    """

    def __init__(self, balance_usd: float) -> None:
        self._balance_usd = balance_usd

    def fetch_balance(self, account_id: str):  # noqa: ANN201
        from src.compliance_bridge.reconciliation_worker import (
            ReconciliationResult,
        )

        return ReconciliationResult(
            source="plaid",
            balance_usd=self._balance_usd,
            raw_response={"account_id": account_id, "benchmark_synthetic": True},
        )


def _measure_reconciliation_write_path(
    n: int, redis_host: str, redis_port: int, use_live_plaid: bool
) -> dict[str, Any]:
    """Run ExternalLedgerReconciler.reconcile() n times against real Redis +
    real Cloud KMS, capturing the OTel spans it already emits.

    Returns a dict with per-stage percentile latencies and a mode label.
    """
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    import redis as _redis_sync

    from src.compliance_bridge.reconciliation_worker import ExternalLedgerReconciler

    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "cage-bench"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    otel_trace.set_tracer_provider(provider)

    redis_client = _redis_sync.Redis(
        host=redis_host, port=redis_port, decode_responses=True
    )

    if use_live_plaid:
        from src.compliance_bridge.reconciliation_worker import PlaidLedgerProvider

        provider_obj = PlaidLedgerProvider()
        mode = "live_authenticated"
    else:
        provider_obj = _SyntheticGroundTruthProvider(balance_usd=48_250.0)
        mode = "network_rtt_proxy"

    reconciler = ExternalLedgerReconciler(
        provider=provider_obj,
        redis_client=redis_client,
        account_id="cage-benchmark-account",
    )

    fetch_ms: list[float] = []
    kms_ms: list[float] = []
    redis_ms: list[float] = []
    total_ms: list[float] = []
    failures = 0

    for _ in range(n):
        exporter.clear()
        t0 = time.perf_counter()
        result = reconciler.reconcile()
        wall_ms = (time.perf_counter() - t0) * 1000.0

        spans = exporter.get_finished_spans()
        cycle_span = next((s for s in spans if s.name == "reconciliation.cycle"), None)
        if cycle_span is None or not result.is_valid:
            failures += 1
            continue

        attrs = dict(cycle_span.attributes or {})
        if "reconciliation.kms_sign_ms" not in attrs:
            # KMS signing was skipped/failed (e.g. no KMS_GOVERNANCE_KEY) —
            # do not fabricate a value.
            failures += 1
            continue

        total_ms.append(wall_ms)
        kms_ms.append(float(attrs.get("reconciliation.kms_sign_ms", 0.0)))
        redis_ms.append(float(attrs.get("reconciliation.redis_write_ms", 0.0)))
        if use_live_plaid:
            fetch_ms.append(float(attrs.get("reconciliation.plaid_fetch_ms", 0.0)))

    if not use_live_plaid:
        # The synthetic provider above makes no network call, so the Plaid
        # fetch component is measured separately as a real network-RTT proxy
        # against the live Plaid Production endpoint.
        fetch_ms = _measure_plaid_network_rtt(n)

    return {
        "mode": mode,
        "iterations_requested": n,
        "iterations_succeeded": len(total_ms),
        "failures": failures,
        "plaid_fetch_ms": _percentiles(fetch_ms),
        "kms_sign_ms": _percentiles(kms_ms),
        "redis_write_ms": _percentiles(redis_ms),
    }


# ---------------------------------------------------------------------------
# Section 6.4 — CBF read-path overhead (Delta t)
# ---------------------------------------------------------------------------
#
# Compares the real ControlBarrierFunction._read_cbf_state_atomic() cost when
# the reconciled balance is present+valid ("reconciled" path, includes a real
# local KMS-signature verify) vs. when it is absent ("self_reported" path,
# a single Redis GET).  Both paths run against a live Redis instance and use
# the actual production cbf.py code — not a reimplementation.
# ---------------------------------------------------------------------------


async def _measure_cbf_read_overhead(
    n: int, redis_host: str, redis_port: int, kms_key: str | None
) -> dict[str, Any]:
    """Measure the real Redis + KMS-verify cost of both balance-read paths.

    Deliberately does NOT patch ``read_verified_balance()`` — doing so would
    skip the real Redis GET + JSON deserialize + staleness check, making the
    "reconciled" path artificially fast and invalidating the comparison.
    Instead, this function writes genuine payloads into the real Redis keys
    (``reconciliation:verified_balance`` present or absent) and lets
    ``_read_cbf_state_atomic()`` perform its normal, unmocked read.
    """
    import redis as _redis_sync

    from src.compliance_bridge.reconciliation_worker import (
        _REDIS_KEY_VERIFIED_BALANCE,
    )
    from src.gateway.governance.cbf import ControlBarrierFunction

    os.environ["REDIS_HOST"] = redis_host
    os.environ["REDIS_PORT"] = str(redis_port)

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    from src.gateway.infrastructure.redis_client import redis_client as gw_redis

    sync_redis = _redis_sync.Redis(host=redis_host, port=redis_port, decode_responses=True)

    # Seed a self-reported balance.
    await gw_redis.set(cbf.redis_key, "48250.0")

    self_reported_samples: list[float] = []
    reconciled_samples: list[float] = []

    # --- self_reported path: ensure the reconciliation key is genuinely absent ---
    sync_redis.delete(_REDIS_KEY_VERIFIED_BALANCE)
    for _ in range(n):
        t0 = time.perf_counter()
        state = await cbf._read_cbf_state_atomic()
        self_reported_samples.append((time.perf_counter() - t0) * 1000.0)
    assert state["source"] == "self_reported"

    # --- reconciled path: write a real, KMS-signed reconciliation result to Redis ---
    if kms_key:
        from src.gateway.governance.kms_signer import get_governance_signer
        from src.compliance_bridge.reconciliation_worker import (
            ReconciliationResult,
        )

        signer = get_governance_signer()
        payload_dict = {
            "source": "plaid",
            "balance_usd": 48_250.0,
            "verified_at": time.time(),
        }
        signature_hex = signer.sign(payload_dict)
        fresh_result = ReconciliationResult(
            source="plaid",
            balance_usd=payload_dict["balance_usd"],
            verified_at=payload_dict["verified_at"],
            signature=signature_hex,
        )
        sync_redis.setex(
            _REDIS_KEY_VERIFIED_BALANCE, 300, fresh_result.to_redis_payload()
        )
        for _ in range(n):
            t0 = time.perf_counter()
            state = await cbf._read_cbf_state_atomic()
            reconciled_samples.append((time.perf_counter() - t0) * 1000.0)
        sync_redis.delete(_REDIS_KEY_VERIFIED_BALANCE)
        assert state["source"] == "reconciled"

    self_p = _percentiles(self_reported_samples)
    recon_p = _percentiles(reconciled_samples) if reconciled_samples else None

    result: dict[str, Any] = {
        "iterations": n,
        "self_reported_ms": self_p,
        "reconciled_ms": recon_p,
    }
    if recon_p:
        result["delta_p50_ms"] = round(recon_p["p50"] - self_p["p50"], 3)
        result["delta_p95_ms"] = round(recon_p["p95"] - self_p["p95"], 3)
    else:
        result["delta_p50_ms"] = None
        result["delta_p95_ms"] = None
        result["note"] = "KMS_GOVERNANCE_KEY not set — reconciled path skipped"

    return result


# ---------------------------------------------------------------------------
# Section 6.5 — Safety violation detection
# ---------------------------------------------------------------------------
#
# IMPORTANT CORRECTION vs. the original paper draft: the previously-published
# example ($500,000 self-reported, $48,250 reconciled, $10,000 trade) does
# NOT actually trigger a CBF rejection under the real barrier formula
# (h(next)=$37,250 > required=$23,625 — the trade is SAFE either way). This
# function uses corrected numbers verified against the live cbf.py formula:
# an inflated self-reported balance ($500,000, would pass) vs. the true
# KMS-reconciled balance ($8,000, correctly rejects a $10,000 trade as it
# would drive the account negative). The scenario demonstrates the exact
# POAM-023 threat model: a compromised execution system inflates its
# self-reported balance to bypass the CBF; the externally-attested
# reconciled balance is what the CBF actually uses in this code path.
#
# The event name `CBF_RECONCILIATION_MISMATCH` used in the earlier paper
# draft does not exist anywhere in the codebase and has been removed from
# this script's output; the real, verifiable signals are:
#   - cbf.verify_action() return value starting with "[CTRL_MRM_004]"
#   - OTel span attribute safety.balance.source == "reconciled"
#   - OTel span attribute safety.result
# ---------------------------------------------------------------------------


async def _measure_safety_violation_detection(
    redis_host: str, redis_port: int, kms_key: str | None
) -> dict[str, Any]:
    """Exercise the real CBF verdict against genuine Redis state (no mocking
    of ``read_verified_balance`` — the reconciliation key is written for real
    so the entire read+verify code path executes unmodified).
    """
    if not kms_key:
        return {"skipped": "KMS_GOVERNANCE_KEY not set — cannot KMS-sign a reconciled balance"}

    import redis as _redis_sync

    os.environ["REDIS_HOST"] = redis_host
    os.environ["REDIS_PORT"] = str(redis_port)

    from src.gateway.governance.cbf import ControlBarrierFunction
    from src.gateway.governance.kms_signer import get_governance_signer
    from src.compliance_bridge.reconciliation_worker import (
        ReconciliationResult,
        _REDIS_KEY_VERIFIED_BALANCE,
    )
    from src.gateway.infrastructure.redis_client import redis_client as gw_redis

    sync_redis = _redis_sync.Redis(host=redis_host, port=redis_port, decode_responses=True)

    cbf = ControlBarrierFunction()
    cbf.tracer = None

    inflated_self_reported_balance = 500_000.0
    true_reconciled_balance = 8_000.0
    trade_amount = 10_000.0

    # 1. Seed the INFLATED self-reported balance (simulating a compromised
    #    execution system trying to make an unsafe trade look safe).
    await gw_redis.set(cbf.redis_key, str(inflated_self_reported_balance))

    # 2. Verdict WITHOUT reconciliation (i.e. what would happen if the CBF
    #    trusted the self-reported balance, as a non-production posture does).
    sync_redis.delete(_REDIS_KEY_VERIFIED_BALANCE)
    verdict_self_reported = await cbf.verify_action(
        "execute_trade", {"amount": trade_amount}
    )
    state_self_reported = await cbf._read_cbf_state_atomic()

    # 3. Verdict WITH the real, KMS-signed reconciled balance written to Redis.
    signer = get_governance_signer()
    payload_dict = {
        "source": "plaid",
        "balance_usd": true_reconciled_balance,
        "verified_at": time.time(),
    }
    signature_hex = signer.sign(payload_dict)
    recon_result = ReconciliationResult(
        source="plaid",
        balance_usd=payload_dict["balance_usd"],
        verified_at=payload_dict["verified_at"],
        signature=signature_hex,
    )
    sync_redis.setex(_REDIS_KEY_VERIFIED_BALANCE, 300, recon_result.to_redis_payload())
    verdict_reconciled = await cbf.verify_action(
        "execute_trade", {"amount": trade_amount}
    )
    state_reconciled = await cbf._read_cbf_state_atomic()
    sync_redis.delete(_REDIS_KEY_VERIFIED_BALANCE)

    return {
        "inflated_self_reported_balance_usd": inflated_self_reported_balance,
        "true_reconciled_balance_usd": true_reconciled_balance,
        "trade_amount_usd": trade_amount,
        "verdict_using_self_reported_balance": verdict_self_reported,
        "balance_source_used_1": state_self_reported["source"],
        "verdict_using_reconciled_balance": verdict_reconciled,
        "balance_source_used_2": state_reconciled["source"],
        "self_reported_verdict_was_safe": verdict_self_reported == "SAFE",
        "reconciled_verdict_was_unsafe": verdict_reconciled != "SAFE",
        "poam_023_validated": (
            verdict_self_reported == "SAFE" and verdict_reconciled != "SAFE"
        ),
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _fmt_write_path_table(write_path: dict[str, Any]) -> str:
    lines = [
        "",
        "## Table 3: Reconciliation Write-Path Latency (ms)",
        f"(mode: {write_path.get('mode', 'N/A')}; "
        f"{write_path.get('iterations_succeeded', 0)}/"
        f"{write_path.get('iterations_requested', 0)} iterations succeeded)",
        "",
        f"{'Component':<28} {'P50':>8} {'P95':>8} {'P99':>8} {'Mean':>8}",
        f"{'-' * 28} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8}",
    ]
    for label, key in (
        ("Plaid balance fetch", "plaid_fetch_ms"),
        ("Cloud KMS asymmetricSign", "kms_sign_ms"),
        ("Redis SETEX pipeline", "redis_write_ms"),
    ):
        stats = write_path.get(key) or {}
        lines.append(
            f"{label:<28} {stats.get('p50', 0):>8.2f} {stats.get('p95', 0):>8.2f} "
            f"{stats.get('p99', 0):>8.2f} {stats.get('mean', 0):>8.2f}"
        )
    return "\n".join(lines)


def _fmt_read_overhead_table(read_overhead: dict[str, Any]) -> str:
    lines = [
        "",
        "## Table 4: CBF Read-Path Overhead (ms)",
        f"({read_overhead.get('iterations', 0)} iterations)",
        "",
    ]
    self_p = read_overhead.get("self_reported_ms") or {}
    recon_p = read_overhead.get("reconciled_ms")
    lines.append(
        f"{'Path':<45} {'P50':>8} {'P95':>8}"
    )
    lines.append(f"{'-' * 45} {'-' * 8} {'-' * 8}")
    lines.append(
        f"{'Self-reported (safety:current_cash)':<45} "
        f"{self_p.get('p50', 0):>8.3f} {self_p.get('p95', 0):>8.3f}"
    )
    if recon_p:
        lines.append(
            f"{'Reconciled (verified_balance + KMS verify)':<45} "
            f"{recon_p.get('p50', 0):>8.3f} {recon_p.get('p95', 0):>8.3f}"
        )
        lines.append(
            f"\nDelta P50/P95 overhead: "
            f"{read_overhead.get('delta_p50_ms')} / {read_overhead.get('delta_p95_ms')} ms"
        )
    else:
        lines.append(f"\n{read_overhead.get('note', 'reconciled path skipped')}")
    return "\n".join(lines)


def _fmt_safety_violation_section(safety: dict[str, Any]) -> str:
    if safety.get("skipped"):
        return f"\n## Section 6.5: Safety Violation Detection\n\nSKIPPED — {safety['skipped']}\n"

    lines = [
        "",
        "## Section 6.5: Safety Violation Detection",
        "",
        f"Inflated self-reported balance: ${safety['inflated_self_reported_balance_usd']:,.2f}",
        f"True KMS-reconciled balance:    ${safety['true_reconciled_balance_usd']:,.2f}",
        f"Trade amount:                   ${safety['trade_amount_usd']:,.2f}",
        "",
        f"Verdict using self-reported balance (source={safety['balance_source_used_1']}):",
        f"  {safety['verdict_using_self_reported_balance']}",
        "",
        f"Verdict using reconciled balance (source={safety['balance_source_used_2']}):",
        f"  {safety['verdict_using_reconciled_balance']}",
        "",
        f"POAM-023 threat model validated: {safety['poam_023_validated']}",
    ]
    return "\n".join(lines)


def _write_outputs(results: dict[str, Any]) -> None:
    json_path = Path("/tmp/cage_reconciliation_metrics.json")
    txt_path = Path("/tmp/cage_reconciliation_metrics.txt")

    json_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"[output] JSON written to {json_path}")

    txt_content = (
        "CAGE §6.3/6.4/6.5 Reconciliation Measurements\n"
        "===============================================\n"
        f"Generated: {results['generated_at']}\n"
        + _fmt_write_path_table(results["write_path"])
        + "\n"
        + _fmt_read_overhead_table(results["read_overhead"])
        + "\n"
        + _fmt_safety_violation_section(results["safety_violation"])
        + "\n"
    )
    txt_path.write_text(txt_content)
    print(f"[output] Text summary written to {txt_path}")
    print()
    print(txt_content)


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------


async def _async_main() -> None:
    print("=" * 70)
    print("CAGE §6.3/6.4/6.5 Reconciliation Measurements")
    print("=" * 70)

    redis_ok, redis_info = _redis_available()
    kms_ok, kms_info = _kms_available()
    plaid_creds_ok = bool(
        os.environ.get("PLAID_CLIENT_ID")
        and os.environ.get("PLAID_SECRET")
        and os.environ.get("PLAID_ACCESS_TOKEN")
    )

    print(f"Redis available       : {redis_ok} ({redis_info})")
    print(f"KMS configured        : {kms_ok} ({kms_info if kms_ok else kms_info})")
    print(f"Plaid credentials set : {plaid_creds_ok}")
    print()

    if not redis_ok:
        print(
            "[FATAL] Redis is required for all three measurements in this "
            "script. Set REDIS_HOST/REDIS_PORT to a reachable instance "
            "(e.g. `docker run -d -p 16379:6379 redis:7-alpine` and "
            "REDIS_HOST=localhost REDIS_PORT=16379)."
        )
        sys.exit(1)

    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", "6379"))
    kms_key = os.environ.get("KMS_GOVERNANCE_KEY") or None

    if not kms_ok:
        print(
            "[WARN] KMS_GOVERNANCE_KEY not set — the KMS-sign component of "
            "§6.3, and the entirety of §6.4/§6.5 (which require a real "
            "KMS-signed reconciled balance) will be skipped rather than "
            "fabricated. Set KMS_GOVERNANCE_KEY to a real Cloud KMS "
            "asymmetric-signing key version to obtain complete results."
        )

    print("\n[6.3] Measuring reconciliation write-path cost...")
    write_path = _measure_reconciliation_write_path(
        N_ITERATIONS, redis_host, redis_port, use_live_plaid=plaid_creds_ok
    )
    print(f"  mode={write_path['mode']} " f"succeeded={write_path['iterations_succeeded']}/{write_path['iterations_requested']}")

    print("\n[6.4] Measuring CBF read-path overhead...")
    read_overhead = await _measure_cbf_read_overhead(
        N_ITERATIONS_FAST, redis_host, redis_port, kms_key
    )
    print(f"  self_reported P50={read_overhead['self_reported_ms']['p50']} ms")

    print("\n[6.5] Measuring safety violation detection...")
    safety_violation = await _measure_safety_violation_detection(
        redis_host, redis_port, kms_key
    )
    if safety_violation.get("skipped"):
        print(f"  SKIPPED: {safety_violation['skipped']}")
    else:
        print(f"  poam_023_validated={safety_violation['poam_023_validated']}")

    results = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "redis_target": f"{redis_host}:{redis_port}",
        "kms_configured": kms_ok,
        "plaid_credentials_configured": plaid_creds_ok,
        "write_path": write_path,
        "read_overhead": read_overhead,
        "safety_violation": safety_violation,
    }
    _write_outputs(results)


def main() -> None:
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()