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
measure_reconciliation_metrics.py — CAGE §6.3/6.4/6.5 data collector
=====================================================================

Manual report tool: run by hand to produce numbers for the paper. It is not
part of the CI test suite.

Measures the ground-truth reconciliation path end to end, using the
production modules unmodified:

  * ``src/gateway/governance/reconciliation/daemon.py`` — ``GroundTruthReconciler``
    (``reconcile()``: fetch → validate → sign → publish → settle).
  * ``src/gateway/governance/reconciliation/trust.py`` — the reconciler's own
    signing identity (``RECONCILER_KMS_KEY``) and ``kid``-resolved verification.
    The gateway key (``KMS_GOVERNANCE_KEY``) is never used: the CBF rejects
    ground truth it signed (G8).
  * ``src/gateway/governance/safety/cbf_engine.py`` — ``ControlBarrierFunction``
    with the finance ``CashBarrier`` invariant and ``finance_cost_resolver``.
  * ``src/cage_finance/ground_truth.py`` — ``SimulatedCashLedgerProvider``, the
    Tier-2 reference custodian (simulated data, real security primitives).

Sections
--------
  §6.3  Reconciliation write path: per-tick ``reconciliation.fetch_ms``,
        ``reconciliation.kms_sign_ms`` and ``reconciliation.redis_write_ms``
        read from the ``reconciliation.cycle`` span the daemon emits.
  §6.4  CBF read overhead: ``_read_cbf_state_atomic()`` with no snapshot
        (self-reported path) vs. a signed snapshot (reconciled path, includes
        signature verification against the reconciler trust anchors).
  §6.5  Safety violation detection, three scenarios:
        (a) inflated self-reported state, no snapshot — what an unreconciled
            CBF preview would admit;
        (b) the reconciler meeting that inflated state — the discrepancy
            guard refuses to publish and bumps the fence epoch;
        (c) a signed $8,000 snapshot published, then the self-reported state
            inflated to $500,000 — the CBF nets against the snapshot and
            refuses the $10,000 trade.

Signing identity (no fabricated numbers)
----------------------------------------
  * ``RECONCILER_KMS_KEY`` set → the real KMS signer and verifier from
    ``trust.py``. Only these results are evidence-grade.
  * ``--software-signer`` → an in-process Ed25519 key, development posture
    only. Results are labelled ``signer: software_ed25519`` and are not
    evidence for POAM closure or OSCAL statements.
  * Neither → every section that needs a signature is reported as SKIPPED.

Redis
-----
Requires a reachable, **ephemeral** Redis (``REDIS_URL``, or ``REDIS_HOST`` /
``REDIS_PORT`` / ``REDIS_PASSWORD``). The run writes the CBF state, fence
epoch and snapshot keys, so it refuses to start if the CBF state key or the
fence epoch already exists (pass ``--force`` to override on a scratch
instance). It never rewinds a fence epoch.

    export REDIS_URL=redis://localhost:16379/0
    export RECONCILER_KMS_KEY="projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1"
    uv run python scripts/measure_reconciliation_metrics.py

Outputs (override with ``RECONCILIATION_OUTPUT_JSON`` / ``RECONCILIATION_OUTPUT_TXT``):
    /tmp/cage_reconciliation_metrics.json
    /tmp/cage_reconciliation_metrics.txt

Copy published runs to ``docs/paper/measurements/<date>-<sha>/`` together
with a filled-in ``PROVENANCE.md`` (see ``docs/paper/measurements/PROVENANCE_TEMPLATE.md``).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import statistics
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

os.environ.setdefault("CAGE_ENV", "development")
os.environ.setdefault("ENVIRONMENT", "development")

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("measure_reconciliation_metrics")

N_ITERATIONS: int = int(os.environ.get("RECONCILIATION_MEASURE_RUNS", "20"))
N_ITERATIONS_FAST: int = int(os.environ.get("CBF_READ_MEASURE_RUNS", "200"))

ACTION = "execute_trade"
SOFTWARE_KID = "software-ed25519/cage-reconciliation-benchmark"
SIGNER_KMS = "kms"
SIGNER_SOFTWARE = "software_ed25519"

#: §6.5 scenario values. Under ``CashBarrier`` (floor from
#: ``domains.finance.cbf.min_cash_balance``, gamma 0.5) a $10,000 trade is
#: admitted from $500,000 and refused from $8,000 (it would breach the floor).
INFLATED_SELF_REPORTED = 500_000.0
TRUE_CUSTODIAN_BALANCE = 8_000.0
TRADE_AMOUNT = 10_000.0
READ_PATH_BALANCE = 48_250.0


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
        return round(s[min(int(pct / 100 * n), n - 1)], 3)

    return {"p50": _p(50), "p95": _p(95), "p99": _p(99), "mean": round(statistics.mean(s), 3)}


def _redis_target() -> str:
    """Human-readable Redis target with any credentials removed."""
    url = os.environ.get("REDIS_URL", "")
    if url:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.hostname}:{parsed.port or 6379}{parsed.path}"
    return f"{os.environ.get('REDIS_HOST', 'localhost')}:{os.environ.get('REDIS_PORT', '6379')}"


def _make_sync_redis() -> Any:
    """Raw sync Redis client for the reconciler, built from the same env as the gateway."""
    import redis

    url = os.environ.get("REDIS_URL", "")
    if url:
        return redis.Redis.from_url(url, decode_responses=True)
    return redis.Redis(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        password=os.environ.get("REDIS_PASSWORD") or None,
        decode_responses=True,
    )


@dataclass(frozen=True)
class SigningIdentity:
    """Reconciler signer plus the verifier the CBF must resolve its ``kid`` with."""

    mode: str
    signer: Any
    verifier: Any
    #: True when the CBF's default verifier (``trust.get_reconciler_verifier``)
    #: already trusts ``signer``; False when it must be pointed at ``verifier``.
    native: bool

    @property
    def evidence_grade(self) -> bool:
        return self.mode == SIGNER_KMS


def resolve_signing_identity(*, allow_software: bool) -> tuple[SigningIdentity | None, str]:
    """Pick the reconciler signing identity; never falls back silently.

    Returns ``(identity, description)``; ``identity`` is ``None`` when no
    signer is available, and every signature-dependent section is skipped.
    """
    from src.gateway.governance.reconciliation import trust

    if os.environ.get(trust.RECONCILER_KMS_KEY_ENV, "").strip():
        signer = trust.get_reconciler_signer()
        return (
            SigningIdentity(SIGNER_KMS, signer, trust.get_reconciler_verifier(), native=True),
            f"{trust.RECONCILER_KMS_KEY_ENV} (KMS)",
        )
    if allow_software:
        from src.gateway.governance.env_posture import is_enforcing, resolve_posture
        from src.gateway.governance.kms_signer import (
            KMSGovernanceSigner,
            SoftwareEd25519Provider,
        )

        if is_enforcing(resolve_posture()):
            raise RuntimeError("--software-signer is development-only; the posture is enforcing")
        signer = KMSGovernanceSigner(provider=SoftwareEd25519Provider(key_id=SOFTWARE_KID))
        verifier = trust.build_reconciler_verifier({SOFTWARE_KID: signer.get_public_key_pem()})
        return (
            SigningIdentity(SIGNER_SOFTWARE, signer, verifier, native=False),
            "software Ed25519 (development only; not evidence)",
        )
    return None, f"{trust.RECONCILER_KMS_KEY_ENV} not set and --software-signer not given"


@contextlib.contextmanager
def _cbf_trusts(identity: SigningIdentity) -> Iterator[None]:
    """Make the CBF resolve ``identity``'s kid.

    In KMS mode the CBF already loads the reconciler's anchors from KMS. A
    software key has no out-of-band anchor, so the CBF's verifier lookup is
    pointed at the benchmark verifier for the duration of the block.
    """
    if identity.native:
        yield
        return
    from unittest import mock

    from src.gateway.governance.reconciliation import trust

    with mock.patch.object(trust, "get_reconciler_verifier", lambda: identity.verifier):
        yield


def _build_cbf() -> Any:
    import src.cage_finance as cage_finance
    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.constants import register_overlay_dir
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    # Mirror bootstrap_governor(): register the finance compliance overlay so
    # ControlRegistry resolves CTRL_MRM_004, which the CBF cites when it rejects
    # (the §6.5 violation pass). Without it the rejection raises KeyError.
    register_overlay_dir(Path(cage_finance.__file__).parent / "config" / "compliance")

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None
    return cbf


def _build_reconciler(sync_redis: Any, signer: Any, balance: float, floor: float) -> Any:
    """A reconciler over a fresh simulated custodian holding ``balance``."""
    from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
    from src.gateway.governance.reconciliation.daemon import GroundTruthReconciler
    from src.gateway.governance.seams.ground_truth import InMemoryLedgerJournal

    provider = SimulatedCashLedgerProvider(
        initial_scalar=balance,
        barrier_floor=floor,
        seed=7,
        journal=InMemoryLedgerJournal(),
        settlement_lag_s=0.0,
    )
    return GroundTruthReconciler(
        provider=provider,
        redis_client=sync_redis,
        account_id="cage-benchmark-account",
        signer=signer,
    )


def _clear_snapshot(sync_redis: Any, invariant_id: str) -> None:
    from src.gateway.governance.reconciliation import daemon

    sync_redis.delete(
        daemon.reconciled_state_key(invariant_id),
        daemon._REDIS_KEY_VERIFIED_BALANCE,
        daemon._REDIS_KEY_VERIFIED_AT,
        daemon._REDIS_KEY_PROVIDER,
        daemon._REDIS_KEY_SIGNATURE,
    )


def preflight_redis(sync_redis: Any, *, force: bool) -> str | None:
    """Return a refusal reason if the target Redis looks shared, else ``None``."""
    from src.cage_finance.invariants import CashBarrier
    from src.gateway.governance.reconciliation.daemon import FENCE_EPOCH_KEY

    sync_redis.ping()
    occupied = [k for k in (CashBarrier.state_key, FENCE_EPOCH_KEY) if sync_redis.exists(k)]
    if occupied and not force:
        return (
            f"Redis already holds {occupied}; this benchmark writes CBF state and "
            "advances the fence epoch. Use an ephemeral Redis or pass --force."
        )
    return None


# ---------------------------------------------------------------------------
# §6.3 — Reconciliation write path
# ---------------------------------------------------------------------------


def _span_exporter() -> Any:
    """Attach an in-memory exporter to the global SDK tracer provider."""
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = otel_trace.get_tracer_provider()
    if not isinstance(provider, TracerProvider):
        provider = TracerProvider()
        otel_trace.set_tracer_provider(provider)
        provider = otel_trace.get_tracer_provider()
    if not isinstance(provider, TracerProvider):
        raise RuntimeError("an OpenTelemetry tracer provider without span processors is installed")
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter


def measure_write_path(n: int, sync_redis: Any, identity: SigningIdentity | None) -> dict[str, Any]:
    """Run ``GroundTruthReconciler.reconcile()`` ``n`` times; read stage timings from its span."""
    if identity is None:
        return {"skipped": "no reconciler signing identity — a signed publish cannot be timed"}

    from src.cage_finance.invariants import CashBarrier

    exporter = _span_exporter()
    cbf_floor = _build_cbf().threshold_value
    sync_redis.set(CashBarrier.state_key, repr(READ_PATH_BALANCE))
    reconciler = _build_reconciler(sync_redis, identity.signer, READ_PATH_BALANCE, cbf_floor)

    stages: dict[str, list[float]] = {"fetch_ms": [], "kms_sign_ms": [], "redis_write_ms": []}
    total_ms: list[float] = []
    failures: list[str] = []
    for _ in range(n):
        exporter.clear()
        t0 = time.perf_counter()
        result = reconciler.reconcile(CashBarrier.invariant_id)
        wall_ms = (time.perf_counter() - t0) * 1000.0
        span = next(
            (s for s in exporter.get_finished_spans() if s.name == "reconciliation.cycle"), None
        )
        attrs = dict(span.attributes or {}) if span is not None else {}
        if not result.is_valid or not result.signature or not attrs.get("reconciliation.signed"):
            failures.append(result.error or "unsigned or missing reconciliation.cycle span")
            continue
        total_ms.append(wall_ms)
        for stage in stages:
            stages[stage].append(float(attrs.get(f"reconciliation.{stage}", 0.0)))

    _clear_snapshot(sync_redis, CashBarrier.invariant_id)
    return {
        "signer": identity.mode,
        "evidence_grade": identity.evidence_grade,
        "iterations_requested": n,
        "iterations_succeeded": len(total_ms),
        "failures": failures[:5],
        "total_ms": _percentiles(total_ms),
        **{stage: _percentiles(samples) for stage, samples in stages.items()},
    }


# ---------------------------------------------------------------------------
# §6.4 — CBF read overhead
# ---------------------------------------------------------------------------


async def _time_reads(cbf: Any, n: int) -> tuple[list[float], dict[str, Any]]:
    samples: list[float] = []
    state: dict[str, Any] = {}
    for _ in range(n):
        t0 = time.perf_counter()
        state = await cbf._read_cbf_state_atomic()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples, state


async def measure_cbf_read_overhead(
    n: int, sync_redis: Any, identity: SigningIdentity | None
) -> dict[str, Any]:
    """Time the CBF's real state read with and without a signed snapshot present."""
    from src.cage_finance.invariants import CashBarrier

    cbf = _build_cbf()
    sync_redis.set(CashBarrier.state_key, repr(READ_PATH_BALANCE))
    _clear_snapshot(sync_redis, CashBarrier.invariant_id)

    self_samples, state = await _time_reads(cbf, n)
    if state.get("source") != "self_reported":
        raise RuntimeError(f"expected the self-reported path, CBF read {state.get('source')!r}")
    out: dict[str, Any] = {"iterations": n, "self_reported_ms": _percentiles(self_samples)}

    if identity is None:
        out.update(
            reconciled_ms=None,
            delta_p50_ms=None,
            delta_p95_ms=None,
            note="no reconciler signing identity — reconciled path skipped",
        )
        return out

    reconciler = _build_reconciler(
        sync_redis, identity.signer, READ_PATH_BALANCE, cbf.threshold_value
    )
    published = reconciler.reconcile(CashBarrier.invariant_id)
    if not (published.is_valid and published.signature):
        raise RuntimeError(f"reconciler did not publish a signed snapshot: {published.error}")
    with _cbf_trusts(identity):
        recon_samples, state = await _time_reads(cbf, n)
    _clear_snapshot(sync_redis, CashBarrier.invariant_id)
    if state.get("source") != "reconciled":
        raise RuntimeError(f"expected the reconciled path, CBF read {state.get('source')!r}")

    self_p, recon_p = out["self_reported_ms"], _percentiles(recon_samples)
    out.update(
        signer=identity.mode,
        evidence_grade=identity.evidence_grade,
        reconciled_ms=recon_p,
        delta_p50_ms=round(recon_p["p50"] - self_p["p50"], 3),
        delta_p95_ms=round(recon_p["p95"] - self_p["p95"], 3),
    )
    return out


# ---------------------------------------------------------------------------
# §6.5 — Safety violation detection
# ---------------------------------------------------------------------------


async def measure_safety_violation_detection(
    sync_redis: Any, identity: SigningIdentity | None
) -> dict[str, Any]:
    """Run the three §6.5 scenarios against the real reconciler and CBF."""
    from src.cage_finance.invariants import CashBarrier

    inv = CashBarrier.invariant_id
    cbf = _build_cbf()
    floor = cbf.threshold_value
    trade = {"amount": TRADE_AMOUNT}
    out: dict[str, Any] = {
        "barrier_floor_usd": floor,
        "gamma": cbf.gamma,
        "inflated_self_reported_balance_usd": INFLATED_SELF_REPORTED,
        "true_custodian_balance_usd": TRUE_CUSTODIAN_BALANCE,
        "trade_amount_usd": TRADE_AMOUNT,
    }

    # (a) Inflated self-reported state, nothing reconciled.
    _clear_snapshot(sync_redis, inv)
    sync_redis.set(CashBarrier.state_key, repr(INFLATED_SELF_REPORTED))
    state = await cbf._read_cbf_state_atomic()
    verdict = await cbf.verify_action(ACTION, trade)
    out["a_self_reported"] = {
        "balance_source": state.get("source"),
        "verdict": verdict,
        "admitted": verdict == "SAFE",
    }

    # (b) The reconciler meets the inflated state: the discrepancy guard fires.
    from src.gateway.governance.reconciliation.daemon import FENCE_EPOCH_KEY

    epoch_before = int(sync_redis.get(FENCE_EPOCH_KEY) or 0)
    reconciler = _build_reconciler(
        sync_redis, identity.signer if identity else None, TRUE_CUSTODIAN_BALANCE, floor
    )
    refused = reconciler.reconcile(inv)
    out["b_reconciler_vs_inflated_state"] = {
        "published": refused.is_valid,
        "discrepancy_detected": refused.discrepancy_detected,
        "discrepancy_delta_usd": round(refused.discrepancy_delta, 2),
        "fence_epoch_before": epoch_before,
        "fence_epoch_after": int(sync_redis.get(FENCE_EPOCH_KEY) or 0),
        "error": refused.error,
    }

    # (c) Signed custodian snapshot, then the self-reported state is inflated.
    if identity is None:
        out["c_reconciled_after_inflation"] = {
            "skipped": "no reconciler signing identity — cannot publish a signed snapshot"
        }
    else:
        sync_redis.set(CashBarrier.state_key, repr(TRUE_CUSTODIAN_BALANCE))
        reconciler = _build_reconciler(sync_redis, identity.signer, TRUE_CUSTODIAN_BALANCE, floor)
        published = reconciler.reconcile(inv)
        sync_redis.set(CashBarrier.state_key, repr(INFLATED_SELF_REPORTED))
        with _cbf_trusts(identity):
            state = await cbf._read_cbf_state_atomic()
            verdict = await cbf.verify_action(ACTION, trade)
        _clear_snapshot(sync_redis, inv)
        out["c_reconciled_after_inflation"] = {
            "signer": identity.mode,
            "evidence_grade": identity.evidence_grade,
            "snapshot_published": published.is_valid and bool(published.signature),
            "balance_source": state.get("source"),
            "verdict": verdict,
            "refused": verdict != "SAFE",
        }

    c = out["c_reconciled_after_inflation"]
    out["poam_023_validated"] = bool(
        out["a_self_reported"]["admitted"]
        and out["b_reconciler_vs_inflated_state"]["discrepancy_detected"]
        and not c.get("skipped")
        and c.get("balance_source") == "reconciled"
        and c.get("refused")
    )
    return out


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _row(label: str, stats: dict[str, float] | None, width: int = 30) -> str:
    stats = stats or {}
    return (
        f"{label:<{width}} {stats.get('p50', 0):>8.3f} {stats.get('p95', 0):>8.3f} "
        f"{stats.get('p99', 0):>8.3f} {stats.get('mean', 0):>8.3f}"
    )


def _fmt_write_path_table(write_path: dict[str, Any]) -> str:
    title = "## Table 3: Reconciliation Write-Path Latency (ms)"
    if write_path.get("skipped"):
        return f"\n{title}\n\nSKIPPED — {write_path['skipped']}"
    lines = [
        "",
        title,
        f"(signer: {write_path['signer']}; evidence_grade: {write_path['evidence_grade']}; "
        f"{write_path['iterations_succeeded']}/{write_path['iterations_requested']} ticks succeeded)",
        "",
        f"{'Component':<30} {'P50':>8} {'P95':>8} {'P99':>8} {'Mean':>8}",
        f"{'-' * 30} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8}",
        _row("Custodian fetch (fetch_ms)", write_path.get("fetch_ms")),
        _row("Snapshot sign (kms_sign_ms)", write_path.get("kms_sign_ms")),
        _row("Redis publish (redis_write_ms)", write_path.get("redis_write_ms")),
        _row("reconcile() wall clock", write_path.get("total_ms")),
    ]
    return "\n".join(lines)


def _fmt_read_overhead_table(read_overhead: dict[str, Any]) -> str:
    lines = [
        "",
        "## Table 4: CBF Read-Path Overhead (ms)",
        f"({read_overhead.get('iterations', 0)} reads per path)",
        "",
        f"{'Path':<30} {'P50':>8} {'P95':>8} {'P99':>8} {'Mean':>8}",
        f"{'-' * 30} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8}",
        _row("Self-reported state", read_overhead.get("self_reported_ms")),
    ]
    if read_overhead.get("reconciled_ms"):
        lines.append(_row("Signed snapshot + verify", read_overhead["reconciled_ms"]))
        lines.append(
            f"\nDelta P50/P95: {read_overhead['delta_p50_ms']} / {read_overhead['delta_p95_ms']} ms "
            f"(signer: {read_overhead['signer']})"
        )
    else:
        lines.append(f"\n{read_overhead.get('note', 'reconciled path skipped')}")
    return "\n".join(lines)


def _fmt_safety_violation_section(safety: dict[str, Any]) -> str:
    a = safety["a_self_reported"]
    b = safety["b_reconciler_vs_inflated_state"]
    c = safety["c_reconciled_after_inflation"]
    lines = [
        "",
        "## Section 6.5: Safety Violation Detection",
        "",
        f"Barrier floor ${safety['barrier_floor_usd']:,.2f}, gamma {safety['gamma']}; "
        f"trade ${safety['trade_amount_usd']:,.2f}",
        "",
        f"(a) Self-reported ${safety['inflated_self_reported_balance_usd']:,.2f}, no snapshot "
        f"(source={a['balance_source']}): {a['verdict']}",
        f"(b) Reconciler vs inflated state: published={b['published']} "
        f"discrepancy_detected={b['discrepancy_detected']} "
        f"fence_epoch {b['fence_epoch_before']} -> {b['fence_epoch_after']}",
    ]
    if c.get("skipped"):
        lines.append(f"(c) SKIPPED — {c['skipped']}")
    else:
        lines.append(
            f"(c) Signed ${safety['true_custodian_balance_usd']:,.2f} snapshot, state inflated "
            f"afterwards (source={c['balance_source']}, signer={c['signer']}): {c['verdict']}"
        )
    lines += ["", f"POAM-023 threat model validated: {safety['poam_023_validated']}"]
    return "\n".join(lines)


def render_text(results: dict[str, Any]) -> str:
    return (
        "CAGE §6.3/6.4/6.5 Reconciliation Measurements\n"
        "===============================================\n"
        f"Generated: {results['generated_at']}\n"
        f"Signer: {results['signer']}\n"
        + _fmt_write_path_table(results["write_path"])
        + "\n"
        + _fmt_read_overhead_table(results["read_overhead"])
        + "\n"
        + _fmt_safety_violation_section(results["safety_violation"])
        + "\n"
    )


def _write_outputs(results: dict[str, Any]) -> None:
    json_path = Path(
        os.environ.get("RECONCILIATION_OUTPUT_JSON", "/tmp/cage_reconciliation_metrics.json")
    )
    txt_path = Path(
        os.environ.get("RECONCILIATION_OUTPUT_TXT", "/tmp/cage_reconciliation_metrics.txt")
    )
    json_path.write_text(json.dumps(results, indent=2, default=str))
    txt = render_text(results)
    txt_path.write_text(txt)
    print(f"[output] JSON written to {json_path}")
    print(f"[output] Text summary written to {txt_path}\n")
    print(txt)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def collect(
    sync_redis: Any,
    identity: SigningIdentity | None,
    *,
    write_runs: int = N_ITERATIONS,
    read_runs: int = N_ITERATIONS_FAST,
) -> dict[str, Any]:
    """Run all three sections against ``sync_redis`` and return the results dict."""
    print("\n[6.3] Reconciliation write path...")
    write_path = measure_write_path(write_runs, sync_redis, identity)
    print("[6.4] CBF read overhead...")
    read_overhead = await measure_cbf_read_overhead(read_runs, sync_redis, identity)
    print("[6.5] Safety violation detection...")
    safety = await measure_safety_violation_detection(sync_redis, identity)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "redis_target": _redis_target(),
        "signer": identity.mode if identity else "none",
        "evidence_grade": bool(identity and identity.evidence_grade),
        "write_path": write_path,
        "read_overhead": read_overhead,
        "safety_violation": safety,
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CAGE §6.3-6.5 reconciliation measurements.")
    parser.add_argument(
        "--software-signer",
        action="store_true",
        help="Sign snapshots with an in-process Ed25519 key when RECONCILER_KMS_KEY is "
        "unset (development posture only; results are not evidence).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run even if the target Redis already holds CBF state or a fence epoch.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    print("=" * 70)
    print("CAGE §6.3/6.4/6.5 Reconciliation Measurements")
    print("=" * 70)
    try:
        sync_redis = _make_sync_redis()
        refusal = preflight_redis(sync_redis, force=args.force)
    except Exception as exc:  # noqa: BLE001
        print(f"[FATAL] Redis unreachable at {_redis_target()}: {exc}")
        return 1
    if refusal:
        print(f"[FATAL] {refusal}")
        return 1

    identity, signer_desc = resolve_signing_identity(allow_software=args.software_signer)
    print(f"Redis  : {_redis_target()}")
    print(f"Signer : {signer_desc}")
    if identity is None:
        print("[WARN] Signature-dependent sections will be SKIPPED, not fabricated.")

    results = asyncio.run(collect(sync_redis, identity))
    _write_outputs(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
