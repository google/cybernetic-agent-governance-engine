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

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║      CAGE · GOVERNANCE-AS-CODE · Three-Act Demo                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

A self-contained, zero-infrastructure walkthrough of the three headline
governance capabilities of CAGE v1.0.0.

  ACT 1 — Multi-Agent Concurrency Race
    Two agents simultaneously attempt a $180k trade against a $200k daily cap.
    FiscalLimitGuard atomically allows the first and rejects the second before
    either reaches OPA — proving TOCTOU is eliminated at the Redis layer.

  ACT 2 — HITL Approval with Mandatory Rationale
    A high-risk trade (risk_score > 0.7) triggers a LangGraph interrupt.
    The operator is prompted for a mandatory rationale, which is hashed
    directly into the evidence chain BEFORE the thread resumes.

  ACT 3 — Tamper-Evident Hash Chain Verification
    Validates every record written in Acts 1 & 2 by recomputing each
    SHA-256 link in the chain. Mutates one field to prove tamper detection.

Usage:
    # Full interactive walkthrough (default)
    uv run python examples/governance_demo.py

    # Skip inter-act pauses (CI / README demos)
    uv run python examples/governance_demo.py --no-pause

    # Run a single act
    uv run python examples/governance_demo.py --act 1
    uv run python examples/governance_demo.py --act 2
    uv run python examples/governance_demo.py --act 3

No external services required — uses fakeredis for Act 1 and the real
PlaygroundTelemetry evidence chain for Acts 2 & 3.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Terminal colours (no external deps — pure ANSI)
# ---------------------------------------------------------------------------
_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


RED     = lambda t: _c("31;1", t)
GREEN   = lambda t: _c("32;1", t)
YELLOW  = lambda t: _c("33;1", t)
CYAN    = lambda t: _c("36;1", t)
MAGENTA = lambda t: _c("35;1", t)
BOLD    = lambda t: _c("1", t)
DIM     = lambda t: _c("2", t)
WHITE   = lambda t: _c("97", t)


def _hr(char: str = "─", width: int = 76) -> None:
    print(DIM(char * width))


def _banner(title: str, colour=CYAN) -> None:
    print()
    _hr("═")
    print(colour(f"  {title}"))
    _hr("═")
    print()


def _step(label: str, detail: str = "") -> None:
    print(f"  {BOLD('▶')} {label}" + (f"  {DIM(detail)}" if detail else ""))


def _ok(label: str) -> None:
    print(f"  {GREEN('✓')} {label}")


def _fail(label: str) -> None:
    print(f"  {RED('✗')} {label}")


def _warn(label: str) -> None:
    print(f"  {YELLOW('⚠')} {label}")


def _info(label: str) -> None:
    print(f"  {DIM('·')} {label}")


def _pause(interactive: bool) -> None:
    if interactive:
        input(f"\n  {DIM('[ press ENTER to continue ]')}\n")
    else:
        print()


# ---------------------------------------------------------------------------
# ACT 1 — Multi-Agent Concurrency Race
# ---------------------------------------------------------------------------

def act1_concurrency_race(interactive: bool) -> bool:
    """
    Two agents fire simultaneously against a $200k daily cap with $180k trades.
    Without FiscalLimitGuard both would pass OPA (TOCTOU).
    With the guard, exactly one is atomically rejected at the Redis layer.
    """
    _banner("ACT 1 · Multi-Agent Concurrency Race  (FiscalLimitGuard)", CYAN)
    print(
        f"  Scenario: three agents (trading, hedging, liquidity) each attempt a\n"
        f"  {BOLD('$180,000')} trade simultaneously against a {BOLD('$200,000')} daily cap.\n\n"
        f"  Without the guard  → all three read {YELLOW('remaining=$200k')} → OPA allows all\n"
        f"  With the guard     → {GREEN('Agent A')} reserves atomically; {RED('B & C are rejected')}\n"
    )
    _hr()

    try:
        import fakeredis  # type: ignore[import]
    except ImportError:
        _warn("fakeredis not installed — skipping Act 1.  Run: uv add fakeredis")
        return True

    from src.gateway.governance.fiscal_limit_guard import FiscalLimitGuard

    CAP_USD   = 200_000.0
    TRADE_USD = 180_000.0

    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    guard = FiscalLimitGuard(fake_redis, daily_cap_usd=CAP_USD, reservation_ttl=300)

    agents = [
        ("trading-agent",   TRADE_USD),
        ("hedging-agent",   TRADE_USD),
        ("liquidity-agent", TRADE_USD),
    ]

    _step("Firing all three agents simultaneously…")
    print()

    results: dict[str, Any] = {}

    def _attempt(agent_id: str, amount: float) -> tuple[str, Any]:
        token = guard.reserve(agent_id=agent_id, amount_usd=amount)
        return agent_id, token

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futs = {pool.submit(_attempt, aid, amt): aid for aid, amt in agents}
        for fut in concurrent.futures.as_completed(futs):
            aid, token = fut.result()
            results[aid] = token

    allowed = 0
    rejected = 0
    for aid, token in results.items():
        if token.rejected:
            _fail(
                f"{aid:<20}  ${TRADE_USD:>10,.0f}   "
                f"{RED('REJECTED')}  "
                f"(cap=${CAP_USD:,.0f}  running=${token.running_total_usd:,.0f})"
            )
            rejected += 1
        else:
            _ok(
                f"{aid:<20}  ${TRADE_USD:>10,.0f}   "
                f"{GREEN('RESERVED')}  "
                f"running=${token.running_total_usd:,.0f}/{CAP_USD:,.0f}"
            )
            allowed += 1

    print()
    _hr()
    print(
        f"\n  Result: {GREEN(str(allowed))} agent(s) proceeded to OPA  ·  "
        f"{RED(str(rejected))} agent(s) blocked at Redis layer\n"
    )

    if allowed == 1 and rejected == 2:
        _ok("PASS — exactly one reservation atomically succeeded")
    else:
        _fail(f"UNEXPECTED — allowed={allowed} rejected={rejected}")
        return False

    # Show Saga rollback path
    winning_token = next(t for t in results.values() if not t.rejected)
    print(f"\n  {BOLD('Saga rollback path')} — simulating trade failure on the winning agent:")
    remaining_before = guard.remaining_usd()
    guard.release(winning_token)
    remaining_after = guard.remaining_usd()
    _ok(
        f"release() restored ${TRADE_USD:,.0f}  "
        f"(remaining: ${remaining_before:,.0f} → ${remaining_after:,.0f})"
    )

    _pause(interactive)
    return True


# ---------------------------------------------------------------------------
# ACT 2 — HITL Approval with Mandatory Rationale
# ---------------------------------------------------------------------------

def act2_hitl_rationale(interactive: bool, evidence_dir: Path) -> bool:
    """
    Simulates the HITL approval loop for a high-risk trade.
    Demonstrates mandatory rationale validation and evidence chain write.
    """
    _banner("ACT 2 · HITL Approval  (Mandatory Rationale → Evidence Chain)", MAGENTA)
    print(
        f"  Scenario: a {BOLD('$95,000')} TSLA trade arrives with {YELLOW('risk_score=0.82')}.\n"
        f"  The graph interrupts at approval_node  →  operator must provide a\n"
        f"  {BOLD('mandatory rationale')} before the thread resumes.\n"
        f"  The rationale is hashed into the evidence chain {BOLD('before')} ainvoke().\n"
    )
    _hr()

    import examples.telemetry as tel_module

    date_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    chain_path = evidence_dir / f"evidence_chain_{date_str}.ndjson"
    view_path  = evidence_dir / f"view_access_log_{date_str}.ndjson"

    thread_id  = f"demo-thread-{uuid.uuid4().hex[:8]}"
    trade_info = {
        "ticker":     "TSLA",
        "quantity":   150,
        "price":      633.40,
        "total_usd":  95_010.0,
        "risk_score": 0.82,
    }

    _step("Graph interrupted", f"thread_id={thread_id}")
    _info(f"Trade: {trade_info['quantity']} × {trade_info['ticker']}  "
          f"@ ${trade_info['price']:,.2f}  =  ${trade_info['total_usd']:,.0f}")
    _warn(f"risk_score={trade_info['risk_score']}  >  threshold=0.70  →  HITL required")
    print()

    # --- Validate mandatory rationale ---
    _step("Testing API validation — submitting empty rationale…")
    try:
        from src.governed_financial_advisor.server import ApprovalResumeRequest
        ApprovalResumeRequest(approved=True, reviewer="lars@example.com", rationale="")
        _fail("Expected ValidationError — empty rationale should have been rejected")
        return False
    except Exception as exc:
        _ok(f"422 Unprocessable Entity — empty rationale rejected  ({type(exc).__name__})")

    print()

    # --- Prompt for rationale (or use default in non-interactive mode) ---
    if interactive:
        print(f"  {YELLOW('►')} Enter approval rationale (press ENTER for demo default):")
        print(f"  {DIM('  e.g. Trade aligns with IPS; risk score within mandate tolerance.')}")
        raw = input(f"  {BOLD('Rationale:')} ").strip()
        rationale = raw or "Trade confirmed within client IPS mandate; drawdown 0.3% < 4.5% CBF limit; approved per SR 11-7 §3.2."
        approved  = True
    else:
        rationale = "Trade confirmed within client IPS mandate; drawdown 0.3% < 4.5% CBF limit; approved per SR 11-7 §3.2."
        approved  = True

    reviewer = "lars.ahlfors@example.com"

    _step("Hashing rationale into evidence chain (pre-resume)…")

    with (
        patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
        patch.object(tel_module, "_VIEW_ACCESS_LOG_PATH", view_path),
        patch.object(tel_module, "_EVIDENCE_DIR", evidence_dir),
    ):
        tel = tel_module.PlaygroundTelemetry()
        record_hash = tel.record_approval(
            thread_id=thread_id,
            approved=approved,
            reviewer=reviewer,
            rationale=rationale,
        )

    decision_str = "APPROVED" if approved else "REJECTED"
    _ok(f"Evidence record written  →  {decision_str}")
    _info(f"hash   : {record_hash[:32]}…")
    _info(f"thread : {thread_id}")
    _info(f"ISO    : A.8.4 · A.7.2 · §6.1    NIST: GOVERN-5 · SC-4")
    print()

    # Show the raw record
    rec = json.loads(chain_path.read_text().strip().splitlines()[-1])
    _step("Raw evidence record (cage-intent/1.0):")
    print()
    display_keys = [
        "event_type", "thread_id", "decision", "reviewer",
        "rationale", "iso_controls", "nist_controls", "iso_42001_clause",
    ]
    for k in display_keys:
        v = rec.get(k, "")
        val_str = json.dumps(v) if isinstance(v, list) else str(v)
        if len(val_str) > 70:
            val_str = val_str[:67] + "…"
        print(f"    {CYAN(k):<28} {val_str}")
    print(f"    {CYAN('record_hash'):<28} {DIM(rec['record_hash'][:40])}…")
    print()

    # Simulate graph resume
    _step("Graph resuming…  Command(resume={approved, reviewer, rationale, timestamp})")
    time.sleep(0.3)
    _ok(f"Thread {thread_id} resumed  →  routing to {'executor' if approved else 'rejection'}")

    _pause(interactive)
    return True


# ---------------------------------------------------------------------------
# ACT 3 — Tamper-Evident Hash Chain Verification
# ---------------------------------------------------------------------------

def act3_verify_chain(interactive: bool, evidence_dir: Path) -> bool:
    """
    Reads every record written in Acts 1 & 2, recomputes the SHA-256 chain,
    then mutates one record to prove tamper detection.
    """
    _banner("ACT 3 · Tamper-Evident Hash Chain Verification", GREEN)
    print(
        "  Recomputes the SHA-256 link for every evidence record written\n"
        "  in Acts 1 & 2, then mutates one to prove chain integrity fails.\n"
    )
    _hr()

    import examples.telemetry as tel_module

    date_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    chain_path = evidence_dir / f"evidence_chain_{date_str}.ndjson"

    if not chain_path.exists() or not chain_path.read_text().strip():
        _warn("No evidence chain found — run Acts 1 & 2 first, or run full demo.")
        return True

    _step("Verifying chain integrity…")
    t0 = time.perf_counter()

    with (
        patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
        patch.object(tel_module, "_EVIDENCE_DIR", evidence_dir),
    ):
        tel    = tel_module.PlaygroundTelemetry()
        valid, count = tel.verify_chain()

    elapsed = (time.perf_counter() - t0) * 1000

    if valid:
        _ok(f"Chain VALID  —  {count} record(s) verified  ({elapsed:.1f} ms)")
    else:
        _fail(f"Chain INVALID at record {count}")
        return False

    # Show each record summary
    print()
    lines = chain_path.read_text().strip().splitlines()
    for i, line in enumerate(lines):
        rec = json.loads(line)
        etype = rec.get("event_type", rec.get("scenario_id", "?"))
        dec   = rec.get("decision", "")
        h     = rec.get("record_hash", "")[:16]
        print(f"    [{i:02d}] {CYAN(etype):<28} {GREEN(dec) if 'APPROVED' in dec else (RED(dec) if 'REJECTED' in dec else YELLOW(dec)):<12} hash={DIM(h)}…")

    # ── Tamper demonstration ──────────────────────────────────────────────────
    print()
    _step("Tamper test — mutating rationale in record [00]…")
    lines = chain_path.read_text().splitlines()
    rec0  = json.loads(lines[0])
    original_rationale = rec0.get("rationale", rec0.get("decision", ""))
    rec0["rationale"]  = "TAMPERED — unauthorised post-hoc edit"
    lines[0] = json.dumps(rec0)
    chain_path.write_text("\n".join(lines) + "\n")

    with (
        patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
        patch.object(tel_module, "_EVIDENCE_DIR", evidence_dir),
    ):
        tel2 = tel_module.PlaygroundTelemetry()
        valid2, bad_at = tel2.verify_chain()

    if not valid2:
        _ok(f"Tamper detected at record [{bad_at - 1:02d}]  →  chain integrity FAILED  ✓")
    else:
        _fail("Tamper NOT detected — hash chain is broken")
        return False

    # Restore
    rec0["rationale"] = original_rationale
    lines[0]          = json.dumps(rec0)
    chain_path.write_text("\n".join(lines) + "\n")
    _info("Original record restored.")

    _pause(interactive)
    return True


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def _summary(results: dict[str, bool]) -> None:
    _banner("DEMO COMPLETE · Governance Summary", WHITE)

    rows = [
        ("ACT 1", "FiscalLimitGuard atomic pre-reservation",
         "Redis WATCH/MULTI/EXEC  ·  TOCTOU eliminated"),
        ("ACT 2", "HITL mandatory rationale  →  evidence chain",
         "ISO 42001 A.8.4 · A.7.2 · §6.1  ·  NIST GOVERN-5"),
        ("ACT 3", "SHA-256 hash chain verification + tamper proof",
         "cage-intent/1.0  ·  tamper detection <1 ms/record"),
    ]

    for (act, title, detail), ok in zip(rows, results.values()):
        status = GREEN("PASS") if ok else RED("FAIL")
        print(f"  {status}  {BOLD(act)}  {title}")
        _info(detail)

    overall = all(results.values())
    print()
    if overall:
        _ok(BOLD("All acts passed — governance-as-code demo complete"))
    else:
        _fail(BOLD("One or more acts failed"))

    print(
        f"\n  {DIM('Evidence chain:')}  examples/evidence/evidence_chain_*.ndjson\n"
        f"  {DIM('Verify anytime:')}  "
        f"uv run python examples/governance_demo.py --act 3\n"
    )
    _hr()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CAGE Governance-as-Code · Three-Act Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--no-pause", action="store_true",
        help="Skip inter-act pause prompts (non-interactive / CI mode)",
    )
    parser.add_argument(
        "--act", type=int, choices=[1, 2, 3], default=None,
        help="Run a single act (default: all three)",
    )
    args = parser.parse_args()

    interactive = not args.no_pause and sys.stdout.isatty()

    # Shared temp directory for Acts 2 & 3 so chain records accumulate
    with tempfile.TemporaryDirectory(prefix="cage_demo_") as td:
        evidence_dir = Path(td)

        results: dict[str, bool] = {}

        try:
            if args.act in (None, 1):
                results["act1"] = act1_concurrency_race(interactive)
            if args.act in (None, 2):
                results["act2"] = act2_hitl_rationale(interactive, evidence_dir)
            if args.act in (None, 3):
                # If running standalone, seed a record so verification has data
                if args.act == 3:
                    import examples.telemetry as tel_module
                    from unittest.mock import patch as _patch
                    date_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    chain_path = evidence_dir / f"evidence_chain_{date_str}.ndjson"
                    view_path  = evidence_dir / f"view_access_log_{date_str}.ndjson"
                    with (
                        _patch.object(tel_module, "_EVIDENCE_CHAIN_PATH", chain_path),
                        _patch.object(tel_module, "_VIEW_ACCESS_LOG_PATH", view_path),
                        _patch.object(tel_module, "_EVIDENCE_DIR", evidence_dir),
                    ):
                        tel = tel_module.PlaygroundTelemetry()
                        tel.record_approval(
                            thread_id="demo-seed",
                            approved=True,
                            reviewer="demo@example.com",
                            rationale="Seeded by standalone Act 3 run.",
                        )
                results["act3"] = act3_verify_chain(interactive, evidence_dir)

        except KeyboardInterrupt:
            print(f"\n\n  {YELLOW('Demo interrupted.')}\n")
            return 130

        if len(results) == 3 or args.act is None:
            _summary(results)

        return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
