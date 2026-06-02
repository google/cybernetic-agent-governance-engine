#!/usr/bin/env python3
# Copyright 2026 Google LLC
# Licensed under the Apache License, Version 2.0
#
# CAGE v2.0.x — execute_trade Load Test
# Fires N governed trade executions through the MCP tool server (/tools/execute)
# to populate OPA, CBF, and Consensus spans in Langfuse.
#
# Run: python scratch/trade_load_test.py

import json, time, statistics
from datetime import datetime, timezone
import requests

BACKEND = "http://localhost:8081"  # governed-financial-advisor :8081
TOOL_URL = f"{BACKEND}/tools/execute"

TRADES = [
    # (symbol, amount, action, confidence, drawdown_pct)
    ("AAPL", 5000.0,  "execute_trade", 0.95, 2.1),
    ("MSFT", 8500.0,  "execute_trade", 0.91, 3.4),
    ("NVDA", 12000.0, "execute_trade", 0.88, 5.2),
    ("BRK.B", 3500.0, "execute_trade", 0.97, 1.8),
    ("SPY",  7500.0,  "execute_trade", 0.93, 2.9),
    ("QQQ",  6200.0,  "execute_trade", 0.90, 4.1),
    ("AMZN", 9800.0,  "execute_trade", 0.86, 6.0),
    ("GOOGL", 4100.0, "execute_trade", 0.94, 2.3),
    ("VTI",  5500.0,  "execute_trade", 0.96, 1.5),
    ("GLD",  2200.0,  "execute_trade", 0.99, 0.8),
]

SEP = "─" * 72

def send_trade(symbol, amount, action, confidence, drawdown_pct, idx, total):
    payload = {
        "tool_name": action,
        "params": {
            "symbol":             symbol,
            "amount":             amount,
            "action":             action,
            "currency":           "USD",
            "confidence":         confidence,
            "drawdown_pct":       drawdown_pct,
            "portfolio_fraction": round(amount / 100000.0, 4),
        }
    }
    t0 = time.perf_counter()
    try:
        r = requests.post(TOOL_URL, json=payload, timeout=30)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        status = r.status_code
        try:
            body = r.json()
            decision = body.get("decision") or body.get("status") or body.get("result", "?")
            if isinstance(decision, dict):
                decision = decision.get("status", str(decision))[:30]
        except Exception:
            decision = r.text[:40] if r.text else "empty"
        print(f"  [{idx:>2}/{total}] {symbol:<6} ${amount:>8,.0f}  "
              f"conf={confidence:.2f}  HTTP {status}  "
              f"{elapsed_ms:>7.0f}ms  → {str(decision)[:30]}")
        return elapsed_ms, status
    except requests.exceptions.Timeout:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"  [{idx:>2}/{total}] {symbol:<6} ${amount:>8,.0f}  TIMEOUT ({elapsed_ms:.0f}ms)")
        return elapsed_ms, 0
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"  [{idx:>2}/{total}] {symbol:<6} ${amount:>8,.0f}  ERROR: {exc}")
        return elapsed_ms, -1


print("\n" + "="*72)
print("  CAGE v2.0.x — execute_trade LOAD TEST")
print(f"  Target: {TOOL_URL}")
print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
print("="*72)
print(f"\nFiring {len(TRADES)} governed trade executions...\n")
print(SEP)

latencies = []
statuses  = []

for i, (symbol, amount, action, confidence, drawdown_pct) in enumerate(TRADES, 1):
    ms, status = send_trade(symbol, amount, action, confidence, drawdown_pct, i, len(TRADES))
    latencies.append(ms)
    statuses.append(status)
    time.sleep(0.5)  # 500ms between trades — avoid hammering CBF atomics

print(SEP)
print(f"\n  Completed {len(TRADES)} requests.\n")

if latencies:
    s = sorted(latencies)
    p50 = s[len(s)//2]
    p95 = s[int(len(s)*0.95)-1]
    print(f"  Latency  avg={statistics.mean(latencies):.0f}ms  "
          f"p50={p50:.0f}ms  p95={p95:.0f}ms  "
          f"[{min(latencies):.0f}–{max(latencies):.0f}ms]")

ok  = sum(1 for s in statuses if s == 200)
gov = sum(1 for s in statuses if s in (403, 422))
err = sum(1 for s in statuses if s not in (200, 403, 422))
print(f"  Results  200-OK={ok}  Governed-block={gov}  Error={err}")
print(f"\n  ✓ Done — traces landing in Langfuse (sampling={100*0.01:.0f}%)")
print("  Wait ~10s then run: python scratch/profile_latency_baseline.py\n")
print("="*72 + "\n")
