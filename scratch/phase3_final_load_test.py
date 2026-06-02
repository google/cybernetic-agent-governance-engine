#!/usr/bin/env python3
"""Phase 3 final load test — all fixes applied.

Fixes in this build:
  1. ?explain=full removed from OPA hot path  (15,000ms → ~30ms)
  2. validate_action(timeout=60s)             (covers 20s OPA JIT cold-start)
  3. GOVERNANCE_SEAL_TTL_S=120               (seal survives cold start)
  4. redis_client.connect() in lifespan      (eliminates ConnectionError)

OPA is already warm on the gateway pod (warmed at 17:15:42).
Expected: p50 ~50ms, p95 ~200ms, 100/100 success.
"""
import asyncio, httpx, time, random, statistics, uuid, sys

BASE = "http://localhost:18080"
N, CONC = 100, 5
SYMS = ["AAPL", "MSFT", "GOOGL", "AMZN", "TSLA", "NVDA", "META", "NFLX"]


async def trade(client: httpx.AsyncClient, i: int) -> dict:
    sym = SYMS[i % len(SYMS)]
    p = {
        "symbol": sym,
        "amount": round(random.uniform(1000, 25000), 2),
        "currency": "USD",
        "confidence": round(random.uniform(0.65, 0.98), 3),
        "side": "BUY" if i % 2 == 0 else "SELL",
        "risk_profile": "moderate",
        "trader_role": "junior",
        "transaction_id": str(uuid.uuid4()),
    }
    t0 = time.perf_counter()
    try:
        r = await client.post(
            f"{BASE}/tools/execute",
            json={"tool_name": "execute_trade", "params": p},
            timeout=90.0,
        )
        ms = (time.perf_counter() - t0) * 1000
        b = r.json() if r.status_code < 500 else {}
        ok = r.status_code < 400 and b.get("status") == "SUCCESS"
        return {
            "i": i, "sym": sym, "ms": ms, "code": r.status_code,
            "ok": ok, "out": str(b.get("output", b.get("error", "?")))[:60],
        }
    except Exception as e:
        return {
            "i": i, "sym": sym, "ms": (time.perf_counter() - t0) * 1000,
            "code": 0, "ok": False, "out": f"{type(e).__name__}: {e}",
        }


async def main():
    sem = asyncio.Semaphore(CONC)

    async def bounded(i):
        async with sem:
            return await trade(client, i)

    print(f"🚀 Phase 3 Final Load Test — {N} trades  concurrency={CONC}")
    print(f"   Target: {BASE}")
    print(f"   Fixes: ?explain=full removed | timeout=60s | TTL=120s | Redis connected")
    t0 = time.time()

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[bounded(i) for i in range(N)])

    elapsed = time.time() - t0
    lats = [r["ms"] for r in results]
    ok = [r for r in results if r["ok"]]
    fail = [r for r in results if not r["ok"]]
    s = sorted(lats)

    print(f"\n{'=' * 64}")
    print(f"  PHASE 3 RESULTS — Unified Gateway Governance Routing")
    print(f"  Single Choke Point: GFA → Gateway → OPA → Seal → Execute")
    print(f"{'=' * 64}")
    print(f"  Wall time  : {elapsed:.1f}s   Throughput: {N / elapsed:.1f} req/s")
    print(f"  Success    : {len(ok)}/{N}   Failed: {len(fail)}/{N}")
    print(f"\n  End-to-end latency (all {N} requests):")
    print(f"    p50 : {statistics.median(lats):.0f}ms")
    print(f"    p75 : {s[74]:.0f}ms")
    print(f"    p95 : {s[94]:.0f}ms")
    print(f"    p99 : {s[98]:.0f}ms")
    print(f"    mean: {statistics.mean(lats):.0f}ms")
    print(f"    min : {min(lats):.0f}ms")
    print(f"    max : {max(lats):.0f}ms")
    print(f"    std : {statistics.stdev(lats):.0f}ms")

    if fail:
        print(f"\n  ❌ Failures (first 5):")
        for r in fail[:5]:
            print(f"    [{r['i']:3d}] {r['sym']} HTTP{r['code']}  {r['out'][:55]}")

    print(f"\n  ✅ Sample results (first 8):")
    for r in results[:8]:
        m = "✅" if r["ok"] else "❌"
        print(f"  {m} [{r['i']:3d}] {r['sym']:5s}  {r['ms']:7.0f}ms  {r['out'][:40]}")

    print(f"\n  📊 TRACE_SAMPLING_RATE=1.0 → {len(ok)} cage.* traces emitted to Langfuse")
    print(f"  🔍 Verify in Langfuse: cage.tool_execute → cage.validate_action → cage.cbf_action_check + cage.opa_action_check")

    if len(ok) == N:
        print(f"\n  🎯 Phase 3 COMPLETE: 100/100 trades succeeded.")
        print(f"     Phase 4: Open Langfuse and verify unified cage.* trace tree.")
        sys.exit(0)
    else:
        print(f"\n  ⚠️  {len(fail)} failures — check logs above.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
