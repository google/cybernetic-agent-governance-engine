#!/usr/bin/env python3
# Copyright 2026 Google LLC
# Licensed under the Apache License, Version 2.0
#
# CAGE v2.0.x — Latency Baseline Profiler  (fixed for Langfuse v3 API)
# Run: python scratch/profile_latency_baseline.py

import os, sys, json, statistics
from datetime import datetime, timezone
from collections import defaultdict
import requests
from requests.auth import HTTPBasicAuth

PK   = os.getenv("LANGFUSE_PUBLIC_KEY",  "REDACTED_LANGFUSE_PK")
SK   = os.getenv("LANGFUSE_SECRET_KEY",  "REDACTED_LANGFUSE_SK")
HOST = os.getenv("LANGFUSE_HOST",        "http://localhost:3001")
auth = HTTPBasicAuth(PK, SK)

def iso(s):
    if not s: return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def ms(start, end):
    if not start or not end: return None
    return (end - start).total_seconds() * 1000

def pct(lst, p):
    if not lst: return None
    s = sorted(lst)
    idx = max(0, int(len(s) * p / 100) - 1)
    return s[idx]

def fetch(path, params=None):
    r = requests.get(f"{HOST}/api/public/{path}", auth=auth,
                     params=params or {}, timeout=15)
    r.raise_for_status()
    return r.json()

def print_stats(label, data, unit="ms", indent=2):
    pad = " " * indent
    if not data:
        print(f"{pad}{label:45s}  (no data)")
        return
    n   = len(data)
    avg = statistics.mean(data)
    med = statistics.median(data)
    p95 = pct(data, 95)
    p99 = pct(data, 99)
    mn, mx = min(data), max(data)
    print(f"{pad}{label:45s}  n={n:>4}  "
          f"avg={avg:>8.1f}{unit}  p50={med:>8.1f}{unit}  "
          f"p95={p95:>8.1f}{unit}  p99={p99:>8.1f}{unit}  "
          f"[{mn:.0f}–{mx:.0f}]")

SEP = "─" * 80

# ── Fetch data ─────────────────────────────────────────────────────────────────
print("\n" + "="*80)
print("  CAGE v2.0.x — LATENCY POST-OPTIMIZATION PROFILER")
print(f"  {HOST}  |  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
print("="*80)

print("\n[1/3] Fetching traces …")
traces = []
page = 1
while True:
    resp = fetch("traces", {"limit": 50, "page": page, "orderBy": "timestamp.desc"})
    batch = resp.get("data", [])
    traces.extend(batch)
    meta = resp.get("meta", {})
    if len(traces) >= meta.get("totalItems", 0) or not batch or page >= 4:
        break
    page += 1
print(f"      {len(traces)} traces retrieved.")

print("[2/3] Fetching observations …")
obs_all = []
page = 1
while True:
    resp = fetch("observations", {"limit": 50, "page": page})
    batch = resp.get("data", [])
    obs_all.extend(batch)
    meta = resp.get("meta", {})
    if len(obs_all) >= min(meta.get("totalItems", 0), 500) or not batch or page >= 10:
        break
    page += 1
gens  = [o for o in obs_all if o.get("type") == "GENERATION"]
spans = [o for o in obs_all if o.get("type") == "SPAN"]
events= [o for o in obs_all if o.get("type") == "EVENT"]
print(f"      {len(obs_all)} observations: {len(gens)} GENERATIONs, {len(spans)} SPANs, {len(events)} EVENTs")

print("[3/3] Computing statistics …\n")

# ── Trace E2E latency ──────────────────────────────────────────────────────────
e2e_all = []
e2e_by_name = defaultdict(list)
e2e_by_svc  = defaultdict(list)

for t in traces:
    lat_s = t.get("latency")
    if lat_s is None:
        continue
    v = float(lat_s) * 1000
    if v <= 0:
        continue
    name = t.get("name") or "unnamed"
    svc  = (t.get("metadata") or {}).get("resourceAttributes", {}).get("service.name", "unknown")
    e2e_all.append(v)
    e2e_by_name[name].append(v)
    e2e_by_svc[svc].append(v)

# ── Generation stats ───────────────────────────────────────────────────────────
gen_total   = []
gen_ttft    = []
gen_by_op   = defaultdict(list)
gen_by_svc  = defaultdict(list)

for g in gens:
    lat_s = g.get("latency")
    if lat_s is not None and float(lat_s) > 0:
        v = float(lat_s) * 1000
        gen_total.append(v)
        op  = (g.get("metadata") or {}).get("attributes", {}).get("gen_ai.operation.name", "unknown")
        svc = (g.get("metadata") or {}).get("resourceAttributes", {}).get("service.name", "unknown")
        gen_by_op[op].append(v)
        gen_by_svc[svc].append(v)
    ttft_s = g.get("timeToFirstToken")
    if ttft_s is not None and float(ttft_s) > 0:
        gen_ttft.append(float(ttft_s) * 1000)
    else:
        v2 = ms(iso(g.get("startTime")), iso(g.get("completionStartTime")))
        if v2 and v2 > 0:
            gen_ttft.append(v2)

# ── Span stats ─────────────────────────────────────────────────────────────────
span_by_name = defaultdict(list)
span_by_svc  = defaultdict(list)

for s in spans:
    lat_s = s.get("latency")
    if lat_s is not None and float(lat_s) > 0:
        v = float(lat_s) * 1000
    else:
        v = ms(iso(s.get("startTime")), iso(s.get("endTime")))
        if not v or v <= 0:
            continue
    name = s.get("name") or "unnamed"
    svc  = (s.get("metadata") or {}).get("resourceAttributes", {}).get("service.name", "unknown")
    span_by_name[name].append(v)
    span_by_svc[svc].append(v)

# ── CAGE pipeline stage mapping ────────────────────────────────────────────────
# Span names are matched by substring (case-insensitive).
# Updated 2026-05-30: Added cage.tool_execute, cage.validate_action,
# cage.cbf_action_check, cage.opa_action_check, cage.routing_seal from
# Option 2: Unified Gateway Governance Routing implementation.
STAGE_MAP = {
    # cage.tool_execute — GFA root span, wraps validate-action + actuation
    "Tool Governance":  ["cage.tool_execute"],

    # Tier 4: OPA Rego policy evaluation via the unified gateway path
    # Note: 'governance' omitted — matches symbolic_governor.govern meta-spans
    # Note: 'policy' omitted — ambiguous with NeMo policy rails
    # cage.* names are checked first; bare 'opa' only matches non-prefixed spans
    "OPA / Policy":     ["cage.opa_action_check", "cage.validate_action",
                         "cage.opa_pre_check", "cage.opa",
                         "opa", "rego", "trade_gov", "trade-gov",
                         "evaluate_policy"],

    # Tier 2: CBF mathematical safety bounds
    # Note: 'safety' omitted — matches 'verify_content_safety' (NeMo span)
    "CBF / Safety":     ["cage.cbf_action_check", "cage.cbf_check",
                         "cage.cbf", "cbf", "barrier"],

    "Presidio (PII)":   ["presidio", "pii", "anonymi", "detect_pii"],

    # NeMo: guardrail spans including verify_content_safety tool path
    "NeMo Guardrails":  ["nemo", "guardrail", "nemo_guardrail",
                         "nemo_output_rail", "verify_content_safety",
                         "cage.nemo"],

    "LLM Inference":    ["inference", "vllm", "llm", "generation", "chat",
                         "completions", "thinker", "thinker_node",
                         "doer", "doer_node", "DataAnalyst", "reasoning",
                         "final_response", "ChatOpenAI"],

    "HITL":             ["hitl", "human_review", "post_hitl",
                         "hitl_approval", "manual_review"],

    "Redis / Cache":    ["redis", "cache", "eviction"],

    # Routing Seal: HMAC token issuance + LangGraph routing nodes
    "Routing / Seal":   ["cage.routing_seal", "routing_seal",
                         "route_after_guardrail", "route_supervisor",
                         "symbolic_governor.govern",
                         "governance_evaluation", "governance_simulation"],

    "Compliance":       ["compliance", "bridge", "oscal", "audit", "iso"],

    "MCP Tool":         ["mcp_tool", "mcp-tool", "execute_trade_action"],

    "Consensus":        ["cage.consensus_gate", "cage.consensus",
                         "consensus.check", "consensus", "multi_agent"],

    "Confidence Check": ["cage.confidence_check", "cage.confidence",
                         "confidence_check"],

    "STPA/UCA":         ["cage.stpa_check", "stpa_check", "stpa", "uca"],
}


stage_gen  = defaultdict(list)
stage_span = defaultdict(list)
uncat_span = defaultdict(list)

for name, vals in span_by_name.items():
    placed = False
    nm = name.lower()
    for stage, kws in STAGE_MAP.items():
        if any(kw in nm for kw in kws):
            stage_span[stage].extend(vals)
            placed = True
            break
    if not placed:
        uncat_span[name].extend(vals)

for name, vals in gen_by_op.items():
    nm = name.lower()
    for stage, kws in STAGE_MAP.items():
        if any(kw in nm for kw in kws):
            stage_gen[stage].extend(vals)
            break

# ══ PRINT REPORT ══════════════════════════════════════════════════════════════
print(SEP)
print("  1. END-TO-END TRACE LATENCY")
print(SEP)
print_stats("All traces", e2e_all, indent=4)
if e2e_by_svc:
    print(f"\n    By service:")
    for svc, vals in sorted(e2e_by_svc.items(), key=lambda x: -statistics.mean(x[1]) if x[1] else 0):
        print_stats(svc[:45], vals, indent=8)
if len(e2e_by_name) > 1:
    print(f"\n    By trace name (top 10 by avg):")
    ranked = sorted(e2e_by_name.items(), key=lambda x: -statistics.mean(x[1]) if x[1] else 0)
    for name, vals in ranked[:10]:
        print_stats(name[:45], vals, indent=8)

print()
print(SEP)
print("  2. GENERATION (vLLM) LATENCY")
print(SEP)
print_stats("Total generation latency", gen_total, indent=4)
print_stats("Time-to-First-Token (TTFT)", gen_ttft, indent=4)
if gen_by_op:
    print(f"\n    By operation type:")
    for op, vals in sorted(gen_by_op.items()):
        print_stats(op[:45], vals, indent=8)
if gen_by_svc:
    print(f"\n    By service:")
    for svc, vals in sorted(gen_by_svc.items()):
        print_stats(svc[:45], vals, indent=8)

print()
print(SEP)
print(f"  3. PIPELINE STAGE BREAKDOWN  (CAGE 10-layer policy stack + Unified Governance Routing)")
print(SEP)
for stage in [
    "Tool Governance",   # cage.tool_execute — GFA root, Option 2 unified path
    "OPA / Policy",      # cage.opa_action_check + cage.validate_action (Tier 4)
    "CBF / Safety",      # cage.cbf_action_check (Tier 2)
    "Presidio (PII)",
    "NeMo Guardrails",
    "LLM Inference",
    "HITL",
    "Redis / Cache",
    "Routing / Seal",    # cage.routing_seal
    "Compliance",
    "MCP Tool",
    "Consensus",
    "Confidence Check",
    "STPA/UCA",
]:
    combined = stage_span.get(stage, []) + stage_gen.get(stage, [])
    print_stats(stage, combined, indent=4)

if uncat_span:
    print(f"\n    Uncategorised spans:")
    for name, vals in sorted(uncat_span.items(), key=lambda x: -statistics.mean(x[1]))[:12]:
        print_stats(name[:45], vals, indent=8)

print()
print(SEP)
print("  4. SLOWEST INDIVIDUAL OBSERVATIONS  (top 20)")
print(SEP)
top_obs = sorted(
    [(float(o.get("latency") or 0) * 1000, o.get("type","?"), o.get("name","?"),
      (o.get("metadata") or {}).get("resourceAttributes", {}).get("service.name","?"),
      o.get("traceId","?"))
     for o in obs_all if o.get("latency") and float(o["latency"]) > 0],
    reverse=True
)[:20]
for lat, typ, name, svc, tid in top_obs:
    print(f"    {lat:>9.1f}ms  [{typ[:4]}]  {name[:40]:<40}  svc:{svc[:25]:<25}  tr:{tid[:10]}")

# ── JSON summary ───────────────────────────────────────────────────────────────
def safe_mean(lst): return round(statistics.mean(lst), 2) if lst else None
def safe_pct(lst, p): v = pct(lst, p); return round(v, 2) if v else None

summary = {
    "captured_at":   datetime.now(timezone.utc).isoformat(),
    "cage_version":  "v2.0.x",
    "run_type":      "post_optimization",
    "optimizations": [
        "asyncio.gather CBF+OPA parallel",
        "per-stage OTel spans (cage.*)",
        "OPA Redis decision cache (10s TTL)",
        "TTFT capture in streaming path",
    ],
    "slm_available": False,
    "trace_count":   len(traces),
    "observation_count": len(obs_all),
    "e2e_latency_ms": {
        "n":   len(e2e_all),
        "avg": safe_mean(e2e_all),
        "p50": safe_pct(e2e_all, 50),
        "p95": safe_pct(e2e_all, 95),
        "p99": safe_pct(e2e_all, 99),
        "min": round(min(e2e_all), 2) if e2e_all else None,
        "max": round(max(e2e_all), 2) if e2e_all else None,
    },
    "generation_latency_ms": {
        "n":   len(gen_total),
        "avg": safe_mean(gen_total),
        "p50": safe_pct(gen_total, 50),
        "p95": safe_pct(gen_total, 95),
        "p99": safe_pct(gen_total, 99),
    },
    "ttft_ms": {
        "n":   len(gen_ttft),
        "avg": safe_mean(gen_ttft),
        "p50": safe_pct(gen_ttft, 50),
        "p95": safe_pct(gen_ttft, 95),
    },
    "pipeline_stage_ms": {
        stage: {
            "n":   len(stage_span.get(stage, []) + stage_gen.get(stage, [])),
            "avg": safe_mean(stage_span.get(stage, []) + stage_gen.get(stage, [])),
            "p95": safe_pct(stage_span.get(stage, []) + stage_gen.get(stage, []), 95),
        }
        for stage in STAGE_MAP
    },
    "by_service_avg_ms": {svc: safe_mean(vals) for svc, vals in e2e_by_svc.items()},
}

out_path = "scratch/latency_post_opt_v2.0.x.json"
with open(out_path, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n  ✓ JSON summary written → {out_path}")
print(SEP + "\n")
