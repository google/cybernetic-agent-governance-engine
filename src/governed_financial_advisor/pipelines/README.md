# Cybernetic Governance Loop — KFP v2 Pipeline

> **Canonical name:** Cybernetic Governance Loop (also referred to as "Green-Stack Pipeline" in historical documentation)

This directory contains the **Kubeflow Pipelines v2** pipeline definition that implements CAGE's self-correcting governance feedback loop — the system that gives the **Cybernetic** Governance Engine its name.

> **⚠️ Human-Gated Refinement (since v2.0.0):** The autonomous NeMo hot-reload loop has been severed. The pipeline no longer calls `POST /v1/nemo/apply-refinement` directly. Instead, it calls `POST /v1/nemo/propose-refinement`, which stages the refinement as a proposal requiring explicit human approval (reviewer identity + rationale) before any config change is applied. This eliminates the recursive self-authentication path where a model could engineer its own privilege escalation. Set `NEMO_AUTO_APPLY_ENABLED=true` to bypass human gating in dev/CI environments only.

## Pipeline: `governance_pipeline`

**File:** [`green_stack_pipeline.py`](green_stack_pipeline.py)
**KFP pipeline name:** `green-stack-governance-loop`

### Architecture

```
Langfuse score event (score-created)
        │
        ▼
POST /v1/webhooks/langfuse   ← governed-financial-advisor (FastAPI)
        │
        ├─ Anti-flapping guards (R-LOOP-6 cooldown / R-LOOP-7 sample-size)
        │
        ▼
_submit_kfp_run()            ← Kubeflow Pipelines SDK (kfp.Client)
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│  KFP Pipeline: green-stack-governance-loop                │
│                                                           │
│  Step 1: fetch_compliance_metrics                         │
│          GET {compliance_bridge_url}/v1/metrics/{ctrl_id} │
│                                                           │
│  Step 2: evaluate_governance_metrics                      │
│          safety_rate >= threshold? → PASS (stop)          │
│          safety_rate <  threshold? → FAIL (continue)      │
│                                                           │
│  Step 3: trigger_nemo_refinement                          │
│          POST {backend_url}/v1/nemo/propose-refinement    │
│          → Stages refinement proposal for human approval  │
│          → Auto-applies only if NEMO_AUTO_APPLY_ENABLED   │
└───────────────────────────────────────────────────────────┘
```

The full loop is: **Langfuse score → webhook → KFP pipeline → evaluate → propose refinement → human approval → apply**. A human reviewer must explicitly approve all NeMo config changes before they take effect. The `NEMO_AUTO_APPLY_ENABLED=true` flag bypasses this gate for dev/CI environments only.

### Components

| Stage | KFP Component | Action |
| ----- | ------------- | ------ |
| 1 | `fetch_compliance_metrics` | Fetches windowed safety scores from the Compliance Bridge for a specific ISO 42001 control |
| 2 | `evaluate_governance_metrics` | Compares `safety_rate` to `safety_threshold` (default: 0.95); returns `PASS` or `FAIL` |
| 3 | `trigger_nemo_refinement` | On FAIL, calls `POST /v1/nemo/propose-refinement` to stage a refinement proposal for human approval; auto-applies only when `NEMO_AUTO_APPLY_ENABLED=true` |

### Trigger Mechanisms

The pipeline can be triggered in two ways:

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| **Reactive (webhook)** | `POST /v1/webhooks/langfuse` | Langfuse fires a `score-created` event when `iso_42001_safety_rate` drops below 0.95. Anti-flapping guards (5-min cooldown + 10-sample minimum) prevent policy flapping. |
| **Manual** | `POST /v1/refinement/trigger` | Accepts `pipeline_id`, `trigger_reason`, and optional `trace_ids`. Degrades gracefully to `dry_run` when `KFP_ENDPOINT` is not set. |

Both call the shared `_submit_kfp_run()` function in `server.py`.

### Environment Variables

| Var | Default | Purpose |
| --- | ------- | ------- |
| `KFP_ENDPOINT` | (empty) | Kubeflow Pipelines API server; if unset, degrades to `dry_run` |
| `COMPLIANCE_BRIDGE_URL` | `http://compliance-bridge/` | Compliance Bridge service URL for metrics fetch |
| `BACKEND_URL` | `http://governed-financial-advisor/` | Backend URL for NeMo refinement proposal endpoint |
| `NEMO_SAFETY_THRESHOLD` | `0.95` | ISO 42001 safety rate below which the loop fires |
| `LANGFUSE_WATCH_SCORE_NAME` | `iso_42001_safety_rate` | Langfuse score name to watch |
| `REFINEMENT_COOLDOWN_SECONDS` | `300` | Anti-flapping cooldown (5 min) |
| `REFINEMENT_MIN_SAMPLES` | `10` | Minimum sample size before triggering |
| `NEMO_AUTO_APPLY_ENABLED` | `false` | Set `true` to bypass human-gated refinement approval (dev/CI only) |

### Running Locally

To compile the pipeline spec (requires `kfp` package):

```bash
pip install kfp
python -c "
from kfp import compiler
from src.governed_financial_advisor.pipelines.green_stack_pipeline import governance_pipeline
compiler.Compiler().compile(governance_pipeline, 'governance_pipeline.json')
"
```

This produces a `governance_pipeline.json` (KFP v2 IR spec) that can be uploaded to any Kubeflow Pipelines instance.

### Documentation

For full architectural documentation of the cybernetic loop including the anti-flapping design, see:
- [`docs/technical-report/02-ARCHITECTURE.md` §10](../../../docs/technical-report/02-ARCHITECTURE.md) — Langfuse Webhook Cybernetic Loop
