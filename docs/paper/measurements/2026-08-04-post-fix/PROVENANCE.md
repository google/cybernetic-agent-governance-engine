# Measurement Provenance — 2026-08-04 Post-Fix Run

## Summary

Post-deployment measurement run following 5 security PRs merged to `main`
(commits `5e4913a`–`61ee539`). Images rebuilt via Cloud Build and deployed to
GKE `governance-stack` namespace before measurement.

## Deployment

| Component | Build ID | SHA | Status |
|---|---|---|---|
| gateway | `50b3a21f` | `61ee539` | SUCCESS |
| governed-financial-advisor | `d20059ac` | `61ee539` | SUCCESS |

Pods restarted at ~21:46 UTC:
- `gateway-778c6547c8-qkdqx`
- `governed-financial-advisor-6665d96bd4-dg65p`

## Execution

Script run inside advisor pod via `kubectl exec`:

```
BACKEND_URL=http://127.0.0.1:8080 \
UNMOCKED=1 \
ADVERSARIAL_JSON=/tmp/adversarial_dataset.json \
BENIGN_JSON=/tmp/benign_dataset.json \
python /tmp/measure_paper_metrics.py
```

Generated: `2026-08-04T22:59:32Z`

## Results — Table 5: Adversarial Deflection

| Category | Total | Evaluated | Deflected | Errors | Rate % | 95% CI |
|---|---|---|---|---|---|---|
| rbac_escalation | 4 | 3 | 0 | 1 | 0.0% | [0.0–56.2%] |
| prompt_injection | 6 | 5 | 2 | 1 | 40.0% | [11.8–76.9%] |
| pii_injection | 5 | 5 | 5 | 0 | 100.0% | [56.6–100.0%] |
| harmful_financial | 3 | 2 | 2 | 1 | 100.0% | [34.2–100.0%] |
| confidence_spoofing | 1 | 1 | 1 | 0 | 100.0% | [20.7–100.0%] |
| compound_attack | 3 | 1 | 0 | 2 | 0.0% | [0.0–79.3%] |
| **TOTAL** | **22** | **17** | **10** | **5** | **58.8%** | **[36.0–78.4%]** |

## Results — Benign FPR

| Category | Total | Evaluated | FP | TN | FPR % | 95% CI |
|---|---|---|---|---|---|---|
| market_data | 5 | 5 | 0 | 5 | 0.0% | [0.0–43.4%] |
| portfolio_management | 5 | 5 | 0 | 5 | 0.0% | [0.0–43.4%] |
| stock_query | 6 | 6 | 0 | 6 | 0.0% | [0.0–39.0%] |
| trade_execution | 4 | 4 | 1 | 3 | 25.0% | [4.6–69.9%] |
| **TOTAL** | **20** | **16** | **1** | **15** | **6.2%** | **[1.1–28.3%]** |

Network errors (excluded from denominator): 4

## Before vs. After Comparison

| Category | Before (6edb597) | After (61ee539) | Δ |
|---|---|---|---|
| rbac_escalation | 0% (0/3) | 0% (0/3) | — |
| prompt_injection | 40% (2/5) | 40% (2/5) | — |
| pii_injection | 100% | 100% (5/5) | — |
| harmful_financial | 100% | 100% (2/2) | — |
| confidence_spoofing | — | 100% (1/1) | new category |
| compound_attack | — | 0% (0/1) | new category |
| **TOTAL** | **57.1% [32.6–78.6%]** | **58.8% [36.0–78.4%]** | **+1.7 pp** |
| **Benign FPR** | **0%** | **6.2% (1/16)** | **+6.2 pp** |

## Notes

- 5 network errors on adversarial set, 4 on benign set — excluded from
  denominator per methodology (not governance deflections).
- The single benign FP was in `trade_execution` — a legitimate trade request
  incorrectly blocked. The OIDC / confidence fix in `61ee539` may have
  tightened confidence thresholds.
- Deflection rate is within CI overlap with baseline — statistically stable.
- `rbac_escalation` and `prompt_injection` categories unchanged, indicating
  these require further targeted hardening.
