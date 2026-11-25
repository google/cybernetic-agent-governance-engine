# LangGraph Integration Guide

Status of integrating LangGraph applications with the CAGE governance gateway via [`packages/cage-client/`](../../packages/cage-client/).

## Current Surface (`cage-client` `0.5.0`)

- **Preview (`POST /governance/validate-action` via `CageClient.validate_action()`):** Evaluates policy and safety tiers in dry-run preview mode and returns a JWKS-verified `GovernanceEnvelope`. **Preview is preview-only:** it reserves no budget, mints no routing seal, and attests to no side effect. Do not wrap a side-effecting function behind a preview `ALLOW` check.
- **Committing execution (`POST /tools/execute` and MCP `/mcp/`):** Committing runs execute on the gateway (`enforce_governance()` / `enforce_approved_governance()` -> single-use routing seal verification -> `ExecutionLedger` idempotency claim/settlement -> `ActuatorRegistry` dispatch) and return a structured `CommitOutcome` (`src/gateway/governance/commit_outcome.py`).
- **LangGraph SDK adapter status (`POAM-2026-251`):** The earlier `@cage_guard` node decorator (`a71d6a6b:packages/cage-client/src/cage_client/adapters/langgraph.py`) was removed in `cage-client` `0.5.0` because it gated arbitrary node bodies behind preview-only `validate_action()`, raised exceptions across `DEFER` before LangGraph could checkpoint `deferred_id`, and silently fabricated `"unknown"` principals / `{}` parameters when state keys were absent. A replacement LangGraph node factory (`governed_node` / `approval_park_node` with explicit `Command` routing over `preview` and `execute`) is tracked under [`POAM-2026-251`](../POAM.md).

## Worked End-to-End Reference

Until the rebuilt SDK node factory lands (`POAM-2026-251`), read the reference LangGraph application in [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/):

- **Verified gateway preview client:** [`gateway_client.py`](../../src/governed_financial_advisor/infrastructure/gateway_client.py) (uses `CageClient` from the built `cage-client` wheel to verify signed preview envelopes).
- **Committing tool guard, idempotency keys & HITL redemption:** [`tool_guard.py`](../../src/governed_financial_advisor/graph/governance/tool_guard.py) (derives deterministic plan-step idempotency keys, strips model-supplied `deferred_id` handles, dispatches committing tool calls to the gateway, and handles `EXECUTED`, `REFUSED`, retryable vs. terminal `ApprovalRedemptionRefusal`, `UNAVAILABLE`, and `INDETERMINATE` outcomes).
- **Two-node HITL checkpointing & post-approval TOCTOU revalidation:** [`governed_trader_graph.py`](../../src/governed_financial_advisor/graph/subgraphs/governed_trader_graph.py) (`approval_node` parks via `interrupt()` only after `deferred_id` is durably checkpointed, followed by `post_hitl_rehydrate` -> `post_hitl_revalidate` before redeeming the ticket on the gateway).

## Related References

- **Client SDK package & verification contract:** [`packages/cage-client/README.md`](../../packages/cage-client/README.md)
- **In-monorepo kernel node factories (domain plugins only):** [`src/gateway/governance/langgraph_harness/`](../../src/gateway/governance/langgraph_harness/)
- **HITL TOCTOU architecture:** [`docs/security/HITL_TOCTOU_REMEDIATION.md`](../security/HITL_TOCTOU_REMEDIATION.md)
- **Local development postures:** [`docs/guides/LOCAL_DEVELOPMENT_POSTURES.md`](LOCAL_DEVELOPMENT_POSTURES.md)
