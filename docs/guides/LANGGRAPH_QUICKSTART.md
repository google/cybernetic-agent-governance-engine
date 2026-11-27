# LangGraph Integration Guide

Status of integrating LangGraph applications with the CAGE governance gateway via [`packages/cage-client/`](../../packages/cage-client/).

## Current Surface (`cage-client` `0.5.0`)

- **Preview (`POST /governance/validate-action` via `CageClient.validate_action()` / `CageClient.preview()`):** Evaluates policy and safety tiers in dry-run preview mode and returns a JWKS-verified `GovernanceEnvelope` (or, via `preview()`, a non-raising `PreviewResult` over the five `GovernanceDecision` outcomes: `ALLOWED`, `NARROWED`, `DENIED`, `DEFERRED`, `UNAVAILABLE`). **Preview is preview-only:** it reserves no budget, mints no routing seal, and attests to no side effect. Do not wrap a side-effecting function behind a preview `ALLOW` check.
- **Committing execution (`POST /tools/execute` via `CageClient.execute_tool()` and MCP `/mcp/`):** Committing runs execute on the gateway (`enforce_governance()` / `enforce_approved_governance()` -> single-use routing seal verification -> `ExecutionLedger` idempotency claim/settlement -> `ActuatorRegistry` dispatch) and return a structured `CommitOutcome` (`src/gateway/governance/commit_outcome.py`, parsed client-side by `cage_client.outcomes.CommitOutcome`). `CageClient.execute_tool()` enforces out-of-band `kid` JWKS/PEM signature and binding verification (`tool_name`, `idempotency_key`, `request_hash`) on every `200`, `202`, and `403` response via `enforce_verification_posture()`, rejecting opt-outs in enforcing postures and emitting a `WARNING` log when permitted under `dev`/`test`. Deterministic plan-step keys can be derived with `derive_plan_step_key()` / `derive_idempotency_key()`.
- **LangGraph SDK node factories (`cage_client.langgraph`, `langgraph>=1.0.0`, `langchain-core>=1.0.0`):** The earlier `@cage_guard` node decorator (`a71d6a6b:packages/cage-client/src/cage_client/adapters/langgraph.py`) was removed in `cage-client` `0.5.0` because it gated arbitrary node bodies behind preview-only `validate_action()`, raised exceptions across `DEFER` before LangGraph could checkpoint `deferred_id`, and silently fabricated `"unknown"` principals / `{}` parameters when state keys were absent. Three composable replacement factories live in [`packages/cage-client/src/cage_client/langgraph.py`](../../packages/cage-client/src/cage_client/langgraph.py):
  - `governed_node` — single-action preview or committing mediation over `CageClient.preview()` / `CageClient.execute_tool()` with explicit `principal_extractor` and `action_extractor` and `Command(goto=...)` routing.
  - `approval_park_node` — checkpoints `deferred_id` before invoking `interrupt()`, validates reviewer resume payloads, and routes approved/rejected resumes.
  - `governed_tool_node` — `1..N` batch `AIMessage.tool_calls` mediation with deterministic `derive_plan_step_key()` idempotency keys, stripping of model-supplied `deferred_id` / `approval_token` fields, retryable vs. terminal `ApprovalRedemptionRefusal` handling, and guaranteed `ToolMessage(tool_call_id=...)` pairing on every exit.

## Worked Reference Application (`POAM-2026-251` Advisor Migration Pending)

Migration of [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/) onto `cage_client.langgraph` remains tracked under [`POAM-2026-251`](../POAM.md). Until that pass completes, the worked reference modules in [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/) remain:

- **Verified gateway client:** [`gateway_client.py`](../../src/governed_financial_advisor/infrastructure/gateway_client.py) (uses `CageClient` from the built `cage-client` wheel).
- **Committing tool guard, idempotency keys & HITL redemption:** [`tool_guard.py`](../../src/governed_financial_advisor/graph/governance/tool_guard.py) (derives deterministic plan-step idempotency keys, strips model-supplied `deferred_id` handles, dispatches committing tool calls to the gateway, and handles `EXECUTED`, `REFUSED`, retryable vs. terminal `ApprovalRedemptionRefusal`, `UNAVAILABLE`, and `INDETERMINATE` outcomes).
- **Two-node HITL checkpointing & post-approval TOCTOU revalidation:** [`governed_trader_graph.py`](../../src/governed_financial_advisor/graph/subgraphs/governed_trader_graph.py) (`approval_node` parks via `interrupt()` only after `deferred_id` is durably checkpointed, followed by `post_hitl_rehydrate` -> `post_hitl_revalidate` before redeeming the ticket on the gateway).

## Related References

- **Client SDK package & verification contract:** [`packages/cage-client/README.md`](../../packages/cage-client/README.md)
- **In-monorepo kernel node factories (domain plugins only):** [`src/gateway/governance/langgraph_harness/`](../../src/gateway/governance/langgraph_harness/)
- **HITL TOCTOU architecture:** [`docs/security/HITL_TOCTOU_REMEDIATION.md`](../security/HITL_TOCTOU_REMEDIATION.md)
- **Local development postures:** [`docs/guides/LOCAL_DEVELOPMENT_POSTURES.md`](LOCAL_DEVELOPMENT_POSTURES.md)
