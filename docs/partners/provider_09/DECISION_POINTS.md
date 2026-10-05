# OpsCanvas (`provider_09`) — CAGE Decision Points

**Slot:** `provider_09` · **Seam:** `EstateProvider` ([`seams/estate.py`](../../../src/gateway/governance/seams/estate.py))
**Response contract:** [`estate_decision_response.schema.json`](../../../schemas/provider_09/estate_decision_response.schema.json)
**Worked example:** [`DP-01.example.json`](../../../tests/fixtures/provider_09/DP-01.example.json)
**Plan:** [`provider_09_opscanvas_integration_plan.md`](../../../plans/provider_09_opscanvas_integration_plan.md)
**Status:** Round 1, open for partner responses (published 2026-10-04)

---

## 1. Purpose

Each decision point below is a concrete action an autonomous CloudOps agent
proposes. For each one, CAGE has to decide whether to **ALLOW** it, **DEFER**
it (park it for more context or human approval) or **DENY** it. The scenarios
list the estate facts CAGE needs to make that call. The goal of this round is
to find out:

1. Which seam fields the OpsCanvas graph populates **natively**, which it can
   **derive**, and which it can't supply today.
2. Whether the seam is missing something the graph knows and governance
   needs. If so, propose it under `gaps`.

## 2. What exists today (honest baseline)

| Component | State at HEAD |
|---|---|
| `EstateProvider` protocol + result dataclasses | ✅ [`seams/estate.py`](../../../src/gateway/governance/seams/estate.py) |
| Provider factory (`CAGE_ESTATE_PROVIDER=opscanvas` → `provider_09`) | ✅ [`estate_provider.py`](../../../src/gateway/governance/estate_provider.py). Resolves to a fail-closed `UNAVAILABLE` provider until the adapter is installed. |
| `provider_09` adapter package | ❌ Not yet built. It will live at `src/integrations/provider_09/` and export `Provider09EstateProvider` with a `from_env()` constructor. |
| Kernel consumers (FTRA, `DeferQueue` hydration, OPA `cloudops_admission`) | ❌ Not wired yet. The "Expected CAGE verdict" column below is the **target** policy from the plan, §4. It is not current runtime behaviour. |

## 3. Fail-closed rules (apply to every decision point)

- Only `status: "OK"` with `error: null` can ground a decision. `UNAVAILABLE`,
  `STALE` and `INVALID` always fail closed.
- A **refusal counts as evidence**. A DENY or DEFER caused by missing or stale
  estate data enters the tamper-evident evidence chain the same way an ALLOW
  does.
- `snapshot_hash` is bound into CAGE's signed decision record. A content hash
  proves *which* snapshot was used, but not *who* produced it (see open
  question Q4).

## 4. Decision points

Resource URNs below are illustrative. Answer with your own URN scheme and
explain it in `notes` (see Q1).

| ID | Proposed agent action | Seam queries | Key predicates | Expected CAGE verdict (target) |
|---|---|---|---|---|
| **DP-01** | `delete` a read replica of the production orders database | `get_resource_predicate`, `query_blast_radius` | `environment_tier=PRODUCTION`, `criticality_tier=TIER_0`, `is_load_bearing`, `has_failover_redundancy=false` | **DEFER → HITL** (`approval_tier=VP_ENG`). FTRA treats load-bearing with no failover as `IRREVERSIBLE_TERMINAL`. |
| **DP-02** | `restart` a stateless TIER_2 reporting service | `get_resource_predicate` | `has_failover_redundancy=true`, `estimated_blast_radius_score < 0.25`, `iac_drift_status=SYNCHRONIZED` | **ALLOW**. `snapshot_id` and `snapshot_hash` are sealed into the decision. |
| **DP-03** | `scale_down` a production service whose live config differs from Terraform | `get_resource_predicate` → `get_topology_snapshot` | `iac_drift_status=DRIFT_DETECTED`, `last_iac_commit_hash` | **DEFER** (`INSUFFICIENT_CONTEXT`). The action is parked, more context is fetched from the snapshot, then OPA re-evaluates. It is never admitted against a drifted baseline without review. |
| **DP-04** | `modify` a resource created by hand in the console with no IaC | `get_resource_predicate` | `managed_by_terraform=false`, `iac_drift_status=UNMANAGED`, `owner_team_urn` | **DEFER → HITL**, routed to the owning team. |
| **DP-05** | Any mutation answered from an expired snapshot | any | `status=STALE`, `captured_at_utc` + `ttl_seconds` | **DENY / DEFER** (fail closed). The refusal is recorded. |
| **DP-06** | Any mutation while OpsCanvas is unreachable or times out | any | `status=UNAVAILABLE` | **DENY** (fail closed). The refusal is recorded. Never fail open. |
| **DP-07** | `delete` an ephemeral sandbox environment | `get_resource_predicate` | `environment_tier=SANDBOX`, `reversibility_tier` | **ALLOW** if synchronized and not load-bearing. |
| **DP-08** | Change an IAM binding / network policy on a shared service with many transitive dependents | `query_blast_radius`, `get_topology_snapshot` | `transitive_dependency_depth`, `direct_dependents_count`, `estimated_affected_services`, `approval_tier` | **DEFER → HITL** at the returned `approval_tier`. CAGE never down-grades the approval tier the estate recommends. |
| **DP-09** | Any mutation on a URN that is **not in the graph** | `get_resource_predicate` | — | **DENY** (fail closed). See Q2: the seam has no `NOT_FOUND` status yet. |

## 5. How to respond

1. For each decision point you can answer, add
   `tests/fixtures/provider_09/DP-XX.json` that conforms to the
   [response schema](../../../schemas/provider_09/estate_decision_response.schema.json).
   Use real (sanitised) graph output where you can.
2. Set `fit` to `NATIVE`, `DERIVED`, `PARTIAL` or `NOT_AVAILABLE`. List any
   field you can't populate, or any field you'd add, in `gaps`.
3. Validate locally:
   ```bash
   uv run pytest tests/test_provider_09_decision_schema.py -v
   ```
   The schema rejects unknown fields on purpose. Propose new fields in `gaps`
   rather than adding them, so the seam is changed deliberately.
4. Open a PR from a fork, using a branch named `test/provider-09-dp-round1`.

These fixtures are **design artefacts**. They are not conformance evidence.
Adapter conformance (M5 in the plan) must run over the wire against a live
OpsCanvas sandbox, per the over-the-wire testing rule in `AGENTS.md`.

## 6. Open questions for OpsCanvas

| # | Question | Why it matters |
|---|---|---|
| Q1 | What is your canonical resource URN scheme, and does it stay stable when resources are renamed or re-parented? | Decisions and evidence are keyed on `resource_urn`. |
| Q2 | How should "resource not in graph" be signalled? Should the seam add `NOT_FOUND`, or reuse `INVALID`? | DP-09. It decides whether unknown resources are distinguishable from malformed answers. |
| Q3 | What freshness guarantee does a snapshot carry (`ttl_seconds`), and how is "confirmed" defined per edge? | DP-05. It sets the `STALE` threshold. |
| Q4 | Is `snapshot_hash` computed over a canonical serialisation (e.g. RFC 8785 JCS)? Can snapshots be **signed** with a key resolvable by `kid` from a manifest CAGE fetches independently? | CAGE never verifies against a key embedded in the signed document. Without a signature, the hash only proves *which* snapshot was used. |
| Q5 | Transport: MCP over stdio, SSE or streamable HTTP? What P99 latency should we expect for a predicate query? | The plan budgets under 30 ms for the synchronous FTRA path. Slower answers move to `DeferQueue` hydration. |
| Q6 | Can we get a sandbox estate for over-the-wire conformance tests? | Required before any adapter test counts as evidence. |
| Q7 | How is `estimated_blast_radius_score` composed? | CAGE thresholds on it (`< 0.25`). It must be explainable in a HITL review. |
