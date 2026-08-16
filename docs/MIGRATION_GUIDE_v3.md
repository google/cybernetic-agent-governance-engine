# CAGE v3.0.0 Migration Guide

> **Status:** Released — v3.0.0 shipped 2026-08-15. This guide helps you
> migrate from v2.x to v3.0.0. Companion to
> [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md) and
> [`docs/MAJOR_VERSION_CLEANUP_PLAN.md`](MAJOR_VERSION_CLEANUP_PLAN.md). Item
> IDs (`SR-#`, `MR-#`, `CR-#`, `FF-#`, `EV-#`) match those documents 1:1.

## Prerequisites

Before upgrading from `v2.x` to `v3.0.0`:

1. **Upgrade to the latest `v2.1.x` patch release first.** Every removed
   symbol in this guide already emits a `DeprecationWarning` in `v2.1.2`+
   (per [`pyproject.toml:3`](../pyproject.toml:3)). Run your test suite with
   `-W error::DeprecationWarning` against `src.gateway.governance` and
   `src.governed_financial_advisor` to surface every call site that needs
   migration **before** you touch `v3.0.0`.
2. **Grep your own integration code** for the removed symbols listed in
   [`BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md#api-changes) — do not
   rely solely on `DeprecationWarning` output, since warnings filtered or
   suppressed in your logging configuration will not surface.
3. **Inventory your environment variable overrides.** If your deployment
   (Helm values, Terraform `tfvars`, `.env` files, CI secrets) sets any of
   the variables listed in
   [`BREAKING_CHANGES_v3.md` § Removed Environment Variables](BREAKING_CHANGES_v3.md#removed-environment-variables),
   plan the equivalent `config/thresholds/*.json` entries **before**
   upgrading — these overrides silently stop taking effect post-upgrade.
4. **If you operate a live evidence chain** (compliance-critical, CR-1),
   confirm with your Compliance/OSCAL owner that the v1.0 → v1.1 evidence
   schema data migration has been executed and verified for your deployment.
   Do not upgrade to a `v3.0.0` build that has removed v1.0 verification
   support until this migration is confirmed complete.
5. **Back up your current configuration** (`config/thresholds/`,
   `config/compliance/`, `.env`) and note your current `pyproject.toml`
   version (`2.1.2` or later) so you have a known-good rollback point (see
   [Rollback Procedure](#rollback-procedure)).
6. **Read [`BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md) in full** —
   this guide assumes familiarity with its tables and does not repeat the
   rationale for each change.

## Step-by-Step Migration

### Step 1: Update Import Statements

#### SR-1 — `stpa_validator.py` → `generated_stpa_validator.py`

```python
# BEFORE (v2.x)
from src.gateway.governance.stpa_validator import STPAValidator

validator = STPAValidator()
violations = validator.validate(action_name, params)
```

```python
# AFTER (v3.0.0)
from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator

validator = GeneratedSTPAValidator()
violations = validator.validate_generated(action_name, params)
```

#### SR-2 — `safety.py` → `text_filter.py` / `cbf.py`

```python
# BEFORE (v2.x)
from src.gateway.governance.safety import (
    ac_keyword_scan,
    ControlBarrierFunction,
    safety_filter,
)
```

```python
# AFTER (v3.0.0)
from src.gateway.governance.text_filter import ac_keyword_scan
from src.gateway.governance.cbf import ControlBarrierFunction, safety_filter
```

#### SR-5 — `HybridClient` → `GatewayClient`

```python
# BEFORE (v2.x)
from src.governed_financial_advisor.infrastructure.llm_client import HybridClient

client = HybridClient(...)
```

```python
# AFTER (v3.0.0)
from src.gateway.core.llm import GatewayClient

client = GatewayClient(...)
```

#### SR-3 — `GovernanceClient` → `StructuredLLMClient`

```python
# BEFORE (v2.x)
from src.governed_financial_advisor.infrastructure.governance_client import (
    GovernanceClient,
)

client: GovernanceClient = GovernanceClient()
```

```python
# AFTER (v3.0.0)
from src.governed_financial_advisor.infrastructure.governance_client import (
    StructuredLLMClient,
)

client: StructuredLLMClient = StructuredLLMClient()
```

#### SR-4 — `RedisClient` → `AsyncRedisClient`

```python
# BEFORE (v2.x)
from src.governed_financial_advisor.infrastructure.redis_client import RedisClient

cache = RedisClient()
```

```python
# AFTER (v3.0.0)
from src.governed_financial_advisor.infrastructure.redis_client import (
    AsyncRedisClient,
)

cache = AsyncRedisClient()
```

> **Note:** do not confuse this with the unrelated
> `src.gateway.infrastructure.redis_client` module (`_AsyncRedisClient`/
> `_SyncRedisClient`) — that module is untouched by this migration.

#### MR-1/MR-2/MR-3 — Region-aware accessor migration

```python
# BEFORE (v2.x)
from src.compliance_bridge.types import (
    CONTROL_META,
    EVIDENCE_SLA_SECONDS,
    ISO_CONTROL_MAP,
)

for control_id, meta in CONTROL_META.items():
    ...

sla_seconds = EVIDENCE_SLA_SECONDS.get("SC-4")
control_id = ISO_CONTROL_MAP.get("nemo_input_scan")
```

```python
# AFTER (v3.0.0)
import os

from src.compliance_bridge.types import (
    get_control_meta,
    get_iso_control_map,
    get_sla_seconds,
)

region = os.environ.get("CAGE_DEPLOYMENT_REGION", "universal")

for control_id, meta in get_control_meta(region).items():
    ...

sla_seconds = get_sla_seconds(region).get("SC-4")
control_id = get_iso_control_map(region).get("nemo_input_scan")
```

For the **separate** `ontology.py` symbol:

```python
# BEFORE (v2.x)
from src.gateway.governance.ontology import TradingKnowledgeGraph

control_id = TradingKnowledgeGraph.ISO_CONTROL_MAP.get("nemo_input_scan")
```

```python
# AFTER (v3.0.0)
from src.gateway.governance.ontology import TradingKnowledgeGraph

control_id = TradingKnowledgeGraph.get_control_map(region).get("nemo_input_scan")
```

### Step 2: Update Configuration

#### EV-1 — `FRIA_ZONE_ALLOW`/`FRIA_ZONE_DEFER` → `config/thresholds/`

```bash
# BEFORE (v2.x) — set via environment
export FRIA_ZONE_ALLOW=0.95
export FRIA_ZONE_DEFER=0.70
```

```json
// AFTER (v3.0.0) — config/thresholds/US_FED_BASELINE.json (or your active region file)
{
  "fria_zone_allow": 0.95,
  "fria_zone_defer": 0.70
}
```

Remove the `FRIA_ZONE_ALLOW`/`FRIA_ZONE_DEFER` exports from your `.env`,
Helm values, or Terraform `tfvars` — they have no effect once
`symbolic_governor.py` and `graph_analyzer.py` are migrated to read from the
config file.

#### EV-2 — `AGENT_CONFIDENCE_THRESHOLD` → `config/thresholds/`

```bash
# BEFORE (v2.x)
export AGENT_CONFIDENCE_THRESHOLD=0.80
```

```json
// AFTER (v3.0.0) — config/thresholds/<REGION>_BASELINE.json
{
  "agent_confidence_threshold": 0.80
}
```

#### EV-3/EV-6 — Causal Lock & telemetry thresholds → `config/thresholds/`

```bash
# BEFORE (v2.x)
export CAUSAL_LOCK_P_VALUE_THRESHOLD=0.05
export CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE=0.1
export CAUSAL_LOCK_RISK_BOUNDARY=0.2
export CAUSAL_MIN_SAMPLES=30
export CAUSAL_CACHE_TTL_SECONDS=3600
export TELEMETRY_MAX_STALENESS_SECONDS=300
```

```json
// AFTER (v3.0.0) — config/thresholds/<REGION>_BASELINE.json
{
  "causal_lock_p_value_threshold": 0.05,
  "causal_lock_placebo_effect_magnitude": 0.1,
  "causal_lock_risk_boundary": 0.2,
  "causal_min_samples": 30,
  "causal_cache_ttl_seconds": 3600,
  "telemetry_max_staleness_seconds": 300
}
```

> Coordinate this migration with your MRM/ISO 42001 §A.9.4 compliance owner
> — these are governed thresholds per
> [`docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md`](governance/CAUSAL_AND_CBF_GOVERNANCE.md).

#### EV-4 — `NEMO_AUTO_APPLY_ENABLED` (delete, do not migrate)

```bash
# BEFORE (v2.x) — dev/test only
export NEMO_AUTO_APPLY_ENABLED=true
```

```bash
# AFTER (v3.0.0) — remove this variable entirely.
# Use the propose/approve flow instead (see Step 3 below).
```

#### EV-5 — `KMS_BATCH_MAX_SIZE`/`KMS_BATCH_ENABLED` → `config/thresholds/`

```bash
# BEFORE (v2.x)
export KMS_BATCH_MAX_SIZE=32
export KMS_BATCH_ENABLED=true
```

```json
// AFTER (v3.0.0) — config/thresholds/<REGION>_BASELINE.json
// CAUTION: confirm the resolved production default with your release notes
// before relying on this value — see BREAKING_CHANGES_v3.md's Feature Flags
// Graduated section for the known kms_batch_signer.py vs. main.py discrepancy.
{
  "kms_batch_max_size": 32,
  "kms_batch_enabled": true
}
```

### Step 3: Update API Calls

#### SR-6 — `check_safety_constraints` → `simulate_governance_check`

```python
# BEFORE (v2.x)
result = await evaluator_agent.check_safety_constraints(
    action_name="place_trade",
    params={"symbol": "AAPL", "quantity": 100},
)
```

```python
# AFTER (v3.0.0)
result = await evaluator_agent.simulate_governance_check(
    action_name="place_trade",
    params={"symbol": "AAPL", "quantity": 100},
)
```

If you call this via the MCP tool registry directly:

```python
# BEFORE (v2.x)
response = await mcp_client.call_tool(
    "check_safety_constraints",
    {"action_name": "place_trade", "params": {...}},
)
```

```python
# AFTER (v3.0.0)
response = await mcp_client.call_tool(
    "simulate_governance_check",
    {"action_name": "place_trade", "params": {...}},
)
```

#### SR-7 — `create_ftra_node()` deprecated params → `FtraNodeConfig`

```python
# BEFORE (v2.x)
from src.gateway.governance.ftra.node_factory import create_ftra_node

ftra_node_fn = create_ftra_node(
    registry_path="config/ftra/terminal_registry.json",
    plan_key="execution_plan_output",
)
```

```python
# AFTER (v3.0.0)
from src.gateway.governance.ftra.node_factory import create_ftra_node
from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

ftra_node_fn = create_ftra_node(
    config=FtraNodeConfig(
        registry_path="config/ftra/terminal_registry.json",
        plan_key="execution_plan_output",
    )
)
```

If you were relying on the default (no params at all), no change is
required:

```python
# UNCHANGED in v3.0.0
ftra_node_fn = create_ftra_node()
```

#### MR-5 / CR-2 — NeMo legacy auto-apply → propose/approve flow

```python
# BEFORE (v2.x) — dev/test env with NEMO_AUTO_APPLY_ENABLED=true
response = await http_client.post(
    "/v1/nemo/apply-refinement",
    json={
        "control_id": "A.9.2",
        "verdict": "FAIL",
        "source": "langfuse_webhook",
    },
)
# Refinement is applied immediately, no human review.
```

```python
# AFTER (v3.0.0) — human-gated propose/approve flow (works in all environments)
propose_response = await http_client.post(
    "/v1/nemo/propose-refinement",
    json={
        "control_id": "A.9.2",
        "verdict": "FAIL",
        "source": "langfuse_webhook",
    },
)
proposal_id = propose_response.json()["proposal_id"]

# A human risk officer reviews the proposal, then approves it explicitly:
approve_response = await http_client.post(
    f"/v1/nemo/approve-refinement/{proposal_id}",
    json={
        "approved": True,
        "reviewer": "jane.doe@example.com",
        "rationale": "Reviewed telemetry; refinement reduces false-negative rate.",
    },
)
```

### Step 4: Test Verification

#### 4.1 Static verification — confirm zero remaining references to removed symbols

```bash
# Safe Removals (SR-1 – SR-7)
grep -rn "from src.gateway.governance.stpa_validator import" src/ tests/
grep -rn "from src.gateway.governance.safety import\|from src.gateway.governance import safety" src/ tests/
grep -rn "GovernanceClient\b" src/ tests/ --include="*.py" | grep -v "StructuredLLMClient"
grep -rn "\bRedisClient\b" src/governed_financial_advisor/ tests/test_redis_config.py
grep -rn "\bHybridClient\b" src/ tests/
grep -rn "check_safety_constraints" src/ tests/
grep -rn "create_ftra_node(.*registry_path=\|create_ftra_node(.*plan_key=" src/ tests/

# Migration-Required Removals (MR-1 – MR-3)
grep -rn "\bCONTROL_META\b" src/ tests/ | grep -v "get_control_meta"
grep -rn "\bEVIDENCE_SLA_SECONDS\b" src/ tests/ | grep -v "get_sla_seconds"
grep -rn "\bISO_CONTROL_MAP\b" src/ tests/ | grep -v "get_iso_control_map\|get_control_map"

# Consolidated environment variables (EV-1 – EV-6) — confirm no lingering reads
grep -rn "FRIA_ZONE_ALLOW\|FRIA_ZONE_DEFER" src/ --include="*.py"
grep -rn "AGENT_CONFIDENCE_THRESHOLD" src/ --include="*.py"
grep -rn "CAUSAL_LOCK_P_VALUE_THRESHOLD\|CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE\|CAUSAL_LOCK_RISK_BOUNDARY" src/ --include="*.py"
grep -rn "NEMO_AUTO_APPLY_ENABLED" src/ --include="*.py"
grep -rn "KMS_BATCH_MAX_SIZE\|KMS_BATCH_ENABLED" src/ --include="*.py"
```

Each command should return **zero matches** in your own integration code
(matches inside the CAGE source tree's replacement/accessor definitions are
expected and fine).

#### 4.2 Dynamic verification — run the full regression suite

Per [`AGENTS.md`](../AGENTS.md) Test Execution standard, always use `uv run`
— never bare `pytest`:

```bash
source .env
export CAGE_ENV=dev
export CAGE_DEPLOYMENT_REGION="${CAGE_DEPLOYMENT_REGION:-LOCAL}"
export CAGE_ROUTING_SEAL_SECRET="${CAGE_ROUTING_SEAL_SECRET:-dev-only-insecure-placeholder-not-for-production-use}"
export GOVERNANCE_SALT="${GOVERNANCE_SALT:-dev-only-insecure-placeholder-not-for-production-use}"
export LANGFUSE_POSTURE_DRY_RUN=true
uv run pytest tests/ --run-integration -v --tb=short
```

Compare against your pre-upgrade baseline pass count — expect the **passed**
count to decrease only by the number of tests your own suite deleted for
removed-shim coverage (mirroring §4 of
[`MAJOR_VERSION_CLEANUP_PLAN.md`](MAJOR_VERSION_CLEANUP_PLAN.md)); any large
unexplained shift in skip/fail count indicates an incomplete migration.

#### 4.3 Region-posture verification

Since MR-1–MR-3 and EV-3/EV-6 touch shared cross-region modules, verify all
three postures explicitly:

```bash
CAGE_DEPLOYMENT_REGION=US_FED uv run pytest tests/ -v
CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest tests/ -v
CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/ -v
```

Confirm no region-specific control mapping (NIST SP 800-53, EU AI Act/DORA,
MAS FEAT/Notice 655) silently disappears from `get_control_meta(region)` /
`get_sla_seconds(region)` / `get_iso_control_map(region)` output.

#### 4.4 Threshold-migration spot check

For each environment variable migrated to `config/thresholds/`, confirm the
resolved runtime value matches what you expect **before** removing the old
env var from your deployment manifests — run your service with both the old
env var **and** the new config value set, confirm they agree, then remove
the env var in a follow-up deploy:

```bash
# Example: confirm FRIA_ZONE_DEFER resolves identically from config
uv run python -c "
from src.gateway.governance.symbolic_governor import FRIA_ZONE_DEFER
print('Resolved FRIA_ZONE_DEFER:', FRIA_ZONE_DEFER)
"
```

## Rollback Procedure

If issues are encountered after upgrading to `v3.0.0`:

1. **Pin back to the last known-good `v2.1.x` release** in your dependency
   manifest (`pyproject.toml`/`uv.lock` or your consuming project's
   lockfile). All symbols removed in `v3.0.0` are still present (with
   `DeprecationWarning`s) in every `v2.1.x` patch release, so a straight
   downgrade restores full functionality without further code changes.
2. **Restore the pre-upgrade configuration backup** taken in
   [Prerequisites](#prerequisites) step 5 — re-apply your `.env`,
   `config/thresholds/`, and `config/compliance/` files from before the
   upgrade, since `v3.0.0` config-file schemas may include new keys not
   understood by `v2.1.x` code.
3. **Re-introduce removed environment variables** in your deployment
   manifests (Helm values, Terraform `tfvars`, CI secrets) if you had
   removed them as part of the Step 2 configuration migration — `v2.1.x`
   still reads them directly.
4. **For CR-1 (Evidence Stream) specifically:** if the v1.0 → v1.1 evidence
   schema data migration was executed as part of your upgrade, this
   migration is **not code-revertible** — data already migrated to v1.1
   remains v1.1. Downgrading code to `v2.1.x` is safe regardless (v2.1.x
   supports both schema versions), but do not attempt to "undo" the data
   migration itself.
5. **Re-run your full regression suite against the downgraded version**
   using the same command from
   [Step 4: Test Verification](#step-4-test-verification) to confirm the
   rollback restored a known-good state.
6. **File an issue / incident report** documenting which specific breaking
   change caused the rollback, referencing the exact `SR-#`/`MR-#`/`CR-#`/
   `FF-#`/`EV-#` item ID from
   [`BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md) — this makes it
   possible to re-attempt just that item's migration in isolation rather
   than re-attempting the entire `v3.0.0` upgrade at once.

## FAQ

**Q: Do I need to migrate everything before upgrading, or can I upgrade
first and fix call sites afterward?**
A: Migrate first. Every symbol removed in `v3.0.0` already emits a
`DeprecationWarning` in `v2.1.x` — there is no reason to upgrade the
package version before your own call sites are already warning-free. See
[Prerequisites](#prerequisites) step 1.

**Q: Will my code silently break, or will I get a clear error?**
A: It depends on the item. Removed classes/functions/modules
(`SR-1`–`SR-5`, `MR-1`–`MR-3`) raise `ImportError`/`AttributeError`
immediately — these are loud failures caught at import time or first use.
**Environment variable consolidations (`EV-1`–`EV-6`) are the dangerous
case** — setting a removed env var in `v3.0.0` raises no error, it simply
has no effect. Always run the [Step 4.1 grep-based static
verification](#step-4-test-verification) before considering your migration
complete.

**Q: I use `CAGE_DEFER_ENABLED=false` in my deployment. Does v3.0.0 change
this?**
A: No. Per the cleanup plan's explicit recommendation, `CAGE_DEFER_ENABLED`
is **not graduated** in `v3.0.0` — the flag and its DENY-fallback behavior
are unchanged. See [`BREAKING_CHANGES_v3.md` § Feature Flags
Graduated](BREAKING_CHANGES_v3.md#feature-flags-graduated).

**Q: What happens if I set `KMS_BATCH_ENABLED` in v3.0.0?**
A: This is explicitly **uncertain** — the resolved default depends on a
Wave 0 discrepancy resolution documented in
[`MAJOR_VERSION_CLEANUP_PLAN.md`](MAJOR_VERSION_CLEANUP_PLAN.md) §2.4 (FF-2).
Consult your specific `v3.0.0` build's release notes before relying on any
particular behavior for this flag.

**Q: Does the `/v1/nemo/apply-refinement` endpoint disappear in v3.0.0?**
A: No. The endpoint and its route decorator remain. Only the
`NEMO_AUTO_APPLY_ENABLED=true` internal branch is removed — all refinement
changes now require the propose/approve human-gated flow regardless of any
environment variable setting. See [Step 3's MR-5/CR-2
example](#step-3-update-api-calls).

**Q: My integration reads `CONTROL_META` and expects exactly 4 entries
(the universal ISO 42001 controls). Will `get_control_meta()` change this
count?**
A: Only if you pass a real region. `get_control_meta("universal")` (or any
unrecognized region string) reproduces the old universal-only behavior
exactly. If you pass `"US_FED"`, `"EU_ECB"`, or `"APAC_MAS"`, you will see
additional jurisdictional entries merged in — this is intentional and
matches your deployment's actual compliance posture. See
[`BREAKING_CHANGES_v3.md` § Behavioral Changes](BREAKING_CHANGES_v3.md#behavioral-changes).

**Q: Is `CBF.update_state()` deleted in v3.0.0?**
A: As of this writing, **no** — the cleanup plan's CR-3 item recommends
retaining it as an internal-only primitive (possibly renamed to
`_update_state_unsafe()`) rather than deleting it outright, but this is
flagged as an **open architectural decision** in the source plan. Do not
assume either outcome; consult your specific `v3.0.0` build's release notes
and the CR-3 design-review record before relying on `update_state()`'s
public availability.

**Q: Where do I report a migration issue not covered by this guide?**
A: Open an issue referencing the exact `SR-#`/`MR-#`/`CR-#`/`FF-#`/`EV-#`
item ID from [`MAJOR_VERSION_CLEANUP_PLAN.md`](MAJOR_VERSION_CLEANUP_PLAN.md),
including the output of the relevant [Step 4.1 grep
command](#step-4-test-verification) and your `CAGE_DEPLOYMENT_REGION`
setting.
