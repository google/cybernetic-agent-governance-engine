# CAGE Plugin Development Guide

This guide establishes the architectural standards, mandatory interfaces, and gate enforcement rules for developing Layer 2 domain plugins (e.g., `cage_healthcare`, `cage_finance`) for the Cybernetic Agent Governance Engine (CAGE).

## Table of Contents

1. [Architectural Principles & Layer Isolation](#1-architectural-principles--layer-isolation)
2. [Mandatory Component Structure](#2-mandatory-component-structure)
3. [Implementing GovernanceTierPlugin](#3-implementing-governancetierplugin)
4. [Action Ontology & FTRA Classification](#4-action-ontology--ftra-classification)
5. [OPA Policy Integration](#5-opa-policy-integration)
6. [NeMo Guardrails Integration](#6-nemo-guardrails-integration)
7. [Compliance & Safety Artifacts](#7-compliance--safety-artifacts)
8. [Testing Requirements](#8-testing-requirements)
9. [Validation Checklist](#9-validation-checklist)
10. [Common Pitfalls & Anti-Patterns](#10-common-pitfalls--anti-patterns)

---

## 1. Architectural Principles & Layer Isolation

CAGE enforces strict separation between the domain-agnostic control kernel (Layer 1) and domain-specific extension modules (Layer 2).

| Layer | Path Pattern | Responsibility | Prohibited Actions |
|-------|--------------|----------------|-------------------|
| **Layer 1 (Kernel)** | `src/gateway/` | Tier dispatch, state consensus, CBF synchronization, audit rails, routing seal integrity | Importing any module from `src/cage_*` or domain namespaces |
| **Layer 2 (Plugins)** | `src/cage_{domain}/` | Domain ontologies, OPA policies, custom execution verbs, action registries, causal graphs | Modifying kernel state bypassing gated consensus, hardcoding domain literals in kernel |
| **Layer 3 (Config)** | `config/`, `deployment/` | Threshold values, regional baselines, infrastructure manifests | Business logic or stateful transformations |

### The G3 & G6 Architectural Gates

**G3 Gate (Import Boundaries)**: Enforced via [`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py).
- Layer 2 plugins **may** import kernel services from `src.gateway.*`
- Kernel code **must never** import from `src.cage_*`
- Violation triggers CI failure and blocks PR merge

**G6 Gate (Domain Literals)**: The kernel contains zero hardcoded domain actions.
- All verbs, classifications, and thresholds must be registered dynamically by Layer 2 plugins
- No `if action == "execute_trade"` blocks in `src/gateway/`
- Domain-specific logic lives exclusively in `src/cage_{domain}/`

---

## 2. Mandatory Component Structure

A compliant Layer 2 plugin must implement the following directory layout:

```text
src/cage_{domain}/
├── __init__.py                    # Package initialization
├── tiers/                         # Governance tier plugins
│   ├── __init__.py
│   ├── {domain}_tier.py          # Domain-specific tier implementations
│   └── ...
├── ontology.py                    # Action ontologies and terminal classifications
├── config/                        # Domain-specific configuration
│   ├── causal_graph.yaml         # Optional: domain causal model
│   └── thresholds.json           # Domain-specific thresholds
├── policies/                      # OPA Rego policy files
│   ├── {domain}_policy.rego
│   └── ...
├── rails/                         # NeMo Guardrails colang specs
│   ├── {domain}_rails.co
│   └── ...
└── tools/                         # Domain-specific execution verbs
    ├── __init__.py
    └── {domain}_actions.py
```

### Example: Finance Domain Plugin Structure

```text
src/cage_finance/
├── __init__.py
├── tiers/
│   ├── __init__.py
│   ├── cbf_tier.py               # CBF safety tier
│   ├── consensus_tier.py         # Consensus validation tier
│   └── causal_tier.py            # Causal safety tier
├── ontology.py                    # Trading action classifications
├── config/
│   ├── causal_graph.yaml
│   └── trading_thresholds.json
├── policies/
│   └── trade_policy.rego         # OPA trading constraints
├── rails/
│   └── trading_rails.co          # NeMo trading guardrails
└── tools/
    └── trading_actions.py         # execute_trade, market_lookup, etc.
```

---

## 3. Implementing GovernanceTierPlugin

Every plugin must expose one or more concrete subclasses of [`GovernanceTierPlugin`](../../src/gateway/governance/contracts.py) registered with the kernel dispatch loop.

### Minimal Plugin Implementation

```python
# src/cage_{domain}/tiers/example_tier.py
from typing import Any

from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class ExampleTierPlugin(GovernanceTierPlugin):
    """
    Example domain tier plugin (phase 1, order 5).
    
    Implements domain-specific validation logic that executes
    during the tier dispatch loop.
    """

    @property
    def tier_name(self) -> str:
        return "example_domain"

    @property
    def phase(self) -> int:
        return 1  # Phase 1: Pre-execution validation

    @property
    def order(self) -> int:
        return 5  # Execution order within phase

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        """
        Declare which actions this tier handles.
        
        Return True if this tier should evaluate the given action.
        """
        return action in {"domain_specific_action", "another_action"}

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """
        Pre-execution validation gate.
        
        Returns violations if action should be blocked.
        Empty list means approval.
        """
        violations = []
        
        # Example: Check domain-specific constraint
        if params.get("risk_score", 0) > 0.95:
            violations.append(
                Violation(
                    tier=self.tier_name,
                    code="RISK_THRESHOLD_EXCEEDED",
                    message=f"Risk score {params['risk_score']} exceeds safety boundary",
                    recoverable=False,
                )
            )
        
        return violations

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """
        Post-execution commit gate.
        
        Called after action execution to finalize state changes.
        """
        return []  # Most tiers have no commit logic

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        """
        Rollback handler for failed transactions.
        
        Called if any tier in the pipeline fails.
        """
        pass  # Most tiers have no rollback logic
```

### Registering Tiers with the Governor

Tiers are registered in the kernel's [`SymbolicGovernor`](../../src/gateway/governance/symbolic_governor.py) initialization:

```python
from src.gateway.governance.symbolic_governor import SymbolicGovernor
from src.cage_{domain}.tiers.example_tier import ExampleTierPlugin

governor = SymbolicGovernor(...)
governor.register_domain_tier(ExampleTierPlugin())
```

---

## 4. Action Ontology & FTRA Classification

All domain actions must be classified under the **FTRA (Fail-Closed Terminal Reachability Analysis)** taxonomy, which implements OWASP AISVS Chapter 9 reversibility requirements.

### Terminal Classification Taxonomy

```python
# src/cage_{domain}/ontology.py
from src.gateway.governance.ftra.models import TerminalClassification

DOMAIN_ACTION_REGISTRY = {
    # Read-only actions (no state mutation)
    "market_lookup": TerminalClassification.READ_ONLY,
    "portfolio_summary": TerminalClassification.READ_ONLY,
    
    # Internally reversible actions (undo within system)
    "reserve_funds": TerminalClassification.REVERSIBLE,
    "create_draft_order": TerminalClassification.REVERSIBLE,
    
    # Externally reversible actions (undo requires external coordination)
    "execute_trade_bounded": TerminalClassification.EXTERNALLY_REVERSIBLE,
    
    # Irreversible terminal actions (no undo mechanism)
    "wire_transfer": TerminalClassification.IRREVERSIBLE_TERMINAL,
    "delete_account": TerminalClassification.IRREVERSIBLE_TERMINAL,
}
```

### Classification Decision Matrix

| Category | Undo Mechanism | HITL Gate | Example Actions |
|----------|----------------|-----------|-----------------|
| `READ_ONLY` | N/A (no mutation) | Optional | `market_lookup`, `get_balance` |
| `REVERSIBLE` | Internal rollback | Optional | `reserve_funds`, `create_draft` |
| `EXTERNALLY_REVERSIBLE` | External coordination required | Recommended | `execute_trade_bounded`, `send_email` |
| `IRREVERSIBLE_TERMINAL` | No undo | **Mandatory** | `wire_transfer`, `delete_data` |

---

## 5. OPA Policy Integration

Domain-specific constraints are expressed as [Open Policy Agent](https://www.openpolicyagent.org/) Rego policies in [`config/opa/`](../../config/opa/).

### Example: Trading Policy

```rego
# config/opa/trade_policy.rego
package trade

import future.keywords.if
import future.keywords.in

# Rule: Block trades exceeding maximum notional value
default max_notional_exceeded := false

max_notional_exceeded if {
    input.action == "execute_trade"
    input.params.amount * input.params.price > data.thresholds.max_trade_notional_usd
}

# Rule: Enforce jurisdiction constraints
default jurisdiction_violation := false

jurisdiction_violation if {
    input.action == "execute_trade"
    input.params.symbol in data.restricted_symbols[input.region]
}

# Final decision aggregation
decision := "DENY" if {
    max_notional_exceeded
} else := "DENY" if {
    jurisdiction_violation
} else := "ALLOW"
```

### Policy Testing

Every Rego policy must include unit tests:

```rego
# config/opa/trade_policy_test.rego
package trade

test_max_notional_exceeded {
    max_notional_exceeded with input as {
        "action": "execute_trade",
        "params": {"amount": 10000, "price": 150}
    } with data.thresholds as {"max_trade_notional_usd": 1000000}
}
```

Run OPA tests:
```bash
opa test config/opa/ -v
```

---

## 6. NeMo Guardrails Integration

[NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) provides natural language safety barriers for LLM-generated actions.

### Example: Trading Guardrails

```colang
# config/rails/trading_rails.co
define user express trade intent
  "I want to trade"
  "Execute a trade for"
  "Buy 100 shares of"

define bot refuse excessive trade
  "I cannot execute trades exceeding the maximum notional value."

define flow trading safety check
  user express trade intent
  $params = extract trade parameters
  
  if $params.amount * $params.price > $thresholds.max_trade_notional_usd
    bot refuse excessive trade
    stop
  
  execute trade with params=$params
```

### Registering Custom Actions

```python
# config/rails/actions.py
from typing import Optional

async def execute_trade(
    symbol: str,
    amount: float,
    price: float,
    context: Optional[dict] = None
) -> dict:
    """
    NeMo-triggered trade execution action.
    
    This function is called by the NeMo runtime when a trading
    flow triggers an execution step.
    """
    # Validation logic here
    return {"status": "executed", "order_id": "..."}
```

---

## 7. Compliance & Safety Artifacts

### STPA (System-Theoretic Process Analysis) Integration

When adding or modifying domain actions, regenerate STPA verification artifacts:

```bash
uv run python scripts/check_stpa_freshness.py --regenerate
```

This updates:
- [`config/stpa_control_structure.yaml`](../../config/stpa_control_structure.yaml)
- [`config/opa/generated_stpa_policy.rego`](../../config/opa/generated_stpa_policy.rego)
- [`config/rails/generated_stpa_rails.co`](../../config/rails/generated_stpa_rails.co)

### OSCAL Component Definition

Domain plugins must provide an OSCAL component definition for NIST SP 800-53 control mapping:

```json
{
  "component-definition": {
    "uuid": "...",
    "metadata": {
      "title": "CAGE {Domain} Plugin Component Definition",
      "version": "1.0.0"
    },
    "components": [
      {
        "uuid": "...",
        "type": "software",
        "title": "{Domain} Governance Plugin",
        "description": "Layer 2 domain plugin implementing {domain}-specific governance controls",
        "control-implementations": [
          {
            "uuid": "...",
            "source": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
            "implemented-requirements": [
              {
                "uuid": "...",
                "control-id": "AC-3",
                "description": "Domain-specific access control enforcement via OPA policies"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

---

## 8. Testing Requirements

### Unit Test Coverage

Every plugin tier must achieve ≥75% code coverage:

```bash
uv run pytest tests/cage_{domain}/ -m "local or unit" \
  --cov=src/cage_{domain} \
  --cov-report=term-missing \
  --cov-fail-under=75
```

### Integration Test Matrix

Test domain actions across all three regional postures:

```python
# tests/cage_{domain}/test_{domain}_regional.py
import pytest

@pytest.mark.parametrize("region", ["US_FED", "EU_ECB", "APAC_MAS"])
async def test_domain_action_regional_compliance(region, monkeypatch):
    """
    Verify domain action respects regional compliance constraints.
    """
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", region)
    
    # Test domain action
    result = await execute_domain_action(...)
    
    # Assert regional constraints
    if region == "US_FED":
        assert result["audit_logged"] is True  # FISMA AU-11
    elif region == "EU_ECB":
        assert "risk_tier" in result  # EU AI Act transparency
    elif region == "APAC_MAS":
        assert result["explainability_score"] >= 0.7  # MAS FEAT
```

### Gate Validation Tests

Verify architectural gates pass:

```bash
# G3 Gate: Import boundary enforcement
uv run python scripts/check_import_boundaries.py --verbose

# G6 Gate: No domain literals in kernel
uv run python scripts/check_domain_literals.py

# STPA Freshness
uv run python scripts/check_stpa_freshness.py
```

---

## 9. Validation Checklist

Before submitting a new plugin PR, verify all gates pass locally:

- [ ] **G3 Gate**: `uv run python scripts/check_import_boundaries.py --verbose`
- [ ] **G6 Gate**: No hardcoded domain actions in `src/gateway/`
- [ ] **STPA Freshness**: `uv run python scripts/check_stpa_freshness.py`
- [ ] **Unit Tests**: `uv run pytest tests/cage_{domain}/ -m "local or unit" --cov-fail-under=75`
- [ ] **OPA Policy Tests**: `opa test config/opa/ -v`
- [ ] **License Headers**: All `.py` files include Apache 2.0 header
- [ ] **Regional Posture Tests**: Tests pass for `US_FED`, `EU_ECB`, `APAC_MAS`
- [ ] **OSCAL Component**: Component definition exists in `compliance/oscal/components/`
- [ ] **Conventional Commits**: Commit message follows `feat(domain):` or `fix(domain):` format

---

## 10. Common Pitfalls & Anti-Patterns

### ❌ Anti-Pattern: Kernel Imports Domain Code

**Wrong:**
```python
# src/gateway/governance/symbolic_governor.py
from src.cage_finance.ontology import TRADING_ACTIONS  # ❌ VIOLATES G3
```

**Correct:**
```python
# src/cage_finance/__init__.py
def register_finance_plugin(governor):
    from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
    governor.register_domain_tier(CBFTierPlugin())
```

### ❌ Anti-Pattern: Hardcoded Domain Logic in Kernel

**Wrong:**
```python
# src/gateway/governance/symbolic_governor.py
if action == "execute_trade":  # ❌ VIOLATES G6
    # domain-specific logic
```

**Correct:**
```python
# src/cage_finance/tiers/consensus_tier.py
def claims_action(self, action: str, params: dict) -> bool:
    return action == "execute_trade"
```

### ❌ Anti-Pattern: Missing FTRA Classification

**Wrong:**
```python
# Unclassified action allows unrestricted execution
DOMAIN_ACTIONS = ["mystery_action"]  # ❌ No terminal classification
```

**Correct:**
```python
from src.gateway.governance.ftra.models import TerminalClassification

DOMAIN_ACTION_REGISTRY = {
    "mystery_action": TerminalClassification.IRREVERSIBLE_TERMINAL
}
```

### ❌ Anti-Pattern: Skipping Regional Posture Tests

**Wrong:**
```python
# tests/cage_{domain}/test_actions.py
async def test_action():
    # Only tests LOCAL posture ❌
    result = await execute_action()
```

**Correct:**
```python
@pytest.mark.parametrize("region", ["US_FED", "EU_ECB", "APAC_MAS", "LOCAL"])
async def test_action_regional(region, monkeypatch):
    monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", region)
    result = await execute_action()
    assert_regional_compliance(result, region)
```

---

## Additional Resources

- [Architecture Overview](../architecture/ARCHITECTURE.md)
- [FTRA Specification](../architecture/FTRA_SPECIFICATION.md)
- [Governance Overview](../governance/GOVERNANCE_OVERVIEW.md)
- [STPA Analysis](../security/STPA_ANALYSIS.md)
- [Regional Compliance Matrix](../compliance/REGION_GUARD_AUDIT.md)

---

**Last Updated:** 2026-09-04  
**Maintainer:** CAGE Core Team  
**License:** Apache 2.0
