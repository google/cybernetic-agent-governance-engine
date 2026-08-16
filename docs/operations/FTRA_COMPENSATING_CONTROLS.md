# FTRA Compensating Controls

> **Status**: INTERIM — This document describes compensating controls that are
> deployed until `CAGE_FTRA_BOUNDARY_ENABLED=true` becomes the default
> production configuration.

## Overview

The Forward-Looking Trajectory Reachability Analyzer (FTRA) is a Tier 0.5
governance gate that performs commencement-time reachability analysis on
execution plans. It identifies plans that can reach IRREVERSIBLE_TERMINAL
actions (e.g., `execute_trade`, `delete_account`) and routes them for
Human-In-The-Loop (HITL) review.

This document describes interim compensating controls deployed to mitigate
risks R-02 and R-03 until the FTRA boundary check is enabled by default.

## Risk Context

### R-02: Trust Boundary Mutation

**Description**: The in-graph `ftra_node` fires within GFA's LangGraph, but
the classification happens BEFORE execution. A compromised host agent could
mutate the plan post-classification but pre-execution.

**Impact**: An action classified as READ_ONLY at FTRA analysis time could be
replaced with an IRREVERSIBLE_TERMINAL action before execution, bypassing
the HITL escalation path.

### R-03: Trust Boundary Bypass

**Description**: `ftra_node` only fires if the host agent wires it into its
own LangGraph. Direct HTTP access to `/validate-action` or ext_authz bypasses
it entirely.

**Impact**: An adversary with direct HTTP access to the gateway could submit
actions that skip FTRA classification entirely, allowing IRREVERSIBLE_TERMINAL
actions to execute without HITL review.

## Compensating Controls

### 1. NetworkPolicy (Interim)

**File**: [`deployment/k8s/ftra-network-policy.yaml`](../../deployment/k8s/ftra-network-policy.yaml)

**Purpose**: Restricts ingress to the `cage-gateway` pod to only allow traffic
from governance-validated sources.

**Policies**:

| Policy Name | Description |
|-------------|-------------|
| `ftra-egress-lockdown` | Only allows ingress from pods with `governance-validated: "true"` label |
| `ftra-allow-gfa-ingress` | Allows GFA pod (which has in-graph ftra_node) to reach gateway |
| `ftra-allow-ingress-controller` | Allows ingress controller for external API access (subject to boundary check) |

**Application**:

```bash
# Apply the FTRA NetworkPolicy
kubectl apply -f deployment/k8s/ftra-network-policy.yaml

# Verify the policies are active
kubectl get networkpolicies -n governance-stack -l cage.io/component=ftra-interim-control
```

**Verification**:

```bash
# Test that unauthorized pods cannot reach the gateway
kubectl run test-pod --rm -it --image=curlimages/curl -- \
  curl -s -o /dev/null -w "%{http_code}" http://cage-gateway:8080/health

# Expected: Connection refused or timeout (network policy blocks)

# Test that GFA can still reach the gateway
kubectl exec -it deploy/governed-financial-advisor -n governance-stack -- \
  curl -s -o /dev/null -w "%{http_code}" http://cage-gateway:8080/health

# Expected: 200 (GFA is allowed)
```

### 2. FTRA Boundary Check (Phase 3.3)

**Environment Variable**: `CAGE_FTRA_BOUNDARY_ENABLED`

**Default**: `false` (interim — will be `true` when this control is production-ready)

**Purpose**: Performs FTRA classification at the HTTP/controller boundary
(validate_action, ext_authz) rather than relying solely on the in-graph
ftra_node. This catches direct HTTP bypasses of the in-graph node.

**How It Works**:

1. When enabled, `SymbolicGovernor._ftra_boundary_check()` runs BEFORE all
   other governance checks.
2. Uses the same `IrreversibilityClassifier` and `terminal_registry.json` as
   the in-graph `ftra_node`.
3. If an action is classified as `IRREVERSIBLE_TERMINAL`, the boundary check
   adds a violation that routes to HITL.

**Activation**:

```bash
# Enable FTRA boundary check (per-deployment)
export CAGE_FTRA_BOUNDARY_ENABLED=true

# Or in Kubernetes deployment manifest:
# env:
#   - name: CAGE_FTRA_BOUNDARY_ENABLED
#     value: "true"
```

**Telemetry**:

When the boundary check fires, the following OTel attributes are emitted:

| Attribute | Description |
|-----------|-------------|
| `cage.ftra.boundary_check_triggered` | `true` when boundary check runs |
| `cage.ftra.classification` | The classification result |
| `cage.ftra.requires_hitl` | `true` if HITL escalation is required |
| `cage.ftra.bypassed_ftra_node` | `true` if this check caught a bypass |

**Prometheus Metrics**:

```
cage_ftra_boundary_checks_total{result="hitl_required"}
cage_ftra_boundary_checks_total{result="passed"}
cage_ftra_boundary_checks_total{result="skipped"}
cage_ftra_boundary_checks_total{result="error"}
```

## Removal Criteria

The NetworkPolicy compensating control can be removed once ALL of the following
conditions are met:

1. **CAGE_FTRA_BOUNDARY_ENABLED=true is the default** in production configuration.
2. **Lula validation passes** (`compliance/lula/lula-validation-ftra.yaml`).
3. **POAM-2026-030 is closed** with evidence of boundary check operation.
4. **At least 30 days of production telemetry** shows the boundary check is
   catching bypass attempts (or confirms none exist).

### Removal Procedure

```bash
# 1. Verify FTRA boundary check is enabled
kubectl exec -it deploy/cage-gateway -n governance-stack -- \
  printenv CAGE_FTRA_BOUNDARY_ENABLED
# Expected: true

# 2. Verify Lula validation passes
lula validate -f compliance/lula/lula-validation-ftra.yaml

# 3. Review telemetry for bypass attempts
# (Query Langfuse or Prometheus for cage.ftra.bypassed_ftra_node=true events)

# 4. Remove the NetworkPolicy
kubectl delete -f deployment/k8s/ftra-network-policy.yaml

# 5. Update this document to mark controls as REMOVED
# 6. Close POAM-2026-030
```

## POAM Reference

| POAM ID | Title | Status |
|---------|-------|--------|
| POAM-2026-030 | FTRA Tier 0.5 Gate Implementation | OPEN |

## Compliance Mappings

| Control | Framework | Description |
|---------|-----------|-------------|
| SC-7 | NIST SP 800-53 | Boundary Protection |
| AC-4 | NIST SP 800-53 | Information Flow Enforcement |
| A.2.5 | ISO 42001 | AI System Boundary Controls |
| CTRL_FTRA_001 | CAGE Internal | Forward-Looking Trajectory Reachability Analyzer |

## Related Documentation

- [`config/ftra/terminal_registry.json`](../../config/ftra/terminal_registry.json) — Terminal action classifications
- [`src/gateway/governance/ftra/`](../../src/gateway/governance/ftra/) — FTRA implementation
- [`plans/CAGE_RISK_MATRIX.md`](../../plans/CAGE_RISK_MATRIX.md) — Risk R-02 and R-03 details
- [`compliance/lula/lula-validation-ftra.yaml`](../../compliance/lula/lula-validation-ftra.yaml) — Lula validation
