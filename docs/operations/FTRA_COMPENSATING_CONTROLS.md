# FTRA Compensating Controls

> **Reference Architecture Note:** Per `AGENTS.md`, CAGE is a reference architecture demonstrating governance patterns for AI systems. The compensating controls below provide an **illustrative operational model** for defense-in-depth.

> **Status**: PERMANENT — The FTRA boundary check is now **mandatory** and
> unconditional (no feature flag). This document is retained for: (1) historical
> record of the interim compensating-control period, and (2) ongoing
> documentation for the NetworkPolicy defense-in-depth layer (R-02 mitigation).

## Document Purpose

As of 2026-08-16, the `CAGE_FTRA_BOUNDARY_ENABLED` feature flag has been
**removed** from the codebase. The FTRA boundary check now runs unconditionally
in [`SymbolicGovernor._run_checks()`](../../src/gateway/governance/symbolic_governor.py)
(lines 970–999) for every governance request — there is no way to disable it.

This document now serves two purposes:

1. **Historical Record**: Documents the interim compensating-control period
   (when the boundary check was behind a feature flag and NetworkPolicy was
   the primary mitigation for R-03).

2. **NetworkPolicy Defense-in-Depth**: The NetworkPolicy controls described
   below remain in place as a defense-in-depth layer against R-02 (Trust
   Boundary Mutation). They are no longer strictly required for R-03 mitigation
   but provide additional protection.

## Overview

The Forward-Looking Trajectory Reachability Analyzer (FTRA) is a **Pre-Pipeline
Boundary Gate** that performs commencement-time reachability analysis on
execution plans. Unlike Tiers 0–6b (which operate per tool call within
`_run_checks()`), FTRA operates on the **whole execution graph** before
per-tool-call checks begin — it is a **gateway precondition**, not a peer of the
numbered tiers. FTRA identifies plans that can reach IRREVERSIBLE_TERMINAL
actions (e.g., `execute_trade`, `delete_account`) and routes them for
Human-In-The-Loop (HITL) review.

The FTRA boundary check runs unconditionally at the HTTP/controller boundary
(`validate_action`, `ext_authz`) to catch any direct HTTP access that would
bypass the in-graph `ftra_node`. This fully mitigates Risk R-03 at the
controller level.

## Risk Context

### R-02: Trust Boundary Mutation

**Description**: The in-graph `ftra_node` fires within GFA's LangGraph, but
the classification happens BEFORE execution. A compromised host agent could
mutate the plan post-classification but pre-execution.

**Impact**: An action classified as READ_ONLY at FTRA analysis time could be
replaced with an IRREVERSIBLE_TERMINAL action before execution, bypassing
the HITL escalation path.

**Mitigation Status**: Partially mitigated by NetworkPolicy (defense-in-depth).
Full mitigation requires execution-time re-validation (future enhancement).

### R-03: Trust Boundary Bypass

**Description**: `ftra_node` only fires if the host agent wires it into its
own LangGraph. Direct HTTP access to `/validate-action` or ext_authz bypasses
it entirely.

**Impact**: An adversary with direct HTTP access to the gateway could submit
actions that skip FTRA classification entirely, allowing IRREVERSIBLE_TERMINAL
actions to execute without HITL review.

**Mitigation Status**: ✅ **FULLY MITIGATED** (2026-08-16). The FTRA boundary
check now runs unconditionally in `SymbolicGovernor._run_checks()` for every
request. Direct HTTP access to `/validate-action` or ext_authz is now subject
to the same FTRA classification as in-graph requests. See POAM-2026-030-B.

## Controls

### 1. NetworkPolicy (Defense-in-Depth)

**File**: [`deployment/k8s/ftra-network-policy.yaml`](../../deployment/k8s/ftra-network-policy.yaml)

**Purpose**: Restricts ingress to the `cage-gateway` pod to only allow traffic
from governance-validated sources. This provides defense-in-depth against R-02
(post-classification plan mutation).

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

### 2. FTRA Boundary Check (Mandatory)

**Status**: ✅ **MANDATORY** — No feature flag; runs unconditionally.

**Purpose**: Performs FTRA classification at the HTTP/controller boundary
(validate_action, ext_authz) rather than relying solely on the in-graph
ftra_node. This catches direct HTTP bypasses of the in-graph node.

**How It Works**:

1. `SymbolicGovernor._ftra_boundary_check()` runs BEFORE all other governance
   checks in `_run_checks()` (lines 970–999).
2. Uses the same `IrreversibilityClassifier` and `terminal_registry.json` as
   the in-graph `ftra_node`.
3. If an action is classified as `IRREVERSIBLE_TERMINAL`, the boundary check
   adds a violation that routes to HITL.
4. The check is hardcoded — there is no environment variable to disable it.

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
cage_ftra_boundary_checks_total{result="error"}
```

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
- [`docs/POAM.md`](../POAM.md) — POAM-2026-030-B closure record
