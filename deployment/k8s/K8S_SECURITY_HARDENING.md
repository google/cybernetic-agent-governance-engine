# Kubernetes Security Hardening Guide

**NIST SP 800-53 Controls: SC-7, SC-39, AC-4, SI-3**  
**Last Updated:** 2026-03-06  
**Reviewer:** ISSO  
**Branch:** `feature/nist-rmf-implementation`

---

> **Branch Reference Update (2026-06-05):** The `rc-v0.1.0` branch no longer exists. `main` is now the authoritative branch for all network policy manifests and Kubernetes security configurations. All emergency rollback procedures referencing `rc-v0.1.0` should use `main` instead. Long-Term governance documentation for the nw environment is deferred per POAM (target: 90 days from 2026-06-05).

---

## Table of Contents

1. [Overview](#overview)
2. [Pod Security Standards (PSA)](#pod-security-standards-psa)
3. [Container Security Contexts](#container-security-contexts)
4. [Network Policy Topology](#network-policy-topology)
5. [Verification Procedures](#verification-procedures)
6. [Testing Network Policies](#testing-network-policies)
7. [Rollback Procedures](#rollback-procedures)
8. [NIST SP 800-53 Control Mapping](#nist-sp-800-53-control-mapping)

---

## Overview

This guide documents the Kubernetes security hardening implemented as part of the NIST RMF Phase 2b remediation for the Cybernetic Governance Engine (CAGE). The hardening addresses four primary NIST SP 800-53 Rev 5 controls:

| Control | Description                  | Mechanism                                                                            |
| ------- | ---------------------------- | ------------------------------------------------------------------------------------ |
| SC-7    | Boundary Protection          | NetworkPolicy egress/ingress allowlists                                              |
| SC-39   | Process Isolation            | Pod Security Standards (PSA) namespace labels                                        |
| AC-4    | Information Flow Enforcement | Per-workload egress NetworkPolicies                                                  |
| SI-3    | Malicious Code Protection    | `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities drop ALL` |

### Files Created

| File                                                             | Purpose                                                       | Controls    |
| ---------------------------------------------------------------- | ------------------------------------------------------------- | ----------- |
| [`pod-security-admission.yaml`](pod-security-admission.yaml)     | PSA labels on all namespaces                                  | SC-39       |
| [`security-context-patch.yaml`](security-context-patch.yaml)     | Security context templates for gateway and compliance-bridge  | SC-39, SI-3 |
| [`network-policy-hardening.yaml`](network-policy-hardening.yaml) | Additive network policies (supplements `network-policy.yaml`) | SC-7, AC-4  |

---

## Pod Security Standards (PSA)

Pod Security Standards replace the deprecated `PodSecurityPolicy` admission controller (removed in Kubernetes 1.25+). PSA enforces security profiles by labeling Namespace resources.

### PSA Profiles Applied Per Namespace

| Namespace          | Enforce      | Audit        | Warn         | Rationale                                                                 |
| ------------------ | ------------ | ------------ | ------------ | ------------------------------------------------------------------------- |
| `governance-stack` | `restricted` | `restricted` | `restricted` | All CAGE workloads are purpose-built to comply with restricted profile    |
| `langfuse`         | `baseline`   | `restricted` | `restricted` | Third-party workload; audit/warn at restricted to track violations        |
| `vllm`             | `baseline`   | `restricted` | `restricted` | CUDA GPU drivers require host-level device access; POAM exception tracked |

### PSS Profile Comparison

| Restriction                | Privileged | Baseline   | Restricted                |
| -------------------------- | ---------- | ---------- | ------------------------- |
| `hostNetwork/PID/IPC`      | ✅ allowed | ❌ blocked | ❌ blocked                |
| `privileged` containers    | ✅ allowed | ❌ blocked | ❌ blocked                |
| Host path volumes          | ✅ allowed | ❌ blocked | ❌ blocked                |
| `runAsRoot`                | ✅ allowed | ✅ allowed | ❌ blocked                |
| `allowPrivilegeEscalation` | ✅ allowed | ✅ allowed | ❌ blocked                |
| Seccomp profile            | optional   | optional   | `RuntimeDefault` required |
| Capabilities drop ALL      | optional   | optional   | required                  |

### Applying PSA Labels

```bash
# Apply namespace labels (idempotent)
kubectl apply -f deployment/k8s/pod-security-admission.yaml

# Verify labels applied
kubectl get namespace governance-stack langfuse vllm \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range $k, $v := .metadata.labels}{"\t"}{$k}: {$v}{"\n"}{end}{end}'
```

### Checking PSA Violations Without Enforcement

Before applying the `restricted` enforce label to `governance-stack`, dry-run to catch violations:

```bash
# Simulate PSA enforcement at restricted level (warning only)
kubectl label namespace governance-stack \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/warn-version=latest \
  --overwrite

# Watch for PSA warnings in pod creation events
kubectl get events -n governance-stack --field-selector reason=FailedCreate -w
```

---

## Container Security Contexts

All containers in `governance-stack` must implement security contexts per [`security-context-patch.yaml`](security-context-patch.yaml).

### Applying Security Contexts to Existing Deployments

The patch file provides strategic merge patch compatible stanzas. Use `kubectl patch` for live clusters:

```bash
# Patch gateway deployment (strategic merge — adds security context without replacing existing spec)
kubectl patch deployment gateway -n governance-stack \
  --type=strategic \
  --patch-file deployment/k8s/security-context-patch.yaml

# Patch compliance-bridge deployment
kubectl patch deployment compliance-bridge -n governance-stack \
  --type=strategic \
  --patch-file deployment/k8s/security-context-patch.yaml
```

> **Note:** For template-based deployments (`*.yaml.tpl`), merge the `spec.template.spec.securityContext` and container-level `securityContext` blocks directly into the template before rendering with `envsubst`.

### Required Security Context (Quick Reference)

**Pod-level:**

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
```

**Container-level:**

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

**Required emptyDir volumes** (for containers with `readOnlyRootFilesystem: true`):

```yaml
volumeMounts:
  - name: tmp-volume
    mountPath: /tmp
volumes:
  - name: tmp-volume
    emptyDir: {}
```

---

## Network Policy Topology

The following diagram describes allowed pod-to-pod communication after both `network-policy.yaml` and `network-policy-hardening.yaml` are applied.

### Allowed Communication Matrix

```
INGRESS CONTROLLER (ingress-nginx ns)
  │
  ├──HTTP 8080──► gateway (governance-stack)
  └──gRPC 50051──► gateway (governance-stack)
                       │
                       ├── OPA sidecar (localhost:8181, no NetworkPolicy needed)
                       ├──8181──► opa pod (governance-stack)
                       ├──6379──► redis (governance-stack)
                       ├──8000──► nemo-guardrails (governance-stack)
                       └──8000──► vllm-service (vllm namespace)

compliance-bridge (governance-stack)
  ├──3000──► langfuse-web (langfuse namespace)
  ├──8181──► opa (governance-stack)
  └──9000──► minio (governance-stack)

lula (governance-stack, CronJob)
  ├──443/6443──► Kubernetes API server
  └──9000──► minio (governance-stack)

ALL pods in governance-stack:
  └──53 UDP/TCP──► kube-dns (cluster DNS)
```

### NetworkPolicy Inventory

**From `network-policy.yaml` (existing baseline):**

| Policy Name                         | Type    | Effect                                               |
| ----------------------------------- | ------- | ---------------------------------------------------- |
| `default-deny-ingress`              | Ingress | Deny all ingress to all pods                         |
| `default-deny-egress`               | Egress  | Deny all egress from all pods                        |
| `allow-gateway-ingress`             | Ingress | Allow 8080 to `governed-financial-advisor`           |
| `allow-opa-egress`                  | Egress  | Allow 8181 to `opa` (namespace-wide)                 |
| `allow-redis-egress`                | Egress  | Allow 6379 to `redis` (namespace-wide)               |
| ~~`allow-otlp-egress`~~             | ~~Egress~~  | ~~Allow 4317/4318 to `otel-collector`~~ — **Removed** (standalone OTel Collector deprecated 2026-05-31; OTLP exported directly to Langfuse) |
| `allow-vllm-egress`                 | Egress  | Allow 8000 to `vllm-service` in governance-stack     |
| `allow-dns-egress`                  | Egress  | Allow UDP/TCP 53 (namespace-wide)                    |
| `allow-opa-ingress-from-governance` | Ingress | Allow 8181 ingress to `opa`                          |

**From `network-policy-hardening.yaml` (this PR):**

| Policy Name                          | Type    | Effect                                                                        |
| ------------------------------------ | ------- | ----------------------------------------------------------------------------- |
| `gateway-egress-to-nemo`             | Egress  | Allow gateway → nemo-guardrails:8000                                          |
| `gateway-egress-to-vllm-namespace`   | Egress  | Allow gateway → vllm namespace:8000                                           |
| `compliance-bridge-egress-allowlist` | Egress  | Allow compliance-bridge → langfuse:3000, opa:8181, minio:9000 |
| `lula-egress-allowlist`              | Egress  | Allow lula → k8s-api:443/6443, minio:9000                                     |
| `allow-gateway-grpc-ingress`         | Ingress | Allow gRPC 50051 to gateway                                                   |
| `allow-compliance-bridge-ingress`    | Ingress | Allow 3001 to compliance-bridge from governance-stack                         |

---

## Verification Procedures

### 1. Verify Pod Security Standards

```bash
# Check PSA labels on all three namespaces
kubectl get ns governance-stack langfuse vllm \
  --show-labels | grep -E 'pod-security|NAME'

# Check for PSA enforcement violations (blocked pod creation)
kubectl get events -n governance-stack \
  --field-selector reason=FailedCreate \
  --sort-by='.lastTimestamp'
```

### 2. Verify Pod-Level Security Contexts

```bash
# Show pod-level securityContext for all governance-stack pods
kubectl get pods -n governance-stack \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext}{"\n"}{end}' \
  | jq -R '. | split("\t") | {pod: .[0], securityContext: (.[1] | fromjson? // "MISSING")}'

# Check that no pods run as root
kubectl get pods -n governance-stack \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t runAsNonRoot="}{.spec.securityContext.runAsNonRoot}{"\n"}{end}'
```

### 3. Verify Container-Level Security Contexts

```bash
# Check container security contexts (allowPrivilegeEscalation must be false)
kubectl get pods -n governance-stack \
  -o jsonpath='{range .items[*]}{.metadata.name}{range .spec.containers[*]}{"\t"}{.name}{"\t allowPrivEsc="}{.securityContext.allowPrivilegeEscalation}{"\t readOnlyRootFS="}{.securityContext.readOnlyRootFilesystem}{"\n"}{end}{end}'

# Check seccomp profile
kubectl get pods -n governance-stack \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t seccomp="}{.spec.securityContext.seccompProfile.type}{"\n"}{end}'
```

### 4. Verify Network Policies

```bash
# List all NetworkPolicies in governance-stack
kubectl get networkpolicies -n governance-stack \
  -o wide

# Describe a specific policy
kubectl describe networkpolicy gateway-egress-to-nemo -n governance-stack

# Verify total policy count (should be 9 baseline + 6 hardening = 15)
kubectl get networkpolicies -n governance-stack --no-headers | wc -l
```

### 5. Verify Read-Only Root Filesystem

```bash
# Attempt to write to root filesystem in gateway container (should fail)
kubectl exec -n governance-stack \
  deployment/gateway \
  -c gateway \
  -- touch /test-write 2>&1 || echo "✅ readOnlyRootFilesystem enforced"

# Verify /tmp is writable (emptyDir)
kubectl exec -n governance-stack \
  deployment/gateway \
  -c gateway \
  -- touch /tmp/test-write && echo "✅ /tmp is writable" || echo "❌ /tmp is not writable"
```

---

## Testing Network Policies

Use `kubectl exec` to test connectivity from within pods. A connection that times out or is refused indicates the NetworkPolicy is correctly blocking traffic.

### Test: Compliance Bridge → Langfuse (should succeed)

```bash
kubectl exec -n governance-stack \
  deployment/compliance-bridge \
  -- wget -q --timeout=5 -O- http://langfuse-web.langfuse.svc.cluster.local:3000/health \
  && echo "✅ Langfuse reachable" || echo "❌ Connection blocked (unexpected)"
```

### Test: Gateway → NeMo (should succeed)

```bash
kubectl exec -n governance-stack \
  deployment/gateway \
  -c gateway \
  -- wget -q --timeout=5 -O- http://nemo-guardrails.governance-stack.svc.cluster.local:8000/health \
  && echo "✅ NeMo reachable" || echo "❌ Connection blocked (unexpected)"
```

### Test: Gateway → Minio (should fail — no policy allows this)

```bash
kubectl exec -n governance-stack \
  deployment/gateway \
  -c gateway \
  -- wget -q --timeout=5 -O- http://minio.governance-stack.svc.cluster.local:9000 2>&1 \
  && echo "❌ Minio reachable from gateway (unexpected — policy gap!)" \
  || echo "✅ Connection blocked (expected)"
```

### Test: Compliance Bridge → vLLM namespace (should fail — no policy allows this)

```bash
kubectl exec -n governance-stack \
  deployment/compliance-bridge \
  -- wget -q --timeout=5 -O- http://vllm-service.vllm.svc.cluster.local:8000 2>&1 \
  && echo "❌ vLLM reachable from compliance-bridge (unexpected — policy gap!)" \
  || echo "✅ Connection blocked (expected)"
```

### Test: Lula → Kubernetes API (should succeed)

```bash
# Run from a lula job pod (if CronJob has run recently)
LULA_POD=$(kubectl get pods -n governance-stack -l app=lula -o name | head -1)
kubectl exec -n governance-stack ${LULA_POD} \
  -- wget -q --timeout=5 --no-check-certificate \
  -O- https://kubernetes.default.svc.cluster.local/readyz \
  && echo "✅ K8s API reachable from lula" || echo "❌ Connection blocked (unexpected)"
```

### Automated Policy Testing with Netassert / Kyverno

For CI-integrated network policy testing, use `netassert` or `kubectl-netpol`:

```bash
# Install netassert
kubectl apply -f https://raw.githubusercontent.com/controlplaneio/netassert/main/netassert.yaml

# Run tests defined in a netassert spec
kubectl apply -f compliance/netassert/network-policy-tests.yaml
```

---

## Rollback Procedures

### Rolling Back Pod Security Standards

If PSA labels break workloads (e.g., a pod is blocked with `Error: pods X is forbidden: violates PodSecurity`):

```bash
# Step 1: Downgrade enforce to baseline temporarily
kubectl label namespace governance-stack \
  pod-security.kubernetes.io/enforce=baseline \
  --overwrite

# Step 2: Identify violating pods
kubectl get events -n governance-stack \
  --field-selector reason=FailedCreate \
  -o wide

# Step 3: Fix the workload security context (see security-context-patch.yaml)
# Step 4: Re-apply restricted enforcement
kubectl label namespace governance-stack \
  pod-security.kubernetes.io/enforce=restricted \
  --overwrite
```

### Rolling Back Security Context Changes

If a container fails due to `readOnlyRootFilesystem: true` (process tries to write outside /tmp):

```bash
# Identify which path is failing (check container logs)
kubectl logs -n governance-stack deployment/gateway -c gateway --previous | grep -i "read-only"

# Temporary rollback: remove readOnlyRootFilesystem constraint
kubectl patch deployment gateway -n governance-stack \
  --type=json \
  -p='[{"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem"}]'

# Permanent fix: add an emptyDir volumeMount for the offending path, then re-apply
# Example: if /app/logs is the problem:
# - Add volumeMount: {name: logs-volume, mountPath: /app/logs}
# - Add volume: {name: logs-volume, emptyDir: {}}
```

### Rolling Back Network Policies

If a network policy blocks legitimate traffic:

```bash
# Delete a specific policy without removing the others
kubectl delete networkpolicy gateway-egress-to-nemo -n governance-stack

# Or: delete all policies from the hardening file
kubectl delete -f deployment/k8s/network-policy-hardening.yaml

# Verify connectivity is restored
kubectl exec -n governance-stack deployment/gateway -c gateway \
  -- wget -q --timeout=5 -O- http://nemo-guardrails.governance-stack.svc.cluster.local:8000/health
```

> **Warning:** Deleting `default-deny-egress` from `network-policy.yaml` will open unrestricted egress. Only do this in a break-glass scenario and re-apply within the same maintenance window.

---

## NIST SP 800-53 Control Mapping

### SC-7 — Boundary Protection

**Implementation:** `network-policy.yaml` + `network-policy-hardening.yaml`

- Default-deny ingress and egress via `default-deny-ingress` and `default-deny-egress` policies
- Explicit allowlist of all permitted inter-pod and cross-namespace communication
- gRPC port 50051 explicitly governed via `allow-gateway-grpc-ingress`
- Compliance bridge cross-namespace egress limited to Langfuse namespace only

**Evidence artifacts:**

- `kubectl get networkpolicies -n governance-stack -o yaml` → all 15 policies
- `kubectl get events -n governance-stack --field-selector reason=NetworkPolicyViolation`

### SC-39 — Process Isolation

**Implementation:** `pod-security-admission.yaml` + `security-context-patch.yaml`

- `governance-stack` namespace: PSS `restricted` enforced
- `langfuse` and `vllm` namespaces: PSS `baseline` enforced, `restricted` audited/warned
- Pod-level: `runAsNonRoot: true`, `runAsUser: 1000`, `seccompProfile: RuntimeDefault`
- Container-level: `allowPrivilegeEscalation: false`, `capabilities drop ALL`

**Evidence artifacts:**

- `kubectl get ns governance-stack -o yaml | grep pod-security`
- `kubectl get pods -n governance-stack -o jsonpath=...` (see Verification Procedures)

### AC-4 — Information Flow Enforcement

**Implementation:** Per-workload egress allowlist NetworkPolicies

- `gateway-egress-to-nemo`: restricts gateway egress to NeMo on port 8000 only
- `gateway-egress-to-vllm-namespace`: restricts cross-namespace vLLM traffic
- `compliance-bridge-egress-allowlist`: limits evidence collection paths
- `lula-egress-allowlist`: limits compliance assessment paths to K8s API and Minio

**Evidence artifacts:**

- `kubectl describe networkpolicy compliance-bridge-egress-allowlist -n governance-stack`
- NetPolicy testing results (see Testing Network Policies section)

### SI-3 — Malicious Code Protection

**Implementation:** `security-context-patch.yaml`

- `readOnlyRootFilesystem: true`: prevents persistent malware installation on container filesystem
- `allowPrivilegeEscalation: false`: blocks privilege escalation exploits
- `capabilities drop ALL`: removes all Linux capabilities from containers
- `seccompProfile: RuntimeDefault`: syscall filtering via kernel seccomp

**Evidence artifacts:**

- `kubectl exec deployment/gateway -c gateway -- touch /test 2>&1` → should fail
- `kubectl get pods -n governance-stack -o jsonpath='{...securityContext...}'`

---

## References

- [NIST SP 800-53 Rev 5 — SC-7 Boundary Protection](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-7)
- [NIST SP 800-53 Rev 5 — SC-39 Process Isolation](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-39)
- [NIST SP 800-53 Rev 5 — AC-4 Information Flow Enforcement](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-4)
- [NIST SP 800-53 Rev 5 — SI-3 Malicious Code Protection](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-3)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [CIS Kubernetes Benchmark v1.8](https://www.cisecurity.org/benchmark/kubernetes)
