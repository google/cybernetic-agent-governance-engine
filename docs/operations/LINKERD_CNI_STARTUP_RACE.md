# linkerd-cni Startup Race: Reproduction and Root Cause

**Status:** Reproduced twice on staging on 2026-11-01. The mechanism below is established for pods scheduled onto a node the cluster autoscaler has just added. Node reboots, surge upgrades and auto-repair were not tested.
**Runbook entry:** [Linkerd Network Validator CrashLoopBackOff](DEPLOYMENT_RULES.md#linkerd-network-validator-crashloopbackoff-mitigation-vs-root-cause)
**Mitigation:** the `linkerd2-cni` repair controller and the repair-scope admission policy in [`infra/modules/service_mesh`](../../infra/modules/service_mesh/main.tf)

## Summary

A meshed pod (one with the Linkerd proxy injected) whose pod sandbox is created on a node before `linkerd2-cni` has chained itself into the node's CNI configuration gets no traffic redirect. Its `linkerd-network-validator` init container then exits 95. The kubelet retries the init container inside the same sandbox, and the CNI plugins run only when a sandbox is created, so every retry fails the same way until the pod is deleted. This matches the staging incident in which pods crash-looped for 31 hours and recovered once they were deleted.

Three conditions combine:

1. **`linkerd2-cni` cannot start early.** It runs as an ordinary DaemonSet pod, not on the host network, so it needs the node's primary CNI (GKE Dataplane V2) before it can start. On a new node, that is the moment the node turns Ready and the scheduler binds every pending pod. `linkerd2-cni` then still has to start its container and run its installer. In the first run, its entry appeared in the CNI configuration 30 seconds after the node turned Ready, although its image was already cached on the node.
2. **Nothing orders workload pods after it.** Kubernetes does not hold pods off a node until a DaemonSet on it is ready. Pods pending when the node turns Ready get their sandboxes within seconds.
3. **The failure is permanent per pod.** The validator's retries reuse the sandbox, so a pod that misses the chain never gets the redirect. Pods created after the chain start normally.

Dataplane V2 overwriting `linkerd2-cni`'s entry in the CNI configuration was the other hypothesis. It is refuted for the period observed: after `linkerd2-cni` wrote its entry, the file did not change again, for about 53 hours on the existing primary node and for the rest of the first run on the new one.

## Environment

| Component | Version or setting |
|---|---|
| Cluster | `cage-staging`, zonal, GKE `1.35.8-gke.1796000`, Dataplane V2 (`cilium-cni` in the node's conflist), containerd `2.2.7`, Container-Optimized OS |
| Node pool | `primary-node-pool`, `e2-standard-4`, cluster autoscaler 1 to 5 nodes |
| Linkerd | `edge-26.9.3` (charts `2026.9.3`); `linkerd2-cni` with `cr.l5d.io/linkerd/cni-plugin:v1.7.0`, repair controller off, as applied from `main` before this change |
| CNI configuration | `/etc/cni/net.d/10-gke-cni.conflist` |

## Method

Everything ran in a temporary namespace that was deleted afterwards. Binary Authorization is enforced on the cluster, so every test container used the allowlisted `cr.l5d.io/linkerd/cni-plugin:v1.7.0` image. For the duration of each run, the existing primary node was annotated `cluster-autoscaler.kubernetes.io/scale-down-disabled`, so that the autoscaler could remove only the node the run added.

**Run 1 (race and repair controller):**

1. A read-only DaemonSet on the host network logged every change to `/etc/cni/net.d` (file hashes, plugin types, modification times) on any new primary-pool node, from as early as the kubelet would run it.
2. A Deployment of three meshed pods that could not be scheduled onto the existing primary node made the autoscaler add one, and the scheduler bound them the moment it turned Ready.
3. After `linkerd2-cni` had chained itself in, the Deployment was scaled to six, giving three pods created after the chain.
4. The repair controller then ran on the new node as the container the `linkerd2-cni` chart renders with `repairController.enabled` (same image, command, arguments, environment, probes and security context), with the chart's repair permissions (`delete` on pods, `create` on events) limited to the test namespace.

The watcher pulled the `cni-plugin` image onto the new node before `linkerd2-cni` started, so `linkerd2-cni` did not have to pull it (a 6.2-second pull on this node). Without the watcher, the window would have been longer.

**Run 2 (repair-scope admission policy):** the same race on another new node, with the admission policy rendered from [`charts/cni-repair-guard`](../../infra/modules/service_mesh/charts/cni-repair-guard/templates/repair-scope-policy.yaml) for a test service account. The account was granted `delete` on pods cluster-wide, as the chart grants its own, so every refusal came from the policy. Deletions were sent as server-side dry runs with tokens bound to pods on different nodes, and then the repair controller ran under the policy.

## Run 1 timeline (UTC, 2026-11-01)

| Time | Event | Source |
|---|---|---|
| 04:00:27 | Deployment of three meshed pods created | `kubectl` |
| 04:00:29 | Cluster autoscaler scales the pool from 1 to 2 | `TriggeredScaleUp` event |
| 04:01:36 | New node registers; its `linkerd2-cni` pod is bound to it | node, `Scheduled` event |
| 04:01:36 to 04:02:09 | The `linkerd2-cni` pod cannot start: `NetworkNotReady` (Dataplane V2 not ready yet) and `FailedMount` (`kube-root-ca.crt` not registered) | events |
| 04:01:42.976 | GKE writes `10-gke-cni.conflist` with `cilium-cni` and its `host-local` IPAM only | watcher (file time) |
| 04:02:11 | Node Ready; the scheduler binds the three meshed pods | `NodeReady`, `Scheduled` events |
| 04:02:22 | The meshed pods pull their proxy image, so their sandboxes exist. The conflist still has no `linkerd-cni` | `Pulling` events, watcher |
| 04:02:32 to :33 | First validator attempts start; each exits 95 when its 10-second timeout expires | events, pod status |
| 04:02:41 | The `linkerd2-cni` pod's sandbox is ready and its installer starts | pod condition, installer log |
| 04:02:41.630 | `linkerd2-cni` appends itself: `host-local`, `cilium-cni`, `linkerd-cni` | installer log (`reconfigured cni`), watcher (file time 04:02:41.630) |
| 04:03:41 to 04:04:55 | The three pods' validators keep exiting 95 after the chain, four restarts each | pod status, validator log |
| 04:03:43 | Deployment scaled to six | `kubectl` |
| 04:03:50 to :54 | The three new pods' validators exit 0 and the pods become Ready | pod status |
| 04:04:57 | Repair controller deployed on the new node; its container starts at 04:05:00 | `kubectl`, events |
| 04:05:01 | Its first deletion gives up after its one-second limit (`Pod deletion timed out`) | controller log |
| 04:06:16, :17, :20 | It deletes the three pods on their next failures, with a `LinkerdCNINotConfigured` event for each | controller log, events |
| 04:06:26 to :30 | Their replacements' validators exit 0 and the pods become Ready | pod status |

Each failing attempt logged:

```text
INFO linkerd_network_validator: Connecting to 1.1.1.1:20001
ERROR linkerd_network_validator: Failed to validate networking configuration. Please ensure traffic redirection rules are rewriting traffic as expected. timeout=10s
```

The validator listens on the proxy's outbound port (4140) and connects to an outside address. With the redirect in place, the connection reaches its own listener; without it, the connection times out.

Why the `linkerd2-cni` pod started 30 seconds after the node turned Ready, while pods bound at that moment had sandboxes within 11 seconds, was not verified. Likely cause: the kubelet's retry back-off from the errors it hit before the node was Ready.

## Run 2: the repair-scope admission policy

The race reproduced again: all three pods pending when the new node turned Ready failed with exit 95. With the account holding `delete` on pods cluster-wide, the policy decided each deletion:

| # | Token | Target | Result |
|---|---|---|---|
| 1 | Bound to a pod on another node | A stuck pod (validator last exited 95) on the new node | Refused: `linkerd-cni may delete only pods bound to its own node` |
| 2 | Not bound to a pod (no node in the token) | The same stuck pod | Refused: `linkerd-cni may delete only pods bound to its own node` |
| 3 | Bound to a pod on the new node | The same stuck pod | Allowed (dry run) |
| 4 | Bound to a pod on the new node | A pod on the new node without a validator | Refused: `linkerd-cni may delete only pods whose linkerd-network-validator last exited 95` |
| 5 | Bound to a pod on the new node | A meshed pod on the new node whose validator exited 0 | Refused: `linkerd-cni may delete only pods whose linkerd-network-validator last exited 95` |
| 6 | Bound to a pod on the new node | A pod on another node | Refused: `linkerd-cni may delete only pods bound to its own node` |

The repair controller, deployed on the new node under the policy, deleted the three stuck pods within 8 seconds of being deployed, with no refusals, and their replacements became Ready. One deletion was followed by a duplicate request for the same pod, which returned `NotFound`; the controller logs it as `Error deleting pod` and carries on.

The pod-bound token's identity carries the node in `authentication.kubernetes.io/node-name`; a token not bound to a pod carries none, which is why the policy refuses it.

## What remains open

- **Node reboots and in-place restarts were not tested.** If the GKE network agent rewrites the conflist when it restarts, the same race follows; the 53-hour observation covers a node whose agent did not restart.
- **Surge upgrades and auto-repair were not tested.** Both add nodes, but whether pods reach a new node inside the window depends on their timing.
- **The repair controller mitigates; it does not prevent.** Holding meshed pods off a node until `linkerd2-cni` is ready would need a startup taint and something that removes it once the plugin is installed, and the `linkerd2-cni` chart CAGE pins (`2026.9.3`) ships nothing that does. Running the proxy's own init container instead needs `NET_ADMIN`, which the restricted Pod Security level CAGE enforces forbids ([`pod-security-admission.yaml`](../../deployment/k8s/pod-security-admission.yaml)). Each victim therefore still loses up to one crash-loop back-off interval before it is repaired.
