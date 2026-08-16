#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Patch CAGE_ARXIV.MD with all Phase 3/4/5 corrections.

Run: uv run python3 scripts/_patch_paper.py

Exit codes:
    0 — all replacements applied successfully (zero [MISS] lines)
    1 — one or more search strings were not found in CAGE_ARXIV.MD

A non-zero exit means the paper text has already been updated (or the
replacement block is stale).  Fix or remove the stale block before
committing.  Never suppress this exit code — it is the machine-enforceable
complement to the human evaluation gate in Step E of the measurement runbook
(docs/paper/MEASUREMENT_RUNBOOK.md).
"""

import sys
from pathlib import Path

paper = Path("tmp/CAGE_ARXIV.md")
text = paper.read_text()

replacements = [
    # All Phase 3/4/5 corrections have been applied to CAGE_ARXIV.MD.
    # Blocks removed: 31 (all already-applied).

    # --- Phase 0.2: Reconciliation Worker Documentation Corrections (2026-08-15) ---
    # Fix §7.2 stale claim about no Kubernetes manifest + provider mismatch
    # Evidence: deployment/k8s/reconciliation-worker.yaml exists (383 lines);
    #           GcsLedgerProvider registered at reconciliation_worker.py:1151-1152
    (
        """**Reconciliation daemon is not yet deployed (see §5.4)**: `reconciliation_worker.py` is fully implemented and unit-tested against live Redis and Cloud KMS infrastructure, but is not currently running as a deployed workload — there is no Kubernetes manifest for it, `hybrid_server.py` never invokes it, and the reference deployment's `RECONCILIATION_PROVIDER=gcs` setting does not match any key in the daemon's own provider registry (`stub`/`anchorage`/`plaid`). Until these three integration gaps are closed, the CBF in the reference deployment operates in its fail-closed (production) or self-reported-fallback (non-production) branch, not its externally-reconciled branch, for every request.""",
        """**Reconciliation daemon activation in progress (see §5.4, POAM-2026-038)**: `reconciliation_worker.py` is fully implemented and unit-tested against live Redis and Cloud KMS infrastructure, and a complete Kubernetes CronJob manifest exists at `deployment/k8s/reconciliation-worker.yaml` (including CiliumNetworkPolicy and Secret template). The `GcsLedgerProvider` is registered under `"gcs"` in the provider registry. The remaining integration gap is operational: the `reconciliation-worker-secrets` Secret must be populated with `KMS_GOVERNANCE_KEY` and `GCS_RECONCILIATION_BUCKET` (tracked as POAM-2026-038). Until secret population is complete, the CBF in the reference deployment operates in its fail-closed (production) or self-reported-fallback (non-production) branch, not its externally-reconciled branch, for every request.""",
    ),

    # Fix §7.3 Future Work item 1: manifest already exists
    (
        """- **Deploy the reconciliation daemon**: Author a Kubernetes `Deployment` or `CronJob` manifest (plus the dedicated `reconciliation-worker` namespace and Cilium `NetworkPolicy` described in Appendix B) and wire it — or an equivalent sidecar — into the serving path so that `reconciliation:verified_balance` is actually populated in the reference deployment.""",
        """- **Activate the reconciliation daemon (POAM-2026-038)**: The Kubernetes CronJob manifest (`deployment/k8s/reconciliation-worker.yaml`) and CiliumNetworkPolicy are complete. Remaining work: populate the `reconciliation-worker-secrets` Secret with production credentials (`KMS_GOVERNANCE_KEY`, `GCS_RECONCILIATION_BUCKET`) and verify the CronJob runs successfully to populate `reconciliation:verified_balance` in the reference deployment.""",
    ),

    # Fix §7.3 Future Work item 2: provider mismatch already fixed
    (
        """- **Fix the `RECONCILIATION_PROVIDER` mismatch**: Either add a `"gcs"` entry to `ExternalLedgerReconciler.from_env()`'s provider registry (backed by the same GCS WORM ledger already used for UCA audit records) or change `deployment/k8s/gateway.yaml` to set `RECONCILIATION_PROVIDER=plaid` with provisioned production credentials, so the deployed configuration and the code's provider registry agree.""",
        """- ~~**Fix the `RECONCILIATION_PROVIDER` mismatch**~~: *Resolved* — `GcsLedgerProvider` is now registered under `"gcs"` in `ExternalLedgerReconciler.from_env()`'s provider registry (`reconciliation_worker.py:1151-1152`), aligning the deployed `RECONCILIATION_PROVIDER=gcs` configuration with the code.""",
    ),
]

count_total = 0
miss_count = 0
for old, new in replacements:
    count = text.count(old)
    if count:
        text = text.replace(old, new)
        count_total += count
        print(f"  [{count}x] {old[:70].strip()!r}")
    else:
        print(f"  [MISS] {old[:70].strip()!r}")
        miss_count += 1

paper.write_text(text)
print(f"\nDone. {count_total} substitutions applied, {miss_count} missed.")

if miss_count:
    print(
        f"\nERROR: {miss_count} replacement block(s) did not match any text in "
        f"{paper}.\n"
        "The paper text may have already been updated, or the replacement block\n"
        "is stale. Fix or remove the stale block before committing.\n"
        "See docs/paper/MEASUREMENT_RUNBOOK.md Step F for guidance."
    )
    sys.exit(1)
