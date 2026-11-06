# ClickHouse Operator & Langfuse OLAP Module (`infra/modules/clickhouse_operator`)

Provisions the ClickHouse OLAP backend dedicated exclusively to Langfuse v3 trace analytics (`langfuse_app` scoped to `langfuse.*`).

## Architectural Role (§2.6 / F-108)

- **System of Record**: The governance Redis Stream and retention-locked GCS WORM bucket ([`infra/modules/worm_bucket`](../worm_bucket/main.tf)) are the sole live compliance evidence stores; GKE Managed Prometheus (`Monarch`) is the operational metrics store.
- **Langfuse OLAP Plane**: ClickHouse serves strictly as Langfuse v3's trace analytics backend and plays no role in compliance evidence custody. Losing a ClickHouse node (or the entire ClickHouse cluster in `dev`/`staging`) causes **zero evidence loss**.

## Posture Matrix (§1.1, §2.6)

| Posture | Topology | Table Engine | Storage Tiering |
|---|---|---|---|
| **`dev`** | 1 node, local SSD | `MergeTree()` | Hot local SSD (`hot_local_ssd`) |
| **`staging`** | 1 node, local SSD | `MergeTree()` | Hot local SSD (`hot_local_ssd`) |
| **`prod`** | Altinity ClickHouse Operator + 3-node cluster + 3-node ClickHouse Keeper | `ReplicatedMergeTree` | Hot local SSD (`hot_local_ssd`) + GCS cold tier (`cold_gcs`, `hot_to_cold` policy) |

## Least-Privilege RBAC Isolation (F-108)

- **Loopback-Only `default` Superuser**: `users.d/networks.xml` restricts the built-in `default` user strictly to container loopback (`127.0.0.1` / `::1`) with `replace="replace"` and `access_management = 0`, and `outputs.tf` never exports the `default` password.
- **Scoped `langfuse_app` Principal**: `users.d/langfuse_user.xml` defines `langfuse_app` (backed by its own Secret `clickhouse-langfuse-app` via `CLICKHOUSE_LANGFUSE_PASSWORD`) with grants scoped strictly to `langfuse.*` after `01_databases.sql` bootstraps `CREATE DATABASE IF NOT EXISTS langfuse;` on container startup.

## Node Isolation Invariant (§3, §7)

All ClickHouse and ClickHouse Keeper pods carry:
- **Taint toleration**: `workload=clickhouse:NoSchedule`
- **Node affinity**: `workload In ["clickhouse"]` and `cloud.google.com/gke-spot NotIn ["true"]`

This ensures stateful ClickHouse pods run exclusively on the dedicated local-SSD `clickhouse` node pool and never land on general or Spot nodes.
