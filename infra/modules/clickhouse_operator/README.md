# ClickHouse Operator & Query-Plane Module (`infra/modules/clickhouse_operator`)

Provisions the ClickHouse analytical query plane for CAGE (`evidence_stream` compliance queries and Langfuse v3 trace analytics).

## Architectural Role (§2.6)

- **System of Record**: The retention-locked GCS WORM bucket ([`infra/modules/worm_bucket`](../worm_bucket/README.md)) is the authoritative system of record for hash-chained compliance evidence and OSCAL assessment artifacts.
- **Query Plane**: ClickHouse is strictly the analytical query plane, fed asynchronously by [`src/compliance_bridge/clickhouse_sink.py`](../../../src/compliance_bridge/clickhouse_sink.py). Losing a ClickHouse node (or the entire ClickHouse cluster in `dev`/`staging`) causes **zero evidence loss**.

## Posture Matrix (§1.1, §2.6)

| Posture | Topology | Table Engine | Storage Tiering |
|---|---|---|---|
| **`dev`** | 1 node, local SSD | `MergeTree()` | Hot local SSD (`hot_local_ssd`) |
| **`staging`** | 1 node, local SSD | `MergeTree()` | Hot local SSD (`hot_local_ssd`) |
| **`prod`** | Altinity ClickHouse Operator + 3-node cluster + 3-node ClickHouse Keeper | `ReplicatedMergeTree` | Hot local SSD (`hot_local_ssd`) + GCS cold tier (`cold_gcs`, `hot_to_cold` policy) |

## Node Isolation Invariant (§3, §7)

All ClickHouse and ClickHouse Keeper pods carry:
- **Taint toleration**: `workload=clickhouse:NoSchedule`
- **Node affinity**: `workload In ["clickhouse"]` and `cloud.google.com/gke-spot NotIn ["true"]`

This ensures stateful ClickHouse pods run exclusively on the dedicated local-SSD `clickhouse` node pool and never land on general or Spot nodes.
