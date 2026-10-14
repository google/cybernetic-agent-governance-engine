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

"""BigQuery Asynchronous Telemetry Harvester (`src/integrations/gcp_eval/bq_harvester.py`).

Closes the Online -> Offline Double Ratchet Flywheel without impacting the
`<10 ms` online enforcement SLA:
1. Online `SymbolicGovernor` emits structured JSON `RefusalReceipt` and `ATIFTrajectory`
   records to Cloud Logging, which routes them via Log Sinks into partitioned
   BigQuery tables.
2. `BigQueryTrajectoryHarvester` queries BigQuery asynchronously using strictly
   parameterized queries (`ScalarQueryParameter` — zero SQL string interpolation
   of filter values) to:
   - Reconstruct and verify `RefusalReceipt` records (`verify_proof_hash()`) and
     feed `FoundationModelEvalHarness.harvest_refusal_receipts()` for DPO/RLVR export.
   - Harvest Eval-Prod Drift trajectories where a certified skill failed in
     production and convert them into new negative `AnchorItem(golden_passed=False)`
     records for the next offline evaluation cycle.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.eval_harness.harness import (
    AnchorItem,
    ATIFTrajectory,
    DPOPreferenceTriplet,
    FoundationModelEvalHarness,
    SkillEvalCase,
    SkillPromptBucket,
    TrajectoryHarvesterProtocol,
)
from src.gateway.governance.contracts import GovernanceTierFailure, RefusalReceipt
from src.gateway.governance.pii_sanitizer import PIISanitizer

logger = logging.getLogger("cage.integrations.gcp_eval.bq_harvester")

_BQ_TABLE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")


def _validate_bq_table_fqn(table_fqn: str) -> str:
    """Validate `project.dataset.table` identifier against SQL injection."""
    cleaned = table_fqn.strip()
    if not _BQ_TABLE_ID_RE.fullmatch(cleaned):
        raise ValueError(
            f"Invalid BigQuery table FQN {table_fqn!r}: must match 'project.dataset.table'"
        )
    return cleaned


@dataclass(frozen=True)
class BigQueryQuerySpec:
    """Parameterized BigQuery query specification for auditability and testing."""

    sql: str
    parameters: tuple[tuple[str, str, Any], ...]


@dataclass(frozen=True)
class LossClusterRecord:
    """Semantic failure cluster surfaced by GEAP `client.evals.generate_loss_clusters` or Online Monitors."""

    cluster_id: str
    title: str
    description: str
    theme: str
    sample_count: int
    avg_score: float
    representative_trajectories: tuple[ATIFTrajectory, ...] = ()


class BigQueryTrajectoryHarvester(TrajectoryHarvesterProtocol):
    """Harvests `RefusalReceipt`, Eval-Prod Drift, and GEAP `LossClusterRecord` anchors from BigQuery."""

    def __init__(
        self,
        *,
        refusal_table_fqn: str = "cage-prod.cage_telemetry.refusal_receipts",
        trajectory_table_fqn: str = "cage-prod.cage_telemetry.atif_trajectories",
        loss_cluster_table_fqn: str = "cage-prod.cage_telemetry.eval_loss_clusters",
        bq_client: Any = None,
        project_id: str | None = None,
    ) -> None:
        self._refusal_table = _validate_bq_table_fqn(refusal_table_fqn)
        self._trajectory_table = _validate_bq_table_fqn(trajectory_table_fqn)
        self._loss_cluster_table = _validate_bq_table_fqn(loss_cluster_table_fqn)
        self._bq_client = bq_client
        self._project_id = project_id
        self._sanitizer = PIISanitizer()
        self._executed_queries: list[BigQueryQuerySpec] = []

    @property
    def executed_queries(self) -> tuple[BigQueryQuerySpec, ...]:
        return tuple(self._executed_queries)

    def _get_client(self) -> Any:
        if self._bq_client is not None:
            return self._bq_client
        try:
            from google.cloud import bigquery  # type: ignore[import,attr-defined]
        except ImportError as exc:
            raise RuntimeError(
                "google-cloud-bigquery is required for BigQueryTrajectoryHarvester"
            ) from exc
        self._bq_client = bigquery.Client(project=self._project_id)
        return self._bq_client

    def _execute_parameterized_query(
        self,
        sql: str,
        params: Sequence[tuple[str, str, Any]],
    ) -> Sequence[Mapping[str, Any]]:
        spec = BigQueryQuerySpec(sql=sql, parameters=tuple(params))
        self._executed_queries.append(spec)
        client = self._get_client()

        try:
            from google.cloud import bigquery  # type: ignore[import,attr-defined]

            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter(name, bq_type, val)
                    for name, bq_type, val in params
                ]
            )
            query_job = client.query(sql, job_config=job_config)
        except ImportError:
            query_job = client.query(sql, parameters=list(params))

        rows = query_job.result() if hasattr(query_job, "result") else query_job
        return [dict(r) for r in rows]

    @staticmethod
    def _parse_json_column(val: Any) -> Any:
        if isinstance(val, str) and val.strip():
            return json.loads(val)
        return val

    async def fetch_refusal_receipts(
        self,
        *,
        since_iso: str,
        limit: int = 500,
    ) -> Sequence[RefusalReceipt]:
        """Fetch and cryptographically verify `RefusalReceipt` rows from BigQuery."""
        if limit <= 0 or limit > 10_000:
            raise ValueError("limit must be between 1 and 10,000")

        # Table identifier is strictly validated by _BQ_TABLE_ID_RE in __init__;
        # all runtime filter values use @since_iso and @row_limit query parameters.
        sql_template = (
            "SELECT thread_id, action, violated_tier, violated_rule, "
            "standing_at_refusal, timestamp, proof_hash, schema_version, "
            "attempted_params, standing_snapshot, control_id, "
            "protected_consequence, non_formation_proof, tier_failures, reliance "
            "FROM `__TABLE_FQN__` "
            "WHERE emitted_at >= @since_iso "
            "ORDER BY emitted_at DESC "
            "LIMIT @row_limit"
        )
        sql = sql_template.replace("__TABLE_FQN__", self._refusal_table)
        rows = self._execute_parameterized_query(
            sql,
            [
                ("since_iso", "STRING", str(since_iso)),
                ("row_limit", "INT64", int(limit)),
            ],
        )

        receipts: list[RefusalReceipt] = []
        for row in rows:
            raw_failures = self._parse_json_column(row.get("tier_failures")) or ()
            tier_failures = tuple(
                GovernanceTierFailure(
                    tier=str(tf.get("tier", "")),
                    control_id=str(tf.get("control_id", "")),
                    rule_description=str(tf.get("rule_description", "")),
                    governing_state=dict(tf.get("governing_state") or {}),
                    protected_consequence=str(tf.get("protected_consequence", "")),
                )
                for tf in raw_failures
                if isinstance(tf, Mapping)
            )
            raw_reliance = self._parse_json_column(row.get("reliance")) or ()
            reliance = tuple(dict(r) for r in raw_reliance if isinstance(r, Mapping))
            receipt = RefusalReceipt(
                thread_id=str(row["thread_id"]),
                action=str(row["action"]),
                violated_tier=str(row["violated_tier"]),
                violated_rule=str(row["violated_rule"]),
                standing_at_refusal=dict(
                    self._parse_json_column(row.get("standing_at_refusal")) or {}
                ),
                timestamp=float(row["timestamp"]),
                proof_hash=str(row["proof_hash"]),
                schema_version=str(row.get("schema_version", "v3")),
                attempted_params=dict(
                    self._parse_json_column(row.get("attempted_params")) or {}
                ),
                standing_snapshot=dict(
                    self._parse_json_column(row.get("standing_snapshot")) or {}
                ),
                control_id=str(row.get("control_id", "")),
                protected_consequence=str(row.get("protected_consequence", "")),
                non_formation_proof=str(row.get("non_formation_proof", "")),
                tier_failures=tier_failures,
                reliance=reliance,
            )
            if not receipt.verify_proof_hash():
                raise ValueError(
                    f"Tampered BigQuery RefusalReceipt detected for thread_id={receipt.thread_id!r}"
                )
            receipts.append(receipt)
        return tuple(receipts)

    async def fetch_eval_prod_drift_anchors(
        self,
        *,
        skill_name: str,
        since_iso: str,
        limit: int = 100,
    ) -> Sequence[AnchorItem]:
        """Harvest production failure trajectories for `skill_name` as negative Golden Anchors."""
        if limit <= 0 or limit > 5_000:
            raise ValueError("limit must be between 1 and 5,000")

        # Table identifier is strictly validated by _BQ_TABLE_ID_RE in __init__;
        # all runtime filter values use @skill_name, @since_iso, @row_limit parameters.
        sql_template = (
            "SELECT trajectory_id, skill_name, bucket, prompt, "
            "expected_script, forbidden_tools, required_output_tokens, "
            "atif_payload "
            "FROM `__TABLE_FQN__` "
            "WHERE skill_name = @skill_name "
            "AND production_failed = TRUE "
            "AND emitted_at >= @since_iso "
            "ORDER BY emitted_at DESC "
            "LIMIT @row_limit"
        )
        sql = sql_template.replace("__TABLE_FQN__", self._trajectory_table)
        rows = self._execute_parameterized_query(
            sql,
            [
                ("skill_name", "STRING", str(skill_name)),
                ("since_iso", "STRING", str(since_iso)),
                ("row_limit", "INT64", int(limit)),
            ],
        )

        anchors: list[AnchorItem] = []
        for idx, row in enumerate(rows, start=1):
            raw_atif = self._parse_json_column(row["atif_payload"])
            sanitized_atif = self._sanitizer.sanitize_dict(dict(raw_atif))
            trajectory = ATIFTrajectory.from_dict(sanitized_atif)
            bucket_str = str(row.get("bucket", "explicit")).lower()
            case = SkillEvalCase(
                case_id=f"drift-{skill_name}-{idx:04d}",
                bucket=SkillPromptBucket(bucket_str),
                prompt=self._sanitizer.sanitize(
                    str(row.get("prompt") or trajectory.prompt)
                ),
                expected_skill=skill_name,
                expected_script=(
                    str(row["expected_script"])
                    if row.get("expected_script") is not None
                    else None
                ),
                forbidden_tools=tuple(
                    str(t)
                    for t in (self._parse_json_column(row.get("forbidden_tools")) or ())
                ),
                required_output_tokens=tuple(
                    str(t)
                    for t in (
                        self._parse_json_column(row.get("required_output_tokens")) or ()
                    )
                ),
            )
            anchors.append(
                AnchorItem(
                    item_id=f"prod-drift-{trajectory.trajectory_id}",
                    case=case,
                    trajectory=trajectory,
                    golden_passed=False,
                )
            )
        return tuple(anchors)

    async def harvest_loss_clusters_to_anchors(
        self,
        *,
        skill_name: str,
        eval_result_name: str | None = None,
        evals_client: Any = None,
        max_avg_score: float = 3.0,
        limit: int = 100,
    ) -> tuple[tuple[LossClusterRecord, ...], tuple[AnchorItem, ...]]:
        """Harvest GEAP Failure Clusters (`generate_loss_clusters` or BigQuery) into negative Golden Anchors.

        Supports both:
        1. Direct GEAP SDK objects/mappings returned by ``evals_client.generate_loss_clusters(src=eval_result_name)``
           (GEAP Tour Slide 28: ``cluster.title``, ``cluster.description``, ``cluster.sample_count``,
           ``cluster.avg_score``, ``cluster.representative_examples``).
        2. Parameterized BigQuery queries over the 10-minute Online Monitor loss cluster sink table.
        """
        if limit <= 0 or limit > 5_000:
            raise ValueError("limit must be between 1 and 5,000")

        raw_clusters: list[Any] = []
        if evals_client is not None:
            if not eval_result_name or not str(eval_result_name).strip():
                raise ValueError(
                    "eval_result_name is required when evals_client is provided"
                )
            gen_fn = getattr(evals_client, "generate_loss_clusters", None)
            if gen_fn is None and hasattr(evals_client, "evals"):
                gen_fn = getattr(evals_client.evals, "generate_loss_clusters", None)
            if not callable(gen_fn):
                raise ValueError(
                    "evals_client must expose generate_loss_clusters(src=...)"
                )
            raw_clusters = list(gen_fn(src=str(eval_result_name).strip()))
        else:
            sql_template = (
                "SELECT cluster_id, title, description, theme, sample_count, "
                "avg_score, representative_examples "
                "FROM `__TABLE_FQN__` "
                "WHERE skill_name = @skill_name "
                "AND avg_score < @max_avg_score "
                "ORDER BY sample_count DESC, avg_score ASC "
                "LIMIT @row_limit"
            )
            sql = sql_template.replace("__TABLE_FQN__", self._loss_cluster_table)
            raw_clusters = list(
                self._execute_parameterized_query(
                    sql,
                    [
                        ("skill_name", "STRING", str(skill_name)),
                        ("max_avg_score", "FLOAT64", float(max_avg_score)),
                        ("row_limit", "INT64", int(limit)),
                    ],
                )
            )

        clusters: list[LossClusterRecord] = []
        anchors: list[AnchorItem] = []

        for c_idx, raw in enumerate(raw_clusters, start=1):
            if isinstance(raw, Mapping):
                c_id = str(raw.get("cluster_id") or f"cluster-{c_idx:04d}")
                title = self._sanitizer.sanitize(
                    str(raw.get("title") or "Untitled Cluster")
                )
                desc = self._sanitizer.sanitize(str(raw.get("description") or ""))
                theme = str(raw.get("theme") or "policy_violation")
                sample_count = int(raw.get("sample_count", 1))
                avg_score = float(raw.get("avg_score", 0.0))
                rep_raw = self._parse_json_column(
                    raw.get("representative_examples")
                    or raw.get("representative_trajectories")
                    or ()
                )
            else:
                c_id = str(getattr(raw, "cluster_id", None) or f"cluster-{c_idx:04d}")
                title = self._sanitizer.sanitize(
                    str(getattr(raw, "title", "Untitled Cluster"))
                )
                desc = self._sanitizer.sanitize(str(getattr(raw, "description", "")))
                theme = str(getattr(raw, "theme", "policy_violation"))
                sample_count = int(getattr(raw, "sample_count", 1))
                avg_score = float(getattr(raw, "avg_score", 0.0))
                rep_raw = (
                    getattr(raw, "representative_examples", None)
                    or getattr(raw, "representative_trajectories", None)
                    or ()
                )

            if avg_score >= max_avg_score:
                continue

            rep_trajs: list[ATIFTrajectory] = []
            for ex_idx, ex in enumerate(rep_raw, start=1):
                if isinstance(ex, ATIFTrajectory):
                    sanitized_dict = self._sanitizer.sanitize_dict(ex.to_dict())
                    traj = ATIFTrajectory.from_dict(sanitized_dict)
                    forbidden: tuple[str, ...] = ()
                    req_tokens: tuple[str, ...] = ()
                    bucket_str = "explicit"
                elif isinstance(ex, Mapping):
                    raw_traj = ex.get("trajectory") or ex.get("atif_payload") or ex
                    sanitized_dict = self._sanitizer.sanitize_dict(dict(raw_traj))
                    traj = ATIFTrajectory.from_dict(sanitized_dict)
                    forbidden = tuple(str(t) for t in (ex.get("forbidden_tools") or ()))
                    req_tokens = tuple(
                        str(t) for t in (ex.get("required_output_tokens") or ())
                    )
                    bucket_str = str(ex.get("bucket", "explicit")).lower()
                else:
                    continue

                rep_trajs.append(traj)
                case = SkillEvalCase(
                    case_id=f"cluster-{c_id}-ex-{ex_idx:02d}",
                    bucket=SkillPromptBucket(bucket_str),
                    prompt=self._sanitizer.sanitize(traj.prompt or title),
                    expected_skill=skill_name,
                    forbidden_tools=forbidden,
                    required_output_tokens=req_tokens,
                )
                anchors.append(
                    AnchorItem(
                        item_id=f"loss-cluster-{c_id}-{traj.trajectory_id}",
                        case=case,
                        trajectory=traj,
                        golden_passed=False,
                    )
                )

            clusters.append(
                LossClusterRecord(
                    cluster_id=c_id,
                    title=title,
                    description=desc,
                    theme=theme,
                    sample_count=sample_count,
                    avg_score=avg_score,
                    representative_trajectories=tuple(rep_trajs),
                )
            )

        return tuple(clusters), tuple(anchors)

    async def harvest_and_export_dpo_dataset(
        self,
        harness: FoundationModelEvalHarness,
        *,
        since_iso: str,
        output_path: Path,
        limit: int = 500,
        trust_receipt_standing: bool = True,
    ) -> list[DPOPreferenceTriplet]:
        """Fetch verified `RefusalReceipt` rows from BigQuery and export PII-sanitized DPO JSONL."""
        receipts = await self.fetch_refusal_receipts(since_iso=since_iso, limit=limit)
        triplets = await harness.harvest_refusal_receipts(
            receipts,
            verify_receipt_hash=True,
            trust_receipt_standing=trust_receipt_standing,
        )
        FoundationModelEvalHarness.export_hf_trl_jsonl(
            triplets,
            output_path,
            sanitize_pii=True,
        )
        return triplets


__all__ = [
    "BigQueryQuerySpec",
    "BigQueryTrajectoryHarvester",
    "LossClusterRecord",
]
