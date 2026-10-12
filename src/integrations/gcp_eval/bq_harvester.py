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


class BigQueryTrajectoryHarvester(TrajectoryHarvesterProtocol):
    """Harvests `RefusalReceipt` and Eval-Prod Drift `AnchorItem` records from BigQuery."""

    def __init__(
        self,
        *,
        refusal_table_fqn: str = "cage-prod.cage_telemetry.refusal_receipts",
        trajectory_table_fqn: str = "cage-prod.cage_telemetry.atif_trajectories",
        bq_client: Any = None,
        project_id: str | None = None,
    ) -> None:
        self._refusal_table = _validate_bq_table_fqn(refusal_table_fqn)
        self._trajectory_table = _validate_bq_table_fqn(trajectory_table_fqn)
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
            from google.cloud import bigquery  # type: ignore[import]
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
            from google.cloud import bigquery  # type: ignore[import]

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
            reliance = tuple(
                dict(r) for r in raw_reliance if isinstance(r, Mapping)
            )
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
                        self._parse_json_column(row.get("required_output_tokens"))
                        or ()
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

    async def harvest_and_export_dpo_dataset(
        self,
        harness: FoundationModelEvalHarness,
        *,
        since_iso: str,
        output_path: Path,
        limit: int = 500,
    ) -> list[DPOPreferenceTriplet]:
        """Fetch verified `RefusalReceipt` rows from BigQuery and export PII-sanitized DPO JSONL."""
        receipts = await self.fetch_refusal_receipts(since_iso=since_iso, limit=limit)
        triplets = await harness.harvest_refusal_receipts(
            receipts,
            verify_receipt_hash=True,
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
]
