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

"""
PolicyLoader — fetches STAMP/STPA hazard YAML specifications from storage.

Uses the storage abstraction layer (``get_storage_backend()``) so that any
configured backend (GCS, S3, local) can serve policy files — no direct GCS SDK
dependency here.
"""

import logging
from typing import Any

import yaml

from src.governed_financial_advisor.infrastructure.storage import get_storage_backend

logger = logging.getLogger("governance.policy_loader")

# ---------------------------------------------------------------------------
# H-12: Schema validation for YAML policy files
# ---------------------------------------------------------------------------

# Required top-level keys for a valid STAMP hazard policy file.
# Each hazard entry must also contain these keys.
REQUIRED_POLICY_KEYS: frozenset[str] = frozenset({"hazards"})
REQUIRED_HAZARD_KEYS: frozenset[str] = frozenset({"id", "description"})


class PolicySchemaError(ValueError):
    """Raised when a downloaded policy YAML does not conform to the expected schema.

    Prevents malformed or tampered policy files from silently altering governance
    behaviour (H-12).
    """


def _validate_policy_schema(data: Any, blob_name: str) -> None:
    """Validate *data* against the STAMP hazard policy schema.

    Args:
        data:      Parsed YAML object (expected to be a dict).
        blob_name: Source path — used in error messages only.

    Raises:
        PolicySchemaError: If the top-level structure or any hazard entry is invalid.
    """
    if not isinstance(data, dict):
        raise PolicySchemaError(
            f"Policy file {blob_name!r} must be a YAML mapping at the top level, "
            f"got {type(data).__name__}"
        )

    missing_keys = REQUIRED_POLICY_KEYS - data.keys()
    if missing_keys:
        raise PolicySchemaError(
            f"Policy file {blob_name!r} is missing required top-level keys: "
            f"{sorted(missing_keys)}"
        )

    hazards = data.get("hazards", [])
    if not isinstance(hazards, list):
        raise PolicySchemaError(
            f"Policy file {blob_name!r}: 'hazards' must be a list, "
            f"got {type(hazards).__name__}"
        )

    for i, hazard in enumerate(hazards):
        if not isinstance(hazard, dict):
            raise PolicySchemaError(
                f"Policy file {blob_name!r}: hazard[{i}] must be a mapping, "
                f"got {type(hazard).__name__}"
            )
        missing_hazard_keys = REQUIRED_HAZARD_KEYS - hazard.keys()
        if missing_hazard_keys:
            raise PolicySchemaError(
                f"Policy file {blob_name!r}: hazard[{i}] is missing required keys: "
                f"{sorted(missing_hazard_keys)}"
            )

    logger.debug(
        "policy_loader: schema validation passed for %s (%d hazards)",
        blob_name,
        len(hazards),
    )


class PolicyLoader:
    """Loads STAMP hazard specifications via the configured storage backend."""

    def __init__(self, bucket_name: str) -> None:
        self.bucket_name = bucket_name
        # get_storage_backend honours STORAGE_BACKEND env var; it may raise
        # RuntimeError / ImportError if the required SDK is unavailable.
        self._backend = get_storage_backend(bucket_name=bucket_name)

    def load_stamp_hazards(self, blob_name: str) -> list[Any]:
        """Download and parse a STAMP hazard YAML from storage.

        Validates the parsed YAML against the STAMP hazard schema before
        returning (H-12).  Raises ``PolicySchemaError`` if the file does not
        conform — callers must handle this to prevent silent governance bypass.

        Args:
            blob_name: Path to the YAML file within the bucket / prefix root.

        Returns:
            List of hazard dicts parsed from the YAML ``hazards`` key.

        Raises:
            PolicySchemaError: If the YAML structure is invalid.
        """
        raw_yaml = self._backend.read_text(blob_name)
        data = yaml.safe_load(raw_yaml)

        # H-12: Validate schema before trusting any content from remote storage.
        _validate_policy_schema(data, blob_name)

        hazards: list[Any] = data.get("hazards", [])
        logger.info(
            "Loaded %d STAMP hazards from %s/%s",
            len(hazards),
            self.bucket_name,
            blob_name,
        )
        return hazards


# ---------------------------------------------------------------------------
# ISO-001 / ISO 42001 §A.4 — Redis Token Quota Snapshot
# ---------------------------------------------------------------------------
# Injects live Redis token quota counters into the OPA input document so that
# trade_governance.rego can gate decisions based on remaining inference budget.
#
# Architecture:
#   - TokenQuotaProxy writes per-agent token counters to Redis db=2 using
#     the key pattern: cage:quota:{agent_id}:tokens_used (int)
#   - This helper reads those counters and returns a snapshot dict that callers
#     merge into the OPA input document before policy evaluation.
#   - On Redis unavailability, behaviour is governed by REDIS_QUOTA_FAIL_CLOSED:
#       True  → raises RuntimeError (fail-closed; all trades require MANUAL_REVIEW)
#       False → returns a degraded snapshot with quota_available=True (fail-open)
#   - Default: fail-OPEN to avoid false positives in dev/CI (ISO-001 CTRL_TQP_007
#     records the fail-closed posture at the sidecar level).
#
# POAM: ISO-001 (POAM_ISO42001.md §A.4)
# Related: CTRL_TQP_007 (lula-validation-tqp007.yaml), H-7 STPA hazard
# ---------------------------------------------------------------------------

import os as _os

_REDIS_QUOTA_FAIL_CLOSED: bool = (
    _os.getenv("REDIS_QUOTA_FAIL_CLOSED", "false").lower() == "true"
)
_REDIS_QUOTA_DB: int = 2  # db=2 reserved for TokenQuotaProxy counters
_REDIS_QUOTA_KEY_PREFIX: str = "cage:quota"
_DEFAULT_TOKEN_BUDGET: int = 100_000  # tokens per agent per window


def get_redis_quota_snapshot(
    agent_id: str,
    *,
    redis_url: str | None = None,
    token_budget: int = _DEFAULT_TOKEN_BUDGET,
    min_reserve_fraction: float = 0.05,
) -> dict:
    """Read live token quota counters from Redis and return an OPA input snapshot.

    The returned dict is suitable for merging into an existing OPA input document
    under the ``token_quota`` key::

        opa_input = {
            "action": "execute_trade",
            "amount": 5000,
            "trader_role": "junior",
            **get_redis_quota_snapshot("financial-advisor"),
        }
        # → opa_input["token_quota"]["remaining_tokens"] is populated

    On Redis unavailability the function either:
    - **Fails-open** (default, REDIS_QUOTA_FAIL_CLOSED=false): returns a degraded
      snapshot with ``quota_available=True`` and a warning. Governance continues.
    - **Fails-closed** (REDIS_QUOTA_FAIL_CLOSED=true): raises RuntimeError.
      The OPA caller should catch this and return ``MANUAL_REVIEW``.

    Args:
        agent_id:              Agent identifier — must match the TokenQuotaProxy
                               counter key pattern ``cage:quota:{agent_id}:*``.
        redis_url:             Redis connection URL. Defaults to the ``REDIS_URL``
                               environment variable, or the in-cluster default.
        token_budget:          Per-window token budget (default: 100,000 tokens).
        min_reserve_fraction:  Fraction of budget that must remain before the
                               policy downgrades to MANUAL_REVIEW (default: 5%).

    Returns:
        Dict with a single top-level key ``token_quota`` containing:
        - ``agent_id``           — echoed from caller
        - ``tokens_used``        — counter from Redis (int)
        - ``token_budget``       — configured budget (int)
        - ``remaining_tokens``   — budget - tokens_used (int)
        - ``quota_exhausted``    — True if remaining_tokens <= 0
        - ``below_min_reserve``  — True if remaining < min_reserve_fraction * budget
        - ``quota_available``    — True if quota data was read successfully
        - ``quota_source``       — "redis" | "degraded" (for OTel attribution)

    Raises:
        RuntimeError: Only when REDIS_QUOTA_FAIL_CLOSED=true and Redis is
                      unreachable. Callers should treat this as MANUAL_REVIEW.
    """
    _url = redis_url or _os.getenv(
        "REDIS_URL",
        "redis://redis-stack.governance-stack.svc.cluster.local:6379",
    )
    key = f"{_REDIS_QUOTA_KEY_PREFIX}:{agent_id}:tokens_used"
    min_reserve = int(min_reserve_fraction * token_budget)

    try:
        # Lazy import to avoid mandatory redis dependency in non-quota code paths.
        import redis as _redis_lib  # type: ignore[import-untyped]

        client = _redis_lib.from_url(
            _url,  # type: ignore[arg-type]
            db=_REDIS_QUOTA_DB,
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=True,
        )
        raw = client.get(key)
        tokens_used = int(raw) if raw is not None else 0  # type: ignore[arg-type]
        remaining = token_budget - tokens_used

        quota_snapshot = {
            "agent_id": agent_id,
            "tokens_used": tokens_used,
            "token_budget": token_budget,
            "remaining_tokens": remaining,
            "quota_exhausted": remaining <= 0,
            "below_min_reserve": remaining < min_reserve,
            "quota_available": True,
            "quota_source": "redis",
        }
        logger.debug(
            "[ISO-001] Token quota snapshot for agent=%s: used=%d budget=%d remaining=%d",
            agent_id,
            tokens_used,
            token_budget,
            remaining,
        )
        return {"token_quota": quota_snapshot}

    except Exception as exc:
        logger.warning(
            "[ISO-001] Redis token quota unavailable for agent=%s (%s: %s). "
            "REDIS_QUOTA_FAIL_CLOSED=%s",
            agent_id,
            type(exc).__name__,
            exc,
            _REDIS_QUOTA_FAIL_CLOSED,
        )
        if _REDIS_QUOTA_FAIL_CLOSED:
            raise RuntimeError(
                f"[ISO-001] Redis quota unavailable for agent={agent_id!r} "
                f"and REDIS_QUOTA_FAIL_CLOSED=true — failing closed. "
                f"Governance: treat as MANUAL_REVIEW."
            ) from exc

        # Fail-open: return degraded snapshot
        return {
            "token_quota": {
                "agent_id": agent_id,
                "tokens_used": 0,
                "token_budget": token_budget,
                "remaining_tokens": token_budget,
                "quota_exhausted": False,
                "below_min_reserve": False,
                "quota_available": False,  # signals degraded mode to OPA
                "quota_source": "degraded",
            }
        }


def with_redis_quota(
    opa_input: dict[str, Any],
    agent_id: str,
    **quota_kwargs: Any,
) -> dict[str, Any]:
    """Merge a live Redis token quota snapshot into an existing OPA input dict.

    Convenience wrapper around ``get_redis_quota_snapshot()`` for single-call
    OPA input enrichment. Returns a new dict (does not mutate the original).

    Example::

        opa_input = with_redis_quota(
            {"action": "execute_trade", "amount": 5000, "trader_role": "junior"},
            agent_id="financial-advisor",
        )
        # opa_input["token_quota"]["remaining_tokens"] is now populated

    On fail-closed RuntimeError, the caller receives the exception unmodified.
    """
    snapshot = get_redis_quota_snapshot(agent_id, **quota_kwargs)
    return {**opa_input, **snapshot}
