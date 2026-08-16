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

"""Confabulation scorer — AI 600-1 §2.1 control.

Records low-confidence events to Langfuse for audit purposes.
Implements CTRL_AGT_001: confidence ≥ CONFIDENCE_MIN_SCORE threshold.

POAM: AI600-001
Region: US_FED (CAGE_DEPLOYMENT_REGION=US_FED)

Usage::

    from src.gateway.governance.confabulation_scorer import (
        ConfabulationEvent, score_confabulation
    )

    event = ConfabulationEvent(
        trace_id="trace-123",
        confidence=0.87,
        model_id="deepseek-r1",
        grounding_source="market_data_api",
        blocked=True,
    )
    payload = score_confabulation(event)
    # → {"name": "confabulation_risk", "value": 0.13, ...}
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger("Gateway.Governance.ConfabulationScorer")

# ---------------------------------------------------------------------------
# EV-5 Migration: Threshold is now sourced from config/governance_thresholds.json
# with environment variable override (CONFIDENCE_MIN_SCORE) supported.
# See schemas/thresholds.py for details.
#
# The env var override is still supported for production deployments that set
# CONFIDENCE_MIN_SCORE via secretKeyRef from advisor-secrets.
# ---------------------------------------------------------------------------
from src.gateway.governance.schemas.thresholds import get_confidence_min_score

CONFIDENCE_THRESHOLD: float = get_confidence_min_score()


# ---------------------------------------------------------------------------
# ConfabulationEvent — structured event for Langfuse scoring
# ---------------------------------------------------------------------------


@dataclass
class ConfabulationEvent:
    """Structured confabulation event for Langfuse audit scoring.

    Attributes:
        trace_id:         Langfuse trace ID for the governed request.
        confidence:       Model self-reported confidence score [0.0, 1.0].
        model_id:         Model identifier (e.g. "deepseek-r1-distill-qwen-14b").
        grounding_source: Optional grounding API used (e.g. "market_data_api").
        blocked:          True if the request was blocked due to low confidence.
    """

    trace_id: str
    confidence: float
    model_id: str
    grounding_source: str | None
    blocked: bool


# ---------------------------------------------------------------------------
# score_confabulation — Langfuse score payload builder
# ---------------------------------------------------------------------------


def score_confabulation(event: ConfabulationEvent) -> dict:
    """Return a Langfuse score payload for confabulation risk.

    The score value is ``1.0 - confidence``, so a confidence of 0.95 yields
    a confabulation risk score of 0.05 (low risk), and a confidence of 0.50
    yields a score of 0.50 (high risk).

    Args:
        event: A ``ConfabulationEvent`` describing the low-confidence response.

    Returns:
        A dict suitable for submission to the Langfuse ``/api/public/scores``
        endpoint.  Schema:
        {
            "name": "confabulation_risk",
            "value": float,          # 1.0 - confidence
            "comment": str,          # human-readable summary
            "trace_id": str,         # Langfuse trace ID
            "data_type": "NUMERIC",
        }
    """
    risk_score = 1.0 - event.confidence
    comment = (
        f"confidence={event.confidence:.3f} "
        f"threshold={CONFIDENCE_THRESHOLD:.3f} "
        f"model={event.model_id} "
        f"blocked={event.blocked}"
    )
    if event.grounding_source:
        comment += f" grounding={event.grounding_source}"

    payload = {
        "name": "confabulation_risk",
        "value": risk_score,
        "comment": comment,
        "trace_id": event.trace_id,
        "data_type": "NUMERIC",
    }

    if event.blocked:
        logger.warning(
            "🚨 Confabulation event blocked: trace_id=%s confidence=%.3f "
            "threshold=%.3f model=%s",
            event.trace_id,
            event.confidence,
            CONFIDENCE_THRESHOLD,
            event.model_id,
        )
    else:
        logger.debug(
            "Confabulation event scored: trace_id=%s confidence=%.3f risk=%.3f",
            event.trace_id,
            event.confidence,
            risk_score,
        )

    return payload


def is_confabulation_blocked(confidence: float) -> bool:
    """Return True if the given confidence score triggers a confabulation block.

    Args:
        confidence: Model self-reported confidence score [0.0, 1.0].

    Returns:
        True if ``confidence < CONFIDENCE_THRESHOLD``, False otherwise.
    """
    return confidence < CONFIDENCE_THRESHOLD
