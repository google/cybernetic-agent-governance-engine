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
test_evidence_consumer.py — Evidence Stream consumer tests.

Validation Criteria:
    V-2: Metrics derive from Evidence Stream only (zero Langfuse dependency)
    V-3: All Lula gates call get_compliance_metrics from evidence
"""

import pytest


@pytest.mark.asyncio
@pytest.mark.local
async def test_consumer_aggregates_windowed_metrics():
    """Verify minute-bucketed counters aggregate correctly."""
    from datetime import datetime, timezone

    from src.compliance_bridge.evidence_consumer import EvidenceStreamConsumer

    consumer = EvidenceStreamConsumer()

    # Simulate processing a record
    control_id = "A.5.2"
    minute_bucket = int(datetime.now(timezone.utc).timestamp() // 60)

    # Manually update metrics (simulating record processing)
    bucket = consumer._metrics[control_id][minute_bucket]
    bucket["total"] += 1
    bucket["allowed"] += 1

    # Verify aggregation
    metrics = consumer.get_compliance_metrics(control_id, window_hours=1)

    assert metrics["control_id"] == control_id
    assert metrics["total_traces"] >= 1
    assert metrics["source"] == "evidence_stream"  # V-2: Not Langfuse!


@pytest.mark.asyncio
@pytest.mark.local
async def test_get_compliance_metrics_without_langfuse():
    """Verify metrics derive from Evidence Stream only (V-2)."""
    from src.compliance_bridge.evidence_consumer import get_evidence_consumer

    consumer = get_evidence_consumer()

    # Get metrics for a control (no data yet)
    metrics = consumer.get_compliance_metrics("A.5.2", window_hours=24)

    # Should return valid structure even with no data
    assert "control_id" in metrics
    assert "source" in metrics
    assert metrics["source"] == "evidence_stream"  # V-2!
    assert "evidence_chain_verified" in metrics
    assert "chain_head_hash" in metrics

    # Should NOT have Langfuse-specific fields
    assert "langfuse_project" not in metrics


@pytest.mark.asyncio
@pytest.mark.local
async def test_chain_verification_on_startup():
    """Verify consumer validates hash chain continuity on startup."""
    from src.compliance_bridge.evidence_consumer import EvidenceStreamConsumer

    consumer = EvidenceStreamConsumer()

    # Before start, chain not verified
    assert consumer.chain_verified is False

    # Note: Full verification requires Redis; test validates initial state


@pytest.mark.local
def test_safety_rate_calculation():
    """Verify safety_rate calculation from allowed/total counters."""
    from datetime import datetime, timezone

    from src.compliance_bridge.evidence_consumer import EvidenceStreamConsumer

    consumer = EvidenceStreamConsumer()

    control_id = "A.5.3"
    minute_bucket = int(datetime.now(timezone.utc).timestamp() // 60)

    # Simulate 8 allowed, 2 denied
    bucket = consumer._metrics[control_id][minute_bucket]
    bucket["total"] = 10
    bucket["allowed"] = 8
    bucket["denied"] = 2

    metrics = consumer.get_compliance_metrics(control_id, window_hours=1)

    assert metrics["total_traces"] == 10
    assert metrics["blocked_traces"] == 2
    assert metrics["safety_rate"] == 0.8  # 8/10


@pytest.mark.local
def test_startup_grace_period():
    """Verify startup_grace_active flag when no evidence yet."""
    from src.compliance_bridge.evidence_consumer import EvidenceStreamConsumer

    consumer = EvidenceStreamConsumer()

    # No data yet
    metrics = consumer.get_compliance_metrics("A.5.2", window_hours=24)

    # Should be in startup grace (no data)
    assert metrics["total_traces"] == 0
    assert metrics["startup_grace_active"] is True
    assert metrics["safety_rate"] is None


@pytest.mark.local
def test_evidence_age_calculation():
    """Verify evidence_age_seconds tracks time since last record."""
    import time
    from datetime import datetime, timezone

    from src.compliance_bridge.evidence_consumer import EvidenceStreamConsumer

    consumer = EvidenceStreamConsumer()

    control_id = "A.5.4"
    now = datetime.now(timezone.utc)
    minute_bucket = int(now.timestamp() // 60)

    # Add a record
    bucket = consumer._metrics[control_id][minute_bucket]
    bucket["total"] = 1
    bucket["allowed"] = 1

    # Get metrics
    metrics = consumer.get_compliance_metrics(control_id, window_hours=1)

    # Evidence age should be recent (< 60 seconds since we just added to current minute)
    assert metrics["evidence_age_seconds"] >= 0
    assert metrics["evidence_age_seconds"] < 60


@pytest.mark.local
def test_consumer_singleton():
    """Verify get_evidence_consumer returns singleton instance."""
    from src.compliance_bridge.evidence_consumer import get_evidence_consumer

    consumer1 = get_evidence_consumer()
    consumer2 = get_evidence_consumer()

    assert consumer1 is consumer2


@pytest.mark.local
def test_metrics_dict_structure():
    """Verify compliance metrics dict matches ComplianceMetrics schema."""
    from src.compliance_bridge.evidence_consumer import EvidenceStreamConsumer

    consumer = EvidenceStreamConsumer()
    metrics = consumer.get_compliance_metrics("A.5.2", window_hours=24)

    # Required fields
    assert "control_id" in metrics
    assert "safety_rate" in metrics
    assert "total_traces" in metrics
    assert "blocked_traces" in metrics
    assert "evidence_age_seconds" in metrics
    assert "startup_grace_active" in metrics

    # V-2: Evidence Stream source fields
    assert "source" in metrics
    assert metrics["source"] == "evidence_stream"
    assert "evidence_chain_verified" in metrics
    assert "chain_head_hash" in metrics
