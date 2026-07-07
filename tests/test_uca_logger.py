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

# tests/test_uca_logger.py
# Unit tests for UCALogger ISO 42001 Clause 6.1 compliance records.
# Marker: @pytest.mark.local — CI-gated, no external dependencies.
# Run: uv run pytest tests/test_uca_logger.py -m local -v

import os
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required")
import fakeredis.aioredis

from src.gateway.governance.pii_sanitizer import PIISanitizer
from src.gateway.governance.token_quota_proxy import QuotaCheckResult


def _mock_quota_result(step_count=13, block_reason="step_count"):
    return QuotaCheckResult(
        allowed=False,
        agent_id="test-agent",
        step_count=step_count,
        accumulated_tokens=1000,
        step_quota_max=12,
        token_quota_max=100_000,
        block_reason=block_reason,
        session_ttl=3600,
    )


@pytest.fixture
async def redis_client():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
async def uca_logger(redis_client):
    from src.gateway.governance.uca_logger import UCALogger

    return UCALogger(
        signer=None,
        redis_client=redis_client,
        bucket="test-bucket",
        pii_sanitizer=PIISanitizer(),
        test_mode=True,
    )


REQUIRED_SCHEMA_FIELDS = [
    "compliance_event_id",
    "timestamp",
    "iso42001_clause",
    "iso42001_control",
    "governance_control_id",
    "uca_type",
    "agent_id",
    "session_key",
    "block_reason",
    "current_value",
    "quota_max",
    "request_summary",
    "cryptographic_signature",
    "signing_key_id",
    "deployment_region",
    "worm_path",
]


@pytest.mark.asyncio
@pytest.mark.local
async def test_uca_record_schema_conformance(uca_logger):
    """UCA record contains all 16 required ISO 42001 Clause 6.1 fields."""
    record = await uca_logger._build_uca_record(
        uca_type="quota_exceeded",
        agent_id="test-agent",
        quota_result=_mock_quota_result(),
        request_body={"model": "test"},
    )
    for field in REQUIRED_SCHEMA_FIELDS:
        assert field in record, f"Missing required field: {field}"


@pytest.mark.asyncio
@pytest.mark.local
async def test_hmac_stub_signing_in_test_mode(uca_logger):
    """test_mode=True produces 0xSTUB_ prefixed signature."""
    record = await uca_logger._build_uca_record(
        uca_type="quota_exceeded",
        agent_id="test-agent",
        quota_result=_mock_quota_result(),
        request_body={},
    )
    assert record["cryptographic_signature"].startswith("0xSTUB_")


@pytest.mark.local
def test_region_bucket_us_fed():
    """_get_worm_bucket() returns OSCAL_S3_BUCKET_US_FED for US_FED."""
    from src.gateway.governance.uca_logger import UCALogger

    logger = UCALogger(
        signer=None,
        redis_client=MagicMock(),
        bucket="",
        pii_sanitizer=PIISanitizer(),
        test_mode=True,
    )
    with patch.dict(
        os.environ,
        {
            "CAGE_DEPLOYMENT_REGION": "US_FED",
            "OSCAL_S3_BUCKET_US_FED": "us-fed-bucket",
        },
    ):
        assert logger._get_worm_bucket() == "us-fed-bucket"


@pytest.mark.local
def test_region_bucket_eu_ecb():
    """_get_worm_bucket() returns OSCAL_S3_BUCKET_EU_ECB for EU_ECB."""
    from src.gateway.governance.uca_logger import UCALogger

    logger = UCALogger(
        signer=None,
        redis_client=MagicMock(),
        bucket="",
        pii_sanitizer=PIISanitizer(),
        test_mode=True,
    )
    with patch.dict(
        os.environ,
        {
            "CAGE_DEPLOYMENT_REGION": "EU_ECB",
            "OSCAL_S3_BUCKET_EU_ECB": "eu-ecb-bucket",
        },
    ):
        assert logger._get_worm_bucket() == "eu-ecb-bucket"


@pytest.mark.local
def test_region_bucket_apac_mas():
    """_get_worm_bucket() returns OSCAL_S3_BUCKET_APAC_MAS for APAC_MAS."""
    from src.gateway.governance.uca_logger import UCALogger

    logger = UCALogger(
        signer=None,
        redis_client=MagicMock(),
        bucket="",
        pii_sanitizer=PIISanitizer(),
        test_mode=True,
    )
    with patch.dict(
        os.environ,
        {
            "CAGE_DEPLOYMENT_REGION": "APAC_MAS",
            "OSCAL_S3_BUCKET_APAC_MAS": "apac-mas-bucket",
        },
    ):
        assert logger._get_worm_bucket() == "apac-mas-bucket"


@pytest.mark.asyncio
@pytest.mark.local
async def test_worm_write_failure_non_blocking(uca_logger):
    """WORM write failure does not suppress the block; method returns."""
    with patch.object(
        uca_logger, "_persist_uca_record", side_effect=Exception("GCS unavailable")
    ):
        # Should not raise; block is still enforced
        try:
            await uca_logger.log_quota_exceeded(_mock_quota_result(), {})
        except Exception as e:
            pytest.fail(f"log_quota_exceeded raised unexpectedly: {e}")


@pytest.mark.asyncio
@pytest.mark.local
async def test_pii_sanitization_applied(uca_logger):
    """Request body SSN is redacted in UCA record request_summary."""
    record = await uca_logger._build_uca_record(
        uca_type="quota_exceeded",
        agent_id="test-agent",
        quota_result=_mock_quota_result(),
        request_body={"prompt": "My SSN is 123-45-6789"},
    )
    assert "[REDACTED_SSN]" in record["request_summary"]
    assert "123-45-6789" not in record["request_summary"]


@pytest.mark.asyncio
@pytest.mark.local
async def test_event_id_format(uca_logger):
    """_generate_event_id() returns 'UCA-{uuid4}' format."""
    event_id = await uca_logger._generate_event_id()
    assert re.match(
        r"^UCA-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        event_id,
    ), f"Event ID format invalid: {event_id}"


@pytest.mark.asyncio
@pytest.mark.local
async def test_worm_path_format(uca_logger):
    """_persist_uca_record() returns path matching uca-records/YYYY-MM-DD/UCA-*.yaml."""
    with patch.object(uca_logger, "_write_to_worm", new_callable=AsyncMock):
        record = await uca_logger._build_uca_record(
            uca_type="quota_exceeded",
            agent_id="test-agent",
            quota_result=_mock_quota_result(),
            request_body={},
        )
        worm_path = await uca_logger._persist_uca_record(record)
        assert re.match(
            r"^uca-records/\d{4}-\d{2}-\d{2}/UCA-[0-9a-f-]+\.yaml$",
            worm_path,
        ), f"WORM path format invalid: {worm_path}"
