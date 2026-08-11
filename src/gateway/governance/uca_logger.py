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
UCA Logger — ISO 42001 Clause 6.1 Unsafe Control Action Records
================================================================
Builds, cryptographically signs, and persists Unsafe Control Action (UCA)
records to a WORM ledger (GCS/S3 region-gated bucket).

Implements ISO 42001 Clause 6.1 (STPA Risk Logging) and Annex A.4
(Resource Management — per-session token quota enforcement).

Governance control: CTRL_TQP_007

Region guard: CAGE_DEPLOYMENT_REGION routes writes to the correct
regional WORM bucket (US_FED → us-central1, EU_ECB → europe-west1,
APAC_MAS → asia-southeast1). See .clinerules §12.2.

Signing: KMSGovernanceSigner in production; HMAC-SHA256 stub in test mode
(CAGE_ENV=test). The stub lives here — KMSGovernanceSigner has no HMAC
fallback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_uca_logger: UCALogger | None = None


# ---------------------------------------------------------------------------
# UCALogger
# ---------------------------------------------------------------------------


class UCALogger:
    """Build, sign, and persist ISO 42001 Clause 6.1 UCA records.

    Parameters
    ----------
    signer:
        ``KMSGovernanceSigner`` instance, or ``None`` when ``test_mode=True``.
    redis_client:
        Async Redis client (fakeredis in tests).  Reserved for future
        deduplication / idempotency checks; not used for primary storage.
    bucket:
        WORM bucket name.  Pass ``""`` to let ``_get_worm_bucket()`` resolve
        from environment at write time.
    pii_sanitizer:
        ``PIISanitizer`` instance applied to ``request_summary`` before signing.
    test_mode:
        When ``True``, HMAC-SHA256 stub signing is used instead of KMS.
        Automatically set when ``CAGE_ENV=test``.
    """

    def __init__(
        self,
        signer: Any | None,
        redis_client: Any,
        bucket: str,
        pii_sanitizer: Any,
        test_mode: bool = False,
    ) -> None:
        self._signer = signer
        self._redis = redis_client
        self._bucket = bucket
        self._pii = pii_sanitizer
        self._test_mode = test_mode

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> UCALogger:
        """Construct from environment variables.

        Reads:
            CAGE_DEPLOYMENT_REGION — routes WORM bucket selection
            OSCAL_S3_BUCKET_*      — regional bucket names
            KMS_GOVERNANCE_KEY     — KMS key resource name (production)
            CAGE_ENV               — set to "test" to enable stub signing
        """
        test_mode = os.environ.get("CAGE_ENV", "").lower() == "test"

        signer: object | None = None
        if not test_mode:
            try:
                from src.gateway.governance.kms_signer import KMSGovernanceSigner

                signer = KMSGovernanceSigner.from_env()
            except Exception as exc:
                logger.warning(
                    "UCALogger: KMS signer unavailable (%s); "
                    "falling back to test-mode HMAC stub. "
                    "Set CAGE_ENV=test to suppress this warning.",
                    exc,
                )
                test_mode = True

        from src.gateway.governance.pii_sanitizer import _get_pii_sanitizer

        pii_sanitizer = _get_pii_sanitizer()

        # Redis client — optional; used for future deduplication
        redis_client: object | None = None
        try:
            from src.gateway.infrastructure.redis_client import get_redis_client

            redis_client = get_redis_client()
        except Exception as exc:
            logger.debug(
                "UCALogger: Redis client unavailable (%s); continuing without it.", exc
            )

        instance = cls(
            signer=signer,
            redis_client=redis_client,
            bucket="",  # resolved dynamically via _get_worm_bucket()
            pii_sanitizer=pii_sanitizer,
            test_mode=test_mode,
        )
        return instance

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    async def log_quota_exceeded(
        self,
        quota_result: Any,  # QuotaCheckResult from token_quota_proxy.py
        request_body: dict,
    ) -> str:
        """Build, sign, and persist a ``quota_exceeded`` UCA record.

        Returns the WORM path string, e.g.
        ``'uca-records/2026-06-08/UCA-{uuid}.yaml'``.

        WORM write failure is logged as ERROR but does NOT suppress the
        quota block — the caller's 429 response is returned regardless.
        """
        try:
            record = await self._build_uca_record(
                uca_type="quota_exceeded",
                agent_id=quota_result.agent_id,
                quota_result=quota_result,
                request_body=request_body,
            )
            return await self._persist_uca_record(record)
        except Exception as exc:
            logger.error(
                "UCALogger.log_quota_exceeded: WORM write failed — %s. "
                "Block is still enforced.",
                exc,
                exc_info=True,
            )
            return ""

    async def log_prompt_injection(
        self,
        agent_id: str,
        injected_content: str,
        block_reason: str,
    ) -> str:
        """Build, sign, and persist a ``prompt_injection`` UCA record.

        Returns the WORM path string.
        """
        try:
            record = await self._build_uca_record(
                uca_type="prompt_injection",
                agent_id=agent_id,
                block_reason=block_reason,
                injected_content=injected_content,
            )
            return await self._persist_uca_record(record)
        except Exception as exc:
            logger.error(
                "UCALogger.log_prompt_injection: WORM write failed — %s. "
                "Block is still enforced.",
                exc,
                exc_info=True,
            )
            return ""

    async def log_pii_sanitization(
        self,
        agent_id: str,
        tool_name: str,
        original_args: str,
        sanitized_args: str,
    ) -> str:
        """Build, sign, and persist a ``pii_sanitization`` UCA record.

        Returns the WORM path string.
        """
        try:
            record = await self._build_uca_record(
                uca_type="pii_sanitization",
                agent_id=agent_id,
                tool_name=tool_name,
                original_args=original_args,
                sanitized_args=sanitized_args,
            )
            return await self._persist_uca_record(record)
        except Exception as exc:
            logger.error(
                "UCALogger.log_pii_sanitization: WORM write failed — %s.",
                exc,
                exc_info=True,
            )
            return ""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _build_uca_record(
        self,
        uca_type: str,
        agent_id: str,
        quota_result: Any | None = None,
        request_body: dict | None = None,
        **kwargs: Any,
    ) -> dict:
        """Build the ISO 42001 Clause 6.1 record dict.

        Applies PII sanitization to ``request_summary`` before signing.
        All 16 required schema fields are populated.
        """
        event_id = await self._generate_event_id()
        now_utc = datetime.now(timezone.utc)
        timestamp = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        date_str = now_utc.strftime("%Y-%m-%d")
        worm_path = f"uca-records/{date_str}/{event_id}.yaml"
        region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
        session_key = f"quota:session:{agent_id}"

        # PII sanitized before persistence per GDPR Art. 32 / MAS Notice 655
        # Sanitize all text fields that may contain PII or sensitive financial data.
        _sanitize = self._pii.sanitize

        # Sanitize kwargs fields that may carry prompt/content/message/description
        for _field in (
            "injected_content",
            "original_args",
            "sanitized_args",
            "prompt",
            "content",
            "message",
            "description",
            "block_reason",
        ):
            if _field in kwargs and isinstance(kwargs[_field], str):
                kwargs[_field] = _sanitize(kwargs[_field])

        # Build request_summary with PII sanitization
        raw_summary = ""
        if request_body:
            try:
                raw_summary = json.dumps(request_body, sort_keys=True)[:512]
            except (TypeError, ValueError):
                raw_summary = str(request_body)[:512]
        elif kwargs.get("injected_content"):
            raw_summary = str(kwargs["injected_content"])[:512]
        elif kwargs.get("original_args"):
            raw_summary = str(kwargs["original_args"])[:512]

        request_summary = _sanitize(raw_summary) if raw_summary else ""

        # Quota-specific fields
        block_reason = kwargs.get("block_reason", "")
        current_value: int = 0
        quota_max: int = 0

        if quota_result is not None:
            block_reason = quota_result.block_reason or ""
            if block_reason == "step_count":
                current_value = quota_result.step_count
                quota_max = quota_result.step_quota_max
            elif block_reason == "token_count":
                current_value = quota_result.accumulated_tokens
                quota_max = quota_result.token_quota_max
            else:
                current_value = quota_result.step_count
                quota_max = quota_result.step_quota_max

        record: dict[str, Any] = {
            "compliance_event_id": event_id,
            "timestamp": timestamp,
            "iso42001_clause": "6.1",
            "iso42001_control": "A.4",
            "governance_control_id": "CTRL_TQP_007",
            "uca_type": uca_type,
            "agent_id": agent_id,
            "session_key": session_key,
            "block_reason": block_reason,
            "current_value": current_value,
            "quota_max": quota_max,
            "request_summary": request_summary,
            "cryptographic_signature": "",  # populated by _persist_uca_record
            "signing_key_id": "",  # populated by _persist_uca_record
            "deployment_region": region,
            "worm_path": worm_path,
        }

        # Sign inline so _build_uca_record returns a fully-signed record
        # (required by test_hmac_stub_signing_in_test_mode)
        self._sign_record(record)

        return record

    async def _persist_uca_record(self, record: dict) -> str:
        """Serialize signed record to YAML and write to WORM ledger.

        On write failure: logs ERROR to stderr; block is still enforced.
        Returns the ``worm_path`` string.
        """
        worm_path: str = record.get("worm_path", "")

        try:
            yaml_content = yaml.dump(record, default_flow_style=False, sort_keys=True)
            await self._write_to_worm(worm_path, yaml_content)
            logger.info("UCALogger: UCA record persisted to WORM at %s", worm_path)
        except Exception as exc:
            logger.error(
                "UCALogger: WORM write failed for path %s — %s",
                worm_path,
                exc,
                exc_info=True,
                stack_info=False,
            )
            # Do NOT re-raise — block is still enforced by caller

        return worm_path

    async def _write_to_worm(self, path: str, content: str) -> None:
        """Write ``content`` to the WORM bucket at ``path``.

        Uses ``src.compliance_bridge.storage.WORMStorage`` when available.
        Falls back to a structured stderr log when storage is unavailable
        (e.g. in unit tests where ``_write_to_worm`` is patched).
        """
        bucket = self._get_worm_bucket()
        if not bucket:
            logger.warning(
                "UCALogger: No WORM bucket configured (OSCAL_S3_BUCKET_* env vars). "
                "UCA record NOT persisted to storage. Path would be: %s",
                path,
            )
            return

        try:
            from src.compliance_bridge.storage import WORMStorage  # type: ignore[attr-defined]

            region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
            await WORMStorage.write(
                bucket=bucket, path=path, content=content, region=region
            )
        except ImportError:
            # compliance_bridge not available in this deployment unit
            logger.warning(
                "UCALogger: WORMStorage not available; writing UCA record to stderr. "
                "Path: %s",
                path,
            )
            print(
                json.dumps({"level": "UCA_RECORD", "path": path, "content": content}),
                file=sys.stderr,
            )

    async def _generate_event_id(self) -> str:
        """Return a ``'UCA-{uuid4}'`` string."""
        return f"UCA-{uuid.uuid4()}"

    def _get_worm_bucket(self) -> str:
        """Return the region-gated WORM bucket name.

        Routing:
            US_FED   → OSCAL_S3_BUCKET_US_FED   (us-central1)
            EU_ECB   → OSCAL_S3_BUCKET_EU_ECB   (europe-west1)
            APAC_MAS → OSCAL_S3_BUCKET_APAC_MAS (asia-southeast1)

        Falls back to OSCAL_S3_BUCKET if the region-specific var is unset.
        Satisfies .clinerules §12.2 (CAGE_DEPLOYMENT_REGION guard).
        """
        region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED")
        fallback = os.environ.get("OSCAL_S3_BUCKET", "")
        bucket_map = {
            "US_FED": os.environ.get("OSCAL_S3_BUCKET_US_FED", fallback),
            "EU_ECB": os.environ.get("OSCAL_S3_BUCKET_EU_ECB", fallback),
            "APAC_MAS": os.environ.get("OSCAL_S3_BUCKET_APAC_MAS", fallback),
        }
        return bucket_map.get(region, fallback)

    def _sign_record(self, record: dict) -> None:
        """Sign ``record`` in-place, populating ``cryptographic_signature``
        and ``signing_key_id``.

        In test mode: HMAC-SHA256 stub with prefix ``0xSTUB_``.
        In production: delegates to ``KMSGovernanceSigner.sign()``.
        """
        # Exclude signature fields from the payload being signed
        payload = {
            k: v
            for k, v in record.items()
            if k not in ("cryptographic_signature", "signing_key_id")
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode()

        if self._test_mode or self._signer is None:
            stub_sig = hmac.new(
                b"test-key",
                payload_bytes,
                hashlib.sha256,
            ).hexdigest()
            record["cryptographic_signature"] = f"0xSTUB_{stub_sig[:16]}"
            record["signing_key_id"] = "test-mode-hmac-sha256"
        else:
            try:
                # KMSGovernanceSigner.sign() accepts a dict and returns hex
                sig_hex = self._signer.sign(payload)
                record["cryptographic_signature"] = sig_hex
                # Expose the key version resource name if available
                key_id = getattr(self._signer, "_key_version", "") or ""
                record["signing_key_id"] = key_id
            except Exception as exc:
                logger.error(
                    "UCALogger: KMS signing failed — %s. "
                    "Falling back to HMAC stub for this record.",
                    exc,
                )
                stub_sig = hmac.new(
                    b"test-key",
                    payload_bytes,
                    hashlib.sha256,
                ).hexdigest()
                record["cryptographic_signature"] = f"0xSTUB_{stub_sig[:16]}"
                record["signing_key_id"] = "kms-fallback-hmac-sha256"


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------


def _get_uca_logger() -> UCALogger:
    """Return the module-level UCALogger singleton (lazy init)."""
    global _uca_logger
    if _uca_logger is None:
        _uca_logger = UCALogger.from_env()
    return _uca_logger
