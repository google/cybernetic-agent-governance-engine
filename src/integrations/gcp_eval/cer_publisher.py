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

"""Cryptographic Skill Certification (`.cer`) Signer, GCS Publisher, and Verifier.

Implements the Static Artifact Handshake between the Offline Evaluation &
Certification Plane and the Online Runtime Enforcement Plane:
1. ``GcpSkillCertifier`` signs ``SkillCertificationReceipt`` objects via RFC 8785
   JCS canonicalization using ``BaseKMSProvider`` (``GCPKMSProvider`` or hermetic
   ``SoftwareEd25519Provider`` in non-enforcing development/test postures).
2. ``GcsArtifactHandshakePublisher`` atomically writes ``.cer`` receipts,
   ``terminal_registry.json``, and OPA ``.rego`` policies to GCS with
   ``if_generation_match=0`` immutability preconditions.
3. ``GcsSkillCertificationVerifier`` resolves signing keys out-of-band by ``kid``
   via ``Ed25519KeyManifestClient`` and verifies ``.cer`` receipts and
   ``SKILL.md`` SHA-256 digests fail-closed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from src.eval_harness.harness import (
    AnchorCalibrationResult,
    SkillCertificationReceipt,
    SkillLiftReport,
)
from src.eval_harness.static_linter import SkillStaticLintReport
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import BaseKMSProvider
from src.gateway.governance.signer_factory import build_kms_provider
from src.integrations.trust.key_manifest import Ed25519KeyResolver

logger = logging.getLogger("cage.integrations.gcp_eval.cer_publisher")

_SAFE_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")


def _validate_safe_identifier(value: str, field_name: str) -> str:
    """Validate skill/domain names against path traversal or injection."""
    cleaned = value.strip()
    if (
        not cleaned
        or ".." in cleaned
        or "/" in cleaned
        or "\\" in cleaned
        or not _SAFE_ARTIFACT_ID_RE.fullmatch(cleaned)
    ):
        raise ValueError(
            f"Invalid {field_name}={value!r}: must match {_SAFE_ARTIFACT_ID_RE.pattern} without traversal"
        )
    return cleaned


def compute_file_sha256(path: Path) -> str:
    """Compute hex SHA-256 digest of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


class GcpSkillCertifier:
    """Signs offline skill evaluation results into `.cer` cryptographic receipts."""

    def __init__(
        self,
        *,
        key_id: str,
        kms_provider: BaseKMSProvider | None = None,
        provider_name: str | None = None,
    ) -> None:
        if not key_id or not key_id.strip():
            raise ValueError("GcpSkillCertifier requires a non-empty key_id (kid)")
        self._key_id = key_id.strip()
        self._kms_provider = kms_provider or build_kms_provider(
            provider_name=provider_name
        )

    @property
    def key_id(self) -> str:
        return self._key_id

    def create_and_sign_receipt(
        self,
        *,
        skill_md_path: Path,
        static_report: SkillStaticLintReport,
        lift_report: SkillLiftReport | None = None,
        anchor_report: AnchorCalibrationResult | None = None,
        evals_json_path: Path | None = None,
        anchors_json_path: Path | None = None,
        model_id: str = "gemini-3.5-flash",
        issued_at: str | None = None,
    ) -> SkillCertificationReceipt:
        """Create and sign a :class:`SkillCertificationReceipt` via JCS + KMS."""
        safe_skill = _validate_safe_identifier(static_report.skill_name, "skill_name")
        skill_sha256 = compute_file_sha256(skill_md_path)
        evals_sha256 = (
            compute_file_sha256(evals_json_path)
            if evals_json_path is not None and evals_json_path.exists()
            else hashlib.sha256(b"").hexdigest()
        )
        anchors_sha256 = (
            compute_file_sha256(anchors_json_path)
            if anchors_json_path is not None and anchors_json_path.exists()
            else None
        )
        ts = issued_at or datetime.now(timezone.utc).isoformat()

        unsigned = SkillCertificationReceipt(
            skill_name=safe_skill,
            skill_sha256=skill_sha256,
            evals_sha256=evals_sha256,
            anchors_sha256=anchors_sha256,
            model_id=lift_report.model_id if lift_report is not None else model_id,
            static_lint_score=static_report.length_adjusted_score,
            anchor_weighted_agreement=(
                anchor_report.weighted_agreement if anchor_report is not None else None
            ),
            mean_composite_lift=(
                lift_report.mean_composite_lift if lift_report is not None else 0.0
            ),
            mean_instruction_following_lift=(
                lift_report.mean_instruction_following_lift
                if lift_report is not None
                else 0.0
            ),
            routing_premium=(
                lift_report.routing_premium if lift_report is not None else None
            ),
            issued_at=ts,
        )

        unsigned_body = unsigned.to_unsigned_body()
        envelope_bytes = jcs_canonicalize_plan(
            {
                "protected": {"algorithm": "Ed25519", "keyId": self._key_id},
                "body": unsigned_body,
            }
        )

        if self._kms_provider.expects_raw_message:
            sig_bytes = self._kms_provider.sign_raw(envelope_bytes)
        else:
            digest = hashlib.sha256(envelope_bytes).digest()
            sig_bytes = self._kms_provider.sign_digest(digest)

        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        signature_block = {
            "algorithm": "Ed25519",
            "keyId": self._key_id,
            "value": sig_b64,
        }
        signed = SkillCertificationReceipt(
            **unsigned_body,
            signature=signature_block,
        )
        return SkillCertificationReceipt(
            **unsigned_body,
            signature=signature_block,
            receipt_digest=signed.compute_signed_digest(),
        )


class GcsArtifactHandshakePublisher:
    """Publishes `.cer` receipts, `terminal_registry.json`, and `.rego` bundles to GCS."""

    def __init__(
        self,
        bucket_name: str,
        *,
        project_id: str | None = None,
        storage_client: Any = None,
    ) -> None:
        if not bucket_name or not bucket_name.strip():
            raise ValueError("GcsArtifactHandshakePublisher requires bucket_name")
        self._bucket_name = bucket_name.strip()
        self._project_id = project_id
        self._storage_client = storage_client

    def _get_client(self) -> Any:
        if self._storage_client is not None:
            return self._storage_client
        try:
            from google.cloud import storage as gcs  # type: ignore[attr-defined]
        except ImportError as exc:
            raise RuntimeError(
                "google-cloud-storage is required for GcsArtifactHandshakePublisher"
            ) from exc
        self._storage_client = gcs.Client(project=self._project_id)
        return self._storage_client

    def publish_cer_receipt(
        self,
        receipt: SkillCertificationReceipt,
        *,
        certified: bool = True,
    ) -> str:
        """Atomically upload a signed `.cer` receipt to GCS (`if_generation_match=0`)."""
        if not certified:
            raise ValueError("Refusing to publish .cer receipt when certified=False")
        safe_skill = _validate_safe_identifier(receipt.skill_name, "skill_name")
        if not _SHA256_HEX_RE.fullmatch(receipt.skill_sha256):
            raise ValueError(f"Invalid skill_sha256={receipt.skill_sha256!r}")
        if not receipt.signature.get("keyId") or not receipt.signature.get("value"):
            raise ValueError("Cannot publish unsigned SkillCertificationReceipt")

        object_key = f"skills/{safe_skill}/{receipt.skill_sha256}.cer"
        payload_bytes = json.dumps(receipt.to_dict(), indent=2, sort_keys=True).encode(
            "utf-8"
        )

        client = self._get_client()
        bucket = client.bucket(self._bucket_name)
        blob = bucket.blob(object_key)
        blob.upload_from_string(
            payload_bytes,
            content_type="application/json",
            if_generation_match=0,
        )
        return f"gs://{self._bucket_name}/{object_key}"

    def publish_policy_and_registry_bundle(
        self,
        *,
        domain: str,
        terminal_registry: Mapping[str, Any],
        rego_policy_text: str,
    ) -> tuple[str, str]:
        """Publish `terminal_registry.json` and `.rego` policy bundle to GCS."""
        safe_domain = _validate_safe_identifier(domain, "domain")
        client = self._get_client()
        bucket = client.bucket(self._bucket_name)

        reg_key = f"manifests/{safe_domain}/terminal_registry.json"
        reg_blob = bucket.blob(reg_key)
        reg_blob.upload_from_string(
            json.dumps(dict(terminal_registry), indent=2, sort_keys=True).encode(
                "utf-8"
            ),
            content_type="application/json",
        )

        rego_key = f"policies/{safe_domain}.rego"
        rego_blob = bucket.blob(rego_key)
        rego_blob.upload_from_string(
            rego_policy_text.encode("utf-8"),
            content_type="text/plain; charset=utf-8",
        )
        return (
            f"gs://{self._bucket_name}/{reg_key}",
            f"gs://{self._bucket_name}/{rego_key}",
        )


class GcsSkillCertificationVerifier:
    """Fail-closed verifier for `.cer` receipts using out-of-band `kid` resolution."""

    def __init__(
        self,
        key_resolver: Ed25519KeyResolver,
        *,
        min_composite_lift: float = 0.0,
        min_static_score: float = 0.70,
    ) -> None:
        self._key_resolver = key_resolver
        self._min_composite_lift = min_composite_lift
        self._min_static_score = min_static_score

    async def verify_cer_receipt(
        self,
        receipt_payload: Mapping[str, Any] | SkillCertificationReceipt,
        *,
        expected_skill_md_bytes: bytes | None = None,
    ) -> tuple[bool, str]:
        """Verify `.cer` digest, out-of-band `kid` Ed25519 signature, and `SKILL.md` hash.

        Returns ``(verified, reason)`` and fails closed on any discrepancy.
        """
        try:
            receipt = (
                receipt_payload
                if isinstance(receipt_payload, SkillCertificationReceipt)
                else SkillCertificationReceipt.from_dict(receipt_payload)
            )
        except Exception as exc:
            return False, f"malformed_cer_receipt: {exc}"

        if not receipt.receipt_digest:
            return False, "missing_receipt_digest"

        computed_digest = receipt.compute_signed_digest()
        if computed_digest != receipt.receipt_digest:
            return False, "receipt_digest_mismatch"

        if expected_skill_md_bytes is not None:
            actual_skill_sha = hashlib.sha256(expected_skill_md_bytes).hexdigest()
            if actual_skill_sha != receipt.skill_sha256:
                return False, "skill_md_sha256_mismatch"

        if receipt.static_lint_score < self._min_static_score:
            return False, "static_lint_score_below_threshold"

        if receipt.mean_composite_lift < self._min_composite_lift:
            return False, "composite_lift_below_threshold"

        sig_block = receipt.signature
        if sig_block.get("algorithm") != "Ed25519":
            return False, "unsupported_signature_algorithm"

        kid = sig_block.get("keyId", "")
        sig_val = sig_block.get("value", "")
        if not kid or not sig_val:
            return False, "missing_kid_or_signature_value"

        public_key = await self._key_resolver.get_key(kid)
        if public_key is None:
            return False, f"unknown_kid:{kid}"

        try:
            sig_bytes = base64.b64decode(sig_val, validate=True)
        except Exception:
            return False, "invalid_signature_base64"

        envelope_bytes = jcs_canonicalize_plan(
            {
                "protected": {"algorithm": "Ed25519", "keyId": kid},
                "body": receipt.to_unsigned_body(),
            }
        )
        try:
            public_key.verify(sig_bytes, envelope_bytes)
        except InvalidSignature:
            return False, "ed25519_signature_verification_failed"
        except Exception as exc:
            return False, f"signature_verification_error:{exc}"

        return True, "VERIFIED"


__all__ = [
    "GcpSkillCertifier",
    "GcsArtifactHandshakePublisher",
    "GcsSkillCertificationVerifier",
    "compute_file_sha256",
]
