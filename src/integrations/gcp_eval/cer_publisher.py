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

Receipts use schema ``cage.skill.cer.v2``: the signed body binds the stages
that ran, the evidence level (``STATIC_ONLY`` / ``PAIRED_TRACES`` /
``LIVE_ROLLOUT``), and the digests of the evaluated evidence. Verifiers refuse
every other schema version and, unless explicitly configured otherwise,
``STATIC_ONLY`` receipts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from src.eval_harness.harness import (
    CER_SCHEMA_VERSION,
    AnchorCalibrationResult,
    CerEvidenceLevel,
    SkillCertificationReceipt,
    SkillLiftReport,
    lift_meets_threshold,
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


def compute_adapter_config_sha256(adapter_config: Mapping[str, Any]) -> str:
    """Compute the hex SHA-256 digest of a rollout adapter config's RFC 8785 JCS form.

    Hashing the canonical JSON (not the raw CLI string or file bytes) yields
    the same digest for the same configuration however it was supplied.
    """
    return hashlib.sha256(jcs_canonicalize_plan(dict(adapter_config))).hexdigest()


def _optional_file_sha256(path: Path | None) -> str | None:
    """Digest ``path`` when given; a missing file raises instead of being skipped."""
    return compute_file_sha256(path) if path is not None else None


def _resolve_receipt_model_id(
    lift_report: SkillLiftReport | None, explicit_model_id: str | None
) -> str | None:
    """Resolve the evaluated model id without falling back to a default model.

    The lift report is authoritative (for live rollouts it carries the rollout
    bundle's model id); an explicit ``model_id`` may only confirm it, or name
    the model when the report carries none. A receipt without measured lift
    names no model.
    """
    explicit = explicit_model_id.strip() if explicit_model_id is not None else None
    if explicit_model_id is not None and not explicit:
        raise ValueError("model_id must be a non-empty string when given")
    if lift_report is None:
        if explicit is not None:
            raise ValueError(
                "model_id was given but no Skill Lift was measured (no lift_report); "
                "STATIC_ONLY receipts name no model"
            )
        return None
    measured = (lift_report.model_id or "").strip()
    if not measured:
        if explicit is None:
            raise ValueError(
                "Stage 2 ran without a model id: the lift report names no model_id "
                "and no explicit model_id was given"
            )
        return explicit
    if explicit is not None and explicit != measured:
        raise ValueError(
            f"model_id {explicit!r} contradicts the lift report's model_id {measured!r}"
        )
    return measured


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
        stages_run: Sequence[int],
        evidence_level: CerEvidenceLevel | str,
        lift_report: SkillLiftReport | None = None,
        anchor_report: AnchorCalibrationResult | None = None,
        evals_json_path: Path | None = None,
        anchors_json_path: Path | None = None,
        baseline_traces_path: Path | None = None,
        with_skill_traces_path: Path | None = None,
        adapter_ref: str | None = None,
        adapter_config: Mapping[str, Any] | None = None,
        model_id: str | None = None,
        issued_at: str | None = None,
    ) -> SkillCertificationReceipt:
        """Create and sign a ``cage.skill.cer.v2`` receipt via JCS + KMS.

        ``stages_run`` and ``evidence_level`` are signed as declared and must
        agree with the supplied reports and evidence. Every digest is computed
        here from the artifacts actually evaluated: ``evals_json_path``,
        ``anchors_json_path``, both trace files (``PAIRED_TRACES``), or
        ``adapter_ref`` plus the JCS digest of ``adapter_config``
        (``LIVE_ROLLOUT``). ``model_id`` comes from ``lift_report``; an
        explicit ``model_id`` must match it. There is no default model.

        Raises ``ValueError`` when Stage 2 ran without a model id or on any
        contradiction between the declared stages, evidence level, and inputs,
        and ``OSError`` when a given evidence file cannot be read.
        """
        safe_skill = _validate_safe_identifier(static_report.skill_name, "skill_name")
        stages = tuple(stages_run)
        level = CerEvidenceLevel(evidence_level)
        if (2 in stages) != (lift_report is not None):
            raise ValueError(
                "stages_run must list stage 2 exactly when a lift_report is supplied"
            )
        if (1 in stages) != (anchor_report is not None):
            raise ValueError(
                "stages_run must list stage 1 exactly when an anchor_report is supplied"
            )
        if adapter_config is not None and adapter_ref is None:
            raise ValueError("adapter_config was given without adapter_ref")
        resolved_model_id = _resolve_receipt_model_id(lift_report, model_id)

        unsigned = SkillCertificationReceipt(
            skill_name=safe_skill,
            skill_sha256=compute_file_sha256(skill_md_path),
            static_lint_score=static_report.length_adjusted_score,
            stages_run=stages,
            evidence_level=level,
            issued_at=issued_at or datetime.now(timezone.utc).isoformat(),
            model_id=resolved_model_id,
            evals_sha256=_optional_file_sha256(evals_json_path),
            anchors_sha256=_optional_file_sha256(anchors_json_path),
            anchor_weighted_agreement=(
                anchor_report.weighted_agreement if anchor_report is not None else None
            ),
            mean_composite_lift=(
                lift_report.mean_composite_lift if lift_report is not None else None
            ),
            mean_instruction_following_lift=(
                lift_report.mean_instruction_following_lift
                if lift_report is not None
                else None
            ),
            routing_premium=(
                lift_report.routing_premium if lift_report is not None else None
            ),
            baseline_traces_sha256=_optional_file_sha256(baseline_traces_path),
            with_skill_traces_sha256=_optional_file_sha256(with_skill_traces_path),
            adapter_ref=adapter_ref,
            adapter_config_sha256=(
                compute_adapter_config_sha256(adapter_config or {})
                if adapter_ref is not None
                else None
            ),
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
    """Fail-closed verifier for ``cage.skill.cer.v2`` receipts with out-of-band ``kid`` resolution.

    ``min_composite_lift`` is applied with :func:`lift_meets_threshold`, the
    same rule as the certification gate (the default ``0.0`` requires strictly
    positive lift). ``STATIC_ONLY`` receipts carry no measured lift and are
    refused unless the verifier is constructed with ``allow_static_only=True``.
    """

    def __init__(
        self,
        key_resolver: Ed25519KeyResolver,
        *,
        min_composite_lift: float = 0.0,
        min_static_score: float = 0.70,
        allow_static_only: bool = False,
    ) -> None:
        self._key_resolver = key_resolver
        self._min_composite_lift = min_composite_lift
        self._min_static_score = min_static_score
        self._allow_static_only = allow_static_only

    async def verify_cer_receipt(
        self,
        receipt_payload: Mapping[str, Any] | SkillCertificationReceipt,
        *,
        expected_skill_md_bytes: bytes,
    ) -> tuple[bool, str]:
        """Verify a `.cer` receipt's signature, ``SKILL.md`` binding, and policy.

        ``expected_skill_md_bytes`` is required: a receipt certifies only the
        exact skill bytes the caller is about to load. Returns
        ``(verified, reason)`` and fails closed, in order, on: a schema other
        than ``cage.skill.cer.v2`` (``unsupported_schema_version``), a
        structurally inconsistent receipt (``malformed_cer_receipt``), a
        receipt digest or Ed25519 signature failure, a ``SKILL.md`` digest
        mismatch, a ``STATIC_ONLY`` receipt (``static_only_receipt``) unless
        allowed, and static score or composite lift below threshold.
        """
        if not isinstance(expected_skill_md_bytes, (bytes, bytearray)):
            raise TypeError(
                "expected_skill_md_bytes must be the SKILL.md bytes the receipt certifies"
            )
        if isinstance(receipt_payload, SkillCertificationReceipt):
            receipt = receipt_payload
        elif isinstance(receipt_payload, Mapping):
            if receipt_payload.get("schema_version") != CER_SCHEMA_VERSION:
                return False, "unsupported_schema_version"
            try:
                receipt = SkillCertificationReceipt.from_dict(receipt_payload)
            except Exception as exc:
                return False, f"malformed_cer_receipt: {exc}"
        else:
            return False, "malformed_cer_receipt: payload must be a JSON object"

        if not receipt.receipt_digest:
            return False, "missing_receipt_digest"

        computed_digest = receipt.compute_signed_digest()
        if computed_digest != receipt.receipt_digest:
            return False, "receipt_digest_mismatch"

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

        actual_skill_sha = hashlib.sha256(bytes(expected_skill_md_bytes)).hexdigest()
        if actual_skill_sha != receipt.skill_sha256:
            return False, "skill_md_sha256_mismatch"

        static_only = receipt.evidence_level is CerEvidenceLevel.STATIC_ONLY
        if static_only and not self._allow_static_only:
            return False, "static_only_receipt"

        if receipt.static_lint_score < self._min_static_score:
            return False, "static_lint_score_below_threshold"

        if not static_only and not lift_meets_threshold(
            receipt.mean_composite_lift, self._min_composite_lift
        ):
            return False, "composite_lift_below_threshold"

        return True, "VERIFIED"


__all__ = [
    "GcpSkillCertifier",
    "GcsArtifactHandshakePublisher",
    "GcsSkillCertificationVerifier",
    "compute_adapter_config_sha256",
    "compute_file_sha256",
]
