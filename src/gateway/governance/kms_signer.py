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
kms_signer.py — Cloud KMS Asymmetric Governance Signer (Priority 1)
====================================================================

Provides Google Cloud KMS asymmetric signing for governance plans.  The
previous in-process HMAC ``GOVERNANCE_SALT`` self-signing pattern has been
**removed** — it created a recursive self-authentication vulnerability where
the signing key lived in the same process memory as both the signer
(evaluator_node) and the verifier (explainer_node).

Architecture
------------
::

    ┌──────────────────────┐        ┌──────────────────────┐
    │   evaluator_node.py  │  gRPC  │   Google Cloud KMS   │
    │   (sign request)     │───────►│   HSM-backed key     │
    │                      │◄───────│   (private key never  │
    │                      │  sig   │    leaves the HSM)    │
    └──────────────────────┘        └──────────────────────┘
                                              │
                                    Cloud Audit Logs
                                    (immutable, external)
                                              │
    ┌──────────────────────┐                  ▼
    │  explainer_node.py   │   Verifies with public key
    │  (verify signature)  │   embedded at build time
    │                      │   (no KMS call needed)
    └──────────────────────┘

Security properties
-------------------
1. **Non-repudiation**: The private signing key never leaves the KMS HSM.
   A forensic auditor can request the Cloud Audit Log for the key ring
   and confirm exactly when and by what workload identity a signature was
   created.

2. **Separation of duties**: The signer (evaluator_node) calls KMS to
   produce a signature.  The verifier (explainer_node) uses only the public
   key — it never has access to the signing key material.

3. **External trust anchor**: The trust root (KMS HSM) is outside the
   application's control plane.  A compromised container cannot forge a
   signature without calling KMS, and that call is logged externally.

No fallback
-----------
The legacy HMAC ``GOVERNANCE_SALT`` fallback has been permanently removed.
If KMS is unavailable, ``sign()`` raises ``RuntimeError`` immediately so
the failure is explicit and audit-visible rather than silently degraded.
Use ``CAGE_ENV=development`` or ``CAGE_ENV=test`` to skip the startup
assertion in non-production environments; signing will still require KMS.

Environment variables
---------------------
  KMS_GOVERNANCE_KEY         — Full KMS key version resource name, e.g.:
                                projects/my-proj/locations/us-central1/
                                keyRings/cage-governance/cryptoKeys/
                                plan-signer/cryptoKeyVersions/1
  KMS_GOVERNANCE_PUBLIC_PEM  — Path to the PEM-encoded public key file
                                (embedded at container build time).
                                If unset, the public key is fetched from
                                KMS on first use (slower, but works).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Optional

from opentelemetry import trace as otel_trace

logger = logging.getLogger("Gateway.Governance.KMSSigner")
_tracer = otel_trace.get_tracer(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_KMS_KEY_VERSION: str = os.environ.get("KMS_GOVERNANCE_KEY", "")
_PUBLIC_PEM_PATH: str = os.environ.get("KMS_GOVERNANCE_PUBLIC_PEM", "")


def _canonicalise_plan(plan: dict) -> bytes:
    """Produce a deterministic byte representation of a governance plan.

    Uses ``json.dumps(sort_keys=True)`` with compact separators to guarantee
    byte-stable serialization — identical to the hash chain strategy in
    ``examples/telemetry.py``.
    """
    return json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# KMS Governance Signer
# ---------------------------------------------------------------------------


class KMSGovernanceSigner:
    """Asymmetric governance signature generator backed by Google Cloud KMS.

    Usage::

        signer = KMSGovernanceSigner.from_env()
        signature = signer.sign(plan_dict)
        is_valid  = signer.verify(plan_dict, signature)

    ``sign()`` calls ``asymmetricSign`` on the KMS HSM.
    ``verify()`` uses the locally-embedded public key (no KMS call needed).

    There is no HMAC fallback.  If KMS is unavailable, ``sign()`` raises
    ``RuntimeError`` so the failure is explicit and audit-visible.
    """

    def __init__(
        self,
        kms_client: object | None = None,
        key_version_name: str = "",
        public_key_pem: bytes = b"",
    ) -> None:
        self._kms_client = kms_client
        self._key_version_name = key_version_name
        self._public_key_pem = public_key_pem
        self._kms_active = kms_client is not None and bool(key_version_name)

    @property
    def is_kms_active(self) -> bool:
        """True if Cloud KMS signing is available (production mode)."""
        return self._kms_active

    @property
    def signing_algorithm(self) -> str:
        """Returns the active signing algorithm identifier for audit tagging."""
        return "KMS_ASYMMETRIC" if self._kms_active else "HMAC_SHA256_FALLBACK"

    @classmethod
    def from_env(cls) -> "KMSGovernanceSigner":
        """Construct from environment variables.

        Raises ``RuntimeError`` if ``KMS_GOVERNANCE_KEY`` is not set or the
        ``google-cloud-kms`` package is not installed.  There is no HMAC
        fallback — failures must be explicit.
        """
        if not _KMS_KEY_VERSION:
            raise RuntimeError(
                "[KMSSigner] KMS_GOVERNANCE_KEY is not set. "
                "Set it to the full Cloud KMS key version resource name. "
                "The legacy HMAC GOVERNANCE_SALT fallback has been removed. "
                "See CTRL_KMS_001 in control_mappings.json."
            )

        try:
            from google.cloud import kms  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "[KMSSigner] google-cloud-kms is not installed. "
                "Install with: pip install google-cloud-kms"
            ) from exc

        try:
            kms_client = kms.KeyManagementServiceClient()
            logger.info(
                "[KMSSigner] Cloud KMS client initialised for key: %s",
                _KMS_KEY_VERSION,
            )
        except Exception as exc:
            raise RuntimeError(
                f"[KMSSigner] KMS client init failed: {exc}. "
                "Check workload identity / ADC credentials."
            ) from exc

        public_key_pem = b""
        # Load public key — prefer local PEM file (build-time embed)
        if _PUBLIC_PEM_PATH and os.path.isfile(_PUBLIC_PEM_PATH):
            with open(_PUBLIC_PEM_PATH, "rb") as f:
                public_key_pem = f.read()
            logger.info("[KMSSigner] Public key loaded from: %s", _PUBLIC_PEM_PATH)
        else:
            # Fetch from KMS (first-use bootstrap)
            try:
                response = kms_client.get_public_key(name=_KMS_KEY_VERSION)
                public_key_pem = response.pem.encode("utf-8")
                logger.info(
                    "[KMSSigner] Public key fetched from KMS "
                    "(embed in container image for production)."
                )
            except Exception as pk_exc:
                raise RuntimeError(
                    f"[KMSSigner] Failed to fetch public key from KMS: {pk_exc}. "
                    "Set KMS_GOVERNANCE_PUBLIC_PEM to a local PEM file path."
                ) from pk_exc

        return cls(
            kms_client=kms_client,
            key_version_name=_KMS_KEY_VERSION,
            public_key_pem=public_key_pem,
        )

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    def sign(self, plan: dict) -> str:
        """Sign a governance plan and return the hex-encoded signature.

        Computes SHA-256 digest of the canonical plan, calls
        ``asymmetricSign`` on the KMS HSM, and returns the hex-encoded
        signature bytes.

        Raises:
            RuntimeError: If KMS signing fails.  There is no HMAC fallback.
        """
        if not self._kms_active:
            raise RuntimeError(
                "[KMSSigner] sign() called but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        plan_bytes = _canonicalise_plan(plan)
        with _tracer.start_as_current_span("cage.kms_signer.sign") as span:
            span.set_attribute("cage.signing.algorithm", self.signing_algorithm)
            span.set_attribute("cage.signing.kms_active", self._kms_active)
            return self._kms_sign(plan_bytes)

    def _kms_sign(self, plan_bytes: bytes) -> str:
        """Sign via Cloud KMS asymmetricSign API.

        Raises ``RuntimeError`` on failure — no HMAC fallback.
        """
        try:
            from google.cloud.kms_v1.types import service as kms_service  # type: ignore[import]

            digest = hashlib.sha256(plan_bytes).digest()

            response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr]
                request=kms_service.AsymmetricSignRequest(
                    name=self._key_version_name,
                    digest=kms_service.Digest(sha256=digest),
                ),
            )

            signature_hex = response.signature.hex()
            logger.info(
                "[KMSSigner] KMS signature generated: %s... (key=%s)",
                signature_hex[:16],
                self._key_version_name.split("/")[-1],
            )
            return signature_hex

        except Exception as exc:
            logger.critical(
                json.dumps({
                    "event": "KMS_SIGNING_FAILED",
                    "severity": "CRITICAL",
                    "kms_key": self._key_version_name,
                    "error": str(exc),
                    "audit_note": "signing failed — no fallback; trade blocked",
                })
            )
            raise RuntimeError(
                f"[KMSSigner] KMS asymmetricSign failed: {exc}. "
                "The HMAC fallback has been removed. Fix KMS connectivity."
            ) from exc

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify(self, plan: dict, signature_hex: str) -> bool:
        """Verify a governance signature against a plan.

        Uses the RSA/EC public key to verify the KMS-produced signature
        locally — no KMS gRPC call needed.

        Returns:
            True if the signature is valid.
        """
        if not signature_hex:
            return False

        if not self._public_key_pem:
            raise RuntimeError(
                "[KMSSigner] verify() called but no public key is loaded. "
                "Ensure KMS_GOVERNANCE_PUBLIC_PEM is set or KMS bootstrap succeeded."
            )

        plan_bytes = _canonicalise_plan(plan)
        return self._kms_verify(plan_bytes, signature_hex)

    def _kms_verify(self, plan_bytes: bytes, signature_hex: str) -> bool:
        """Verify using the KMS public key (local, no gRPC call)."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import (
                ec,
                padding,
                utils as asym_utils,
            )

            public_key = serialization.load_pem_public_key(self._public_key_pem)
            signature_bytes = bytes.fromhex(signature_hex)
            digest = hashlib.sha256(plan_bytes).digest()

            # Support both RSA and EC keys
            if hasattr(public_key, "verify"):
                try:
                    # Try EC first (Cloud KMS default for signing)
                    public_key.verify(  # type: ignore[union-attr]
                        signature_bytes,
                        digest,
                        ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())),
                    )
                    return True
                except (TypeError, AttributeError):
                    # Try RSA-PSS
                    public_key.verify(  # type: ignore[union-attr]
                        signature_bytes,
                        digest,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        asym_utils.Prehashed(hashes.SHA256()),
                    )
                    return True

        except Exception as exc:
            logger.warning(
                "[KMSSigner] KMS public key verification failed: %s",
                exc,
            )
            return False

        return False


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init)
# ---------------------------------------------------------------------------

_signer: Optional[KMSGovernanceSigner] = None


def get_governance_signer() -> KMSGovernanceSigner:
    """Return the module-level KMSGovernanceSigner singleton.

    Lazily initialised on first call.  Thread-safe because Python's GIL
    guarantees atomic reference assignment.
    """
    global _signer
    if _signer is None:
        _signer = KMSGovernanceSigner.from_env()
    return _signer


def assert_kms_active_in_production() -> None:
    """Raise RuntimeError if HMAC fallback is active in a production environment.

    Call this during application startup. Safe to call multiple times.
    Checks CAGE_ENV / ENVIRONMENT to determine if production rules apply.
    """
    env = (os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")).lower()
    if env in ("development", "test", "dev", "ci"):
        return
    signer = get_governance_signer()
    if not signer.is_kms_active:
        raise RuntimeError(
            "CAGE STARTUP FAILURE: KMSGovernanceSigner is in HMAC fallback mode "
            "in a non-development environment. Set KMS_GOVERNANCE_KEY to the full "
            "Cloud KMS key version resource name. "
            "Evidentiary independence control violation (see CTRL_KMS_001 in control_mappings.json)."
        )
