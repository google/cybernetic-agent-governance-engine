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

"""Reconciler signing identity and ``kid``-resolved snapshot verification.

The ground-truth reconciler and the gateway hold **separate** signing keys:

* ``KMS_GOVERNANCE_KEY`` — the gateway's own routing-seal / decision key.
* ``RECONCILER_KMS_KEY`` — the reconciler's snapshot-signing key.

The reconciler signs every ground-truth snapshot with ``RECONCILER_KMS_KEY``
and records the signing ``kid`` and algorithm in the snapshot. The CBF
verifies snapshots against an explicit trust-anchor set that contains only
the reconciler's public key(s), fetched out-of-band from the KMS provider.
A snapshot signed by the gateway's own key is rejected even if the signature
is cryptographically valid: a compromised gateway must not be able to mint
its own ground truth.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from src.gateway.governance.kms_signer import KMSGovernanceSigner

logger = logging.getLogger(__name__)

RECONCILER_KMS_KEY_ENV = "RECONCILER_KMS_KEY"
GATEWAY_KMS_KEY_ENV = "KMS_GOVERNANCE_KEY"

_VERSION_SEPARATOR = "/cryptoKeyVersions/"

_lock = threading.Lock()
_reconciler_signer: KMSGovernanceSigner | None = None
_reconciler_verifier: KMSGovernanceSigner | None = None


def _crypto_key_of(name: str) -> str:
    """Return the key identity of ``name`` with any version suffix removed."""
    return name.split(_VERSION_SEPARATOR, 1)[0].strip()


def _reconciler_key_name() -> str:
    return os.environ.get(RECONCILER_KMS_KEY_ENV, "").strip()


def _gateway_key_name() -> str:
    return os.environ.get(GATEWAY_KMS_KEY_ENV, "").strip()


def is_gateway_kid(kid: str) -> bool:
    """True if ``kid`` belongs to the gateway's own signing key."""
    gateway_key = _gateway_key_name()
    if not gateway_key or not kid:
        return False
    return _crypto_key_of(kid) == _crypto_key_of(gateway_key)


def _build_reconciler_provider() -> Any:
    """Build the KMS provider for ``RECONCILER_KMS_KEY`` (fail-closed)."""
    key_name = _reconciler_key_name()
    if not key_name:
        raise RuntimeError(
            f"{RECONCILER_KMS_KEY_ENV} is not set; the reconciler signing "
            "identity is unconfigured."
        )
    if is_gateway_kid(key_name):
        raise RuntimeError(
            f"{RECONCILER_KMS_KEY_ENV} must not reference the gateway key "
            f"({GATEWAY_KMS_KEY_ENV}); reconciler and gateway keys must be "
            "separate."
        )

    from src.gateway.governance.signer_factory import build_kms_provider

    provider_name = (
        os.environ.get("KMS_PROVIDER") or os.environ.get("CAGE_KMS_PROVIDER") or "gcp"
    ).lower()
    if provider_name == "gcp":
        return build_kms_provider(provider_name, key_version_name=key_name)
    if provider_name == "aws":
        return build_kms_provider(provider_name, key_id=key_name)
    raise RuntimeError(
        f"KMS provider {provider_name!r} is not supported for the reconciler "
        "signing identity. Use 'gcp' or 'aws'."
    )


def build_reconciler_signer() -> KMSGovernanceSigner:
    """Build the signer the reconciler uses to sign ground-truth snapshots."""
    return KMSGovernanceSigner(provider=_build_reconciler_provider())


def load_reconciler_trust_anchors() -> dict[str, bytes]:
    """Fetch the reconciler's public keys (``kid -> PEM``) from the provider.

    Returns an empty mapping when ``RECONCILER_KMS_KEY`` is unset, so every
    signed snapshot resolves to an unknown ``kid`` and fails closed.
    """
    if not _reconciler_key_name():
        logger.warning(
            "%s is not set — no reconciler trust anchors loaded; signed "
            "ground-truth snapshots will fail verification.",
            RECONCILER_KMS_KEY_ENV,
        )
        return {}
    anchors = _build_reconciler_provider().get_public_keys_pem()
    return {kid: pem for kid, pem in anchors.items() if pem and not is_gateway_kid(kid)}


def build_reconciler_verifier(
    trust_anchors: dict[str, bytes] | None = None,
) -> KMSGovernanceSigner:
    """Build a verify-only signer whose only trust anchors are the reconciler's.

    The instance has no provider and no own key, so ``verify_decision`` can
    only resolve the injected ``kid``s — never the gateway key.
    """
    anchors = (
        load_reconciler_trust_anchors() if trust_anchors is None else trust_anchors
    )
    return KMSGovernanceSigner(provider=None, trust_anchors=dict(anchors))


def get_reconciler_signer() -> KMSGovernanceSigner:
    """Return the cached reconciler signer (raises if unconfigured)."""
    global _reconciler_signer
    with _lock:
        if _reconciler_signer is None:
            _reconciler_signer = build_reconciler_signer()
        return _reconciler_signer


def get_reconciler_verifier() -> KMSGovernanceSigner:
    """Return the cached reconciler-only verifier."""
    global _reconciler_verifier
    with _lock:
        if _reconciler_verifier is None:
            _reconciler_verifier = build_reconciler_verifier()
        return _reconciler_verifier


def reset_reconciler_trust() -> None:
    """Drop cached reconciler signer/verifier (for tests and key rotation)."""
    global _reconciler_signer, _reconciler_verifier
    with _lock:
        _reconciler_signer = None
        _reconciler_verifier = None


def snapshot_signing_payload(snapshot: Any) -> dict[str, Any]:
    """Return the canonical payload covered by a snapshot signature."""
    return {
        "source": snapshot.source,
        "state_scalar": float(snapshot.state_scalar),
        "verified_at": snapshot.verified_at,
        "sequence": snapshot.sequence,
    }


def verify_snapshot_signature(
    snapshot: Any,
    verifier: KMSGovernanceSigner | None = None,
) -> bool:
    """Verify a ground-truth snapshot signature against reconciler anchors.

    Fails closed (returns ``False``) when the signature, ``kid`` or algorithm
    is missing, when the ``kid`` is the gateway's own key, or when the ``kid``
    is not in the verifier's trust anchors. Errors while loading the trust
    anchors propagate so callers can treat them as ground truth unavailable.
    """
    signature = getattr(snapshot, "signature", "")
    kid = getattr(snapshot, "kms_key_id", "")
    algorithm = getattr(snapshot, "signing_algorithm", "")
    if not (isinstance(signature, str) and signature):
        return False
    if not (isinstance(kid, str) and kid):
        logger.critical(
            "Ground-truth snapshot carries no signing kid — failing closed."
        )
        return False
    if not (isinstance(algorithm, str) and algorithm):
        logger.critical(
            "Ground-truth snapshot carries no signing algorithm — failing closed."
        )
        return False
    if is_gateway_kid(kid):
        logger.critical(
            "Ground-truth snapshot signed by the gateway key (kid=%r) — "
            "rejected; only the reconciler key may sign ground truth.",
            kid,
        )
        return False

    active = verifier if verifier is not None else get_reconciler_verifier()
    return bool(
        active.verify_decision(
            snapshot_signing_payload(snapshot),
            signature,
            kid=kid,
            algorithm=algorithm,
        )
    )


__all__ = [
    "GATEWAY_KMS_KEY_ENV",
    "RECONCILER_KMS_KEY_ENV",
    "build_reconciler_signer",
    "build_reconciler_verifier",
    "get_reconciler_signer",
    "get_reconciler_verifier",
    "is_gateway_kid",
    "load_reconciler_trust_anchors",
    "reset_reconciler_trust",
    "snapshot_signing_payload",
    "verify_snapshot_signature",
]
