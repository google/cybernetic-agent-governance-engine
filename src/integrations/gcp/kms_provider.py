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

"""Google Cloud KMS HSM provider (Layer 3 integration)."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from src.gateway.governance.env_posture import is_enforcing, resolve_posture
from src.gateway.governance.kms_signer import BaseKMSProvider

logger = logging.getLogger("Gateway.Governance.KMSSigner")

# CryptoKeyVersionAlgorithm names (as returned by CryptoKeyVersion.algorithm)
# that use each hash width. Anything not listed here defaults to SHA-256,
# preserving prior behaviour for EC_SIGN_P256_SHA256 and similar keys.
_GCP_KMS_SHA384_ALGORITHMS = frozenset(
    {
        "RSA_SIGN_PKCS1_3072_SHA384",
        "RSA_SIGN_PSS_3072_SHA384",
        "EC_SIGN_P384_SHA384",
    }
)
_GCP_KMS_SHA512_ALGORITHMS = frozenset(
    {
        "RSA_SIGN_PKCS1_4096_SHA512",
        "RSA_SIGN_PSS_4096_SHA512",
    }
)
_GCP_KMS_ED25519_ALGORITHMS = frozenset(
    {
        "EC_SIGN_ED25519",
    }
)

# RFC 7518 JOSE identifier for each supported CryptoKeyVersionAlgorithm.
_GCP_KMS_JOSE_ALGORITHMS: dict[str, str] = {
    "EC_SIGN_P256_SHA256": "ES256",
    "EC_SIGN_P384_SHA384": "ES384",
    "EC_SIGN_ED25519": "EdDSA",
    "RSA_SIGN_PSS_2048_SHA256": "PS256",
    "RSA_SIGN_PSS_3072_SHA256": "PS256",
    "RSA_SIGN_PSS_4096_SHA256": "PS256",
    "RSA_SIGN_PSS_3072_SHA384": "PS384",
    "RSA_SIGN_PSS_4096_SHA512": "PS512",
    "RSA_SIGN_PKCS1_2048_SHA256": "RS256",
    "RSA_SIGN_PKCS1_3072_SHA256": "RS256",
    "RSA_SIGN_PKCS1_4096_SHA256": "RS256",
    "RSA_SIGN_PKCS1_3072_SHA384": "RS384",
    "RSA_SIGN_PKCS1_4096_SHA512": "RS512",
}

# After a failed lookup on first use, reads fail fast for this long instead
# of queueing another GetCryptoKeyVersion call behind the lock.
_ALGORITHM_LOOKUP_BACKOFF_S = 10.0
_LOOKUP_BACKOFF_MESSAGE = (
    "[KMSSigner] Key algorithm lookup failed recently; next attempt after a "
    f"{_ALGORITHM_LOOKUP_BACKOFF_S:g}s backoff."
)


@dataclass(frozen=True, slots=True)
class _KeyAlgorithm:
    """Signing metadata derived from a key version's algorithm name.

    Cloud KMS fixes a key version's algorithm when the version is created,
    so one lookup stays valid for the provider's lifetime. A name outside
    ``_GCP_KMS_JOSE_ALGORITHMS`` is not ``recognized``: it gets the SHA-256 /
    ES256 fallback, which only permissive postures accept.
    """

    name: str
    digest: str
    jose_alg: str
    rsa_pss: bool
    recognized: bool

    @classmethod
    def from_name(cls, name: str) -> _KeyAlgorithm:
        if name in _GCP_KMS_SHA512_ALGORITHMS:
            digest = "sha512"
        elif name in _GCP_KMS_SHA384_ALGORITHMS:
            digest = "sha384"
        elif name in _GCP_KMS_ED25519_ALGORITHMS:
            digest = "raw"
        else:
            digest = "sha256"
        jose_alg = _GCP_KMS_JOSE_ALGORITHMS.get(name)
        if jose_alg is None:
            logger.warning(
                "[KMSSigner] Unknown GCP algorithm %s: permissive postures fall "
                "back to SHA-256/ES256, enforcing postures refuse to sign",
                name,
            )
        return cls(
            name=name,
            digest=digest,
            jose_alg=jose_alg or "ES256",
            rsa_pss="PSS" in name,
            recognized=jose_alg is not None,
        )


class GCPKMSProvider(BaseKMSProvider):
    """Google Cloud KMS HSM provider.

    The key version's algorithm is read once and cached, so signing makes no
    ``GetCryptoKeyVersion`` call. Under an enforcing posture the provider
    never signs with a guessed algorithm: one that cannot be read, or is not
    supported, makes ``digest_algorithm`` and ``jose_alg`` raise.
    """

    def __init__(
        self, key_version_name: str = "", kms_client: object | None = None
    ) -> None:
        self._key_version_name = key_version_name
        self._kms_client = kms_client
        self._key_algorithm: _KeyAlgorithm | None = None
        self._algorithm_lock = threading.Lock()
        # time.monotonic() before which a failed lookup is not retried, and
        # that lookup's error.
        self._lookup_retry_at = 0.0
        self._lookup_error = ""
        if not kms_client and key_version_name:
            try:
                from google.cloud import kms  # type: ignore[import]
            except ImportError as exc:
                raise RuntimeError(
                    "[KMSSigner] google-cloud-kms is not installed. "
                    "Install with: pip install google-cloud-kms"
                ) from exc
            try:
                self._kms_client = kms.KeyManagementServiceClient()
                logger.info(
                    "[GCPKMSProvider] Client initialised for key: %s",
                    self._key_version_name,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"[KMSSigner] KMS client init failed: {exc}. Check workload identity / ADC credentials."
                ) from exc
        self._detect_hash_width()

    def _cache_key_algorithm(self, algorithm_name: str) -> _KeyAlgorithm:
        """Cache the algorithm read from the key version.

        Callers must hold ``_algorithm_lock``.
        """
        key_algorithm = _KeyAlgorithm.from_name(algorithm_name)
        self._key_algorithm = key_algorithm
        logger.info(
            "[GCPKMSProvider] Key algorithm=%s → digest width=%s",
            key_algorithm.name,
            key_algorithm.digest,
        )
        return key_algorithm

    def _fetch_key_algorithm(self) -> _KeyAlgorithm:
        """Read the key version's algorithm from Cloud KMS and cache it.

        Callers must hold ``_algorithm_lock``.
        """
        version = self._kms_client.get_crypto_key_version(  # type: ignore[union-attr, attr-defined]
            name=self._key_version_name
        )
        return self._cache_key_algorithm(str(version.algorithm.name))

    def _detect_hash_width(self) -> None:
        """Read and cache the key algorithm, which fixes the digest width.

        A failure is logged and the first use retries the lookup (see
        :meth:`_resolve_key_algorithm`).
        """
        if not self._kms_client or not self._key_version_name:
            return
        try:
            with self._algorithm_lock:
                self._fetch_key_algorithm()
        except Exception as exc:
            logger.warning(
                "[GCPKMSProvider] Could not determine key algorithm; retrying "
                "on first use: %s",
                exc,
            )

    def _resolve_key_algorithm(self) -> _KeyAlgorithm:
        """Return the cached key algorithm, fetching it if still unknown.

        Concurrent callers share one lookup. After a failed lookup, reads
        fail fast for ``_ALGORITHM_LOOKUP_BACKOFF_S`` before the next attempt.

        Raises:
            RuntimeError: If the provider has no client or key version name,
                or a lookup failed within the backoff window.
            Exception: Any error from the Cloud KMS lookup.
        """
        key_algorithm = self._key_algorithm
        if key_algorithm is not None:
            return key_algorithm
        if not self._kms_client or not self._key_version_name:
            raise RuntimeError(
                "[KMSSigner] GCP KMS provider has no client or key version name."
            )
        if time.monotonic() < self._lookup_retry_at:
            raise self._backoff_error()
        with self._algorithm_lock:
            if self._key_algorithm is not None:
                return self._key_algorithm
            if time.monotonic() < self._lookup_retry_at:
                raise self._backoff_error()
            try:
                return self._fetch_key_algorithm()
            except Exception as exc:
                # Set the error before the deadline: lock-free readers that
                # see the deadline must also see its cause.
                self._lookup_error = f"{type(exc).__name__}: {exc}"
                self._lookup_retry_at = time.monotonic() + _ALGORITHM_LOOKUP_BACKOFF_S
                logger.warning(
                    "[GCPKMSProvider] Key algorithm lookup failed; next attempt "
                    "in %gs: %s",
                    _ALGORITHM_LOOKUP_BACKOFF_S,
                    self._lookup_error,
                )
                raise

    def _backoff_error(self) -> RuntimeError:
        """The fail-fast error for reads inside the backoff window."""
        return RuntimeError(
            f"{_LOOKUP_BACKOFF_MESSAGE} Last error: {self._lookup_error}"
        )

    def _supported(self, key_algorithm: _KeyAlgorithm) -> _KeyAlgorithm:
        """Return ``key_algorithm``; an enforcing posture refuses an unsupported one."""
        if not key_algorithm.recognized and is_enforcing(resolve_posture()):
            raise RuntimeError(
                f"[KMSSigner] Unsupported GCP KMS algorithm {key_algorithm.name!r} "
                f"for {self._key_version_name!r}; an enforcing posture does not "
                "sign with a fallback algorithm."
            )
        return key_algorithm

    def warm_channel(self) -> None:
        """Pre-warm the KMS gRPC channel by querying key version metadata."""
        self._detect_hash_width()

    @property
    def provider_name(self) -> str:
        return "KMS_ASYMMETRIC"

    @property
    def digest_algorithm(self) -> str:
        """Digest width for the key's algorithm.

        Under an enforcing posture an algorithm that cannot be read, or is
        not supported, raises rather than guess; other postures fall back to
        SHA-256.
        """
        try:
            key_algorithm = self._resolve_key_algorithm()
        except Exception as exc:
            if is_enforcing(resolve_posture()):
                raise RuntimeError(
                    "[KMSSigner] Cannot determine the digest width for "
                    f"{self._key_version_name!r}: {exc}"
                ) from exc
            return "sha256"
        return self._supported(key_algorithm).digest

    @property
    def expects_raw_message(self) -> bool:
        return self.digest_algorithm == "raw"

    @property
    def jose_alg(self) -> str:
        """Map the GCP CryptoKeyVersionAlgorithm to its RFC 7518 JOSE name."""
        if not self._kms_client or not self._key_version_name:
            raise RuntimeError(
                "[KMSSigner] GCP KMS provider has no client or key version name."
            )
        try:
            key_algorithm = self._resolve_key_algorithm()
        except Exception as exc:
            raise RuntimeError(
                f"[KMSSigner] Failed to determine JOSE algorithm: {exc}"
            ) from exc
        return self._supported(key_algorithm).jose_alg

    @property
    def uses_rsa_pss(self) -> bool:
        """True if the active GCP KMS key version uses RSA-PSS padding."""
        try:
            return self._resolve_key_algorithm().rsa_pss
        except Exception:
            return False

    def validate_ready(self, key_version_name: str = "") -> None:
        """Verify the GCP KMS key version exists and is in ENABLED state.

        For the provider's own key this also caches the version's algorithm
        (no extra call) and, under an enforcing posture, raises if that
        algorithm is not supported.
        """
        target_key = key_version_name or self._key_version_name
        if self._kms_client is not None:
            version = self._kms_client.get_crypto_key_version(  # type: ignore[attr-defined]
                name=target_key
            )
            if version.state.name not in ("ENABLED",):
                raise RuntimeError(
                    f"KMS key version {target_key!r} is in state "
                    f"{version.state.name!r} — expected ENABLED"
                )
            if target_key == self._key_version_name:
                with self._algorithm_lock:
                    key_algorithm = self._key_algorithm or self._cache_key_algorithm(
                        str(version.algorithm.name)
                    )
                self._supported(key_algorithm)
        else:
            self.get_public_key_pem()

    def sign_digest(self, digest: bytes) -> bytes:
        from google.cloud.kms_v1.types import (
            service as kms_service,  # type: ignore[import]
        )

        digest_kwargs = {self.digest_algorithm: digest}
        response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr]
            request=kms_service.AsymmetricSignRequest(
                name=self._key_version_name,
                digest=kms_service.Digest(**digest_kwargs),
            )
        )
        return response.signature

    def sign_raw(self, message: bytes) -> bytes:
        from google.cloud.kms_v1.types import (
            service as kms_service,  # type: ignore[import]
        )

        response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr]
            request=kms_service.AsymmetricSignRequest(
                name=self._key_version_name,
                data=message,
            )
        )
        return response.signature

    def get_public_key_pem(self) -> bytes:
        response = self._kms_client.get_public_key(name=self._key_version_name)  # type: ignore[union-attr]
        return response.pem.encode("utf-8")

    def get_public_keys_pem(self) -> dict[str, bytes]:
        """Fetch all ENABLED public keys for the CryptoKey to support rotation."""
        parts = self._key_version_name.split("/cryptoKeyVersions/")
        if len(parts) != 2:
            return {self._key_version_name: self.get_public_key_pem()}

        crypto_key_name = parts[0]
        keys = {}
        try:
            versions = self._kms_client.list_crypto_key_versions(parent=crypto_key_name)  # type: ignore[union-attr]
            for v in versions:
                if v.state.name == "ENABLED":
                    pub = self._kms_client.get_public_key(name=v.name)  # type: ignore[union-attr]
                    keys[v.name] = pub.pem.encode("utf-8")
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Failed to list crypto key versions: %s", exc
            )

        if not keys:
            keys[self._key_version_name] = self.get_public_key_pem()
        return keys
