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

"""Cryptographic verification, RFC 8785 action hashing, and W3C traceparent helpers.

Zero vendor SDKs. Exactly two signature algorithms are accepted, the two the
gateway signs with: ``ES256`` (ECDSA on P-256 with SHA-256) and ``EdDSA``
(Ed25519). Every other algorithm is rejected, as is any key that is not P-256
or Ed25519. Canonicalization is RFC 8785 JCS, matching
``GovernanceEnvelopeBuilder``.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from ._jcs import canonicalize
from .exceptions import RoutingSealVerificationError
from .jwks import PublicKey, b64url_decode, jwk_to_public_key

_MAX_SAFE_INTEGER = 2**53 - 1
_P256_COORDINATE_BYTES = 32


def generate_w3c_traceparent() -> str:
    """Generate W3C Trace Context traceparent header.

    Returns compliant ``00-{trace_id}-{span_id}-01`` header using OpenTelemetry
    if available, or cryptographically secure hex fallback.
    """
    trace_id: str | None = None
    span_id: str | None = None

    try:
        from opentelemetry import trace

        current_span = trace.get_current_span()
        span_context = current_span.get_span_context()

        if span_context.is_valid:
            trace_id = f"{span_context.trace_id:032x}"
            span_id = f"{span_context.span_id:016x}"
    except (ImportError, AttributeError):
        pass

    if trace_id is None:
        trace_id = secrets.token_hex(16)
    if span_id is None:
        span_id = secrets.token_hex(8)

    return f"00-{trace_id}-{span_id}-01"


def _sanitize_for_action_hash(value: Any) -> Any:
    """Preserve JSON-native scalars/containers and stringify non-JSON leaves."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, Mapping):
        return {str(k): _sanitize_for_action_hash(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_action_hash(item) for item in value]
    return str(value)


def _validate_ijson(value: Any, path: str) -> Any:
    """Enforce RFC 7493 I-JSON numeric bounds matching server ``SEAL_CANON``."""
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise RoutingSealVerificationError(
                f"{path}: integer outside I-JSON ±(2**53-1) range"
            )
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RoutingSealVerificationError(f"{path}: non-finite float")
        return value
    if isinstance(value, dict):
        return {k: _validate_ijson(v, f"{path}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [_validate_ijson(v, f"{path}[{i}]") for i, v in enumerate(value)]
    raise RoutingSealVerificationError(
        f"{path}: unsupported canonicalization type {type(value).__name__}"
    )


def compute_expected_action_hash(action: str, parameters: Mapping[str, Any]) -> str:
    """Compute ``sha256:<hex>`` over RFC 8785 JCS ``{"action": action, "params": ...}``."""
    if not isinstance(action, str) or not action:
        raise RoutingSealVerificationError("action must be a non-empty string")
    if not isinstance(parameters, Mapping):
        raise RoutingSealVerificationError("parameters must be a mapping")
    sanitized = _sanitize_for_action_hash(parameters)
    strict_params = _validate_ijson(sanitized, "params")
    canonical_bytes = canonicalize({"action": action, "params": strict_params})
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def _describe_key(key: Any) -> str:
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name} key"
    return f"{type(key).__name__}"


def _validate_loaded_public_key(loaded: Any, *, kid: str) -> PublicKey:
    """Admit only EC P-256 and Ed25519 public keys."""
    if isinstance(loaded, ec.EllipticCurvePublicKey):
        if loaded.curve.name != "secp256r1":
            raise RoutingSealVerificationError(
                f"EC curve {loaded.curve.name!r} for kid={kid!r} is not accepted "
                "(only P-256)"
            )
        return loaded
    if isinstance(loaded, ed25519.Ed25519PublicKey):
        return loaded
    raise RoutingSealVerificationError(
        f"Public key type {type(loaded).__name__} for kid={kid!r} is not accepted "
        "(only EC P-256 and Ed25519)"
    )


def load_pinned_public_key(key_raw: Any, *, kid: str) -> PublicKey:
    """Parse and validate a pinned public key (PEM str/bytes, JWK dict, or key object)."""
    if isinstance(key_raw, Mapping):
        jwk_copy = dict(key_raw)
        jwk_copy.setdefault("kid", kid)
        try:
            _, pub_key = jwk_to_public_key(jwk_copy)
            return pub_key
        except RoutingSealVerificationError:
            raise
        except Exception as exc:
            raise RoutingSealVerificationError(
                f"Invalid pinned JWK public key for kid={kid!r}: {exc}"
            ) from exc

    if isinstance(key_raw, (str, bytes)):
        try:
            pem_bytes = key_raw.encode("utf-8") if isinstance(key_raw, str) else key_raw
            loaded = serialization.load_pem_public_key(pem_bytes)
        except Exception as exc:
            raise RoutingSealVerificationError(
                f"Invalid pinned PEM public key for kid={kid!r}: {exc}"
            ) from exc
        return _validate_loaded_public_key(loaded, kid=kid)

    return _validate_loaded_public_key(key_raw, kid=kid)


def _verify_es256(
    public_key: PublicKey, signature_bytes: bytes, canonical_bytes: bytes
) -> None:
    """ECDSA P-256 / SHA-256 over ``canonical_bytes`` (IEEE P1363 or DER signature)."""
    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or public_key.curve.name != "secp256r1"
    ):
        raise RoutingSealVerificationError(
            f"ES256 requires an EC P-256 key, got {_describe_key(public_key)}"
        )
    if len(signature_bytes) == 2 * _P256_COORDINATE_BYTES:
        r = int.from_bytes(signature_bytes[:_P256_COORDINATE_BYTES], "big")
        s = int.from_bytes(signature_bytes[_P256_COORDINATE_BYTES:], "big")
        if r <= 0 or s <= 0:
            raise RoutingSealVerificationError("Invalid ECDSA IEEE P1363 zero scalar")
        der_sig = utils.encode_dss_signature(r, s)
        try:
            public_key.verify(der_sig, canonical_bytes, ec.ECDSA(hashes.SHA256()))
            return
        except Exception as p1363_err:
            if signature_bytes[:1] != b"\x30":
                raise RoutingSealVerificationError(
                    f"GovernanceEnvelope ECDSA signature verification failed: {p1363_err}"
                ) from p1363_err
    try:
        public_key.verify(signature_bytes, canonical_bytes, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise RoutingSealVerificationError(
            f"GovernanceEnvelope ECDSA signature verification failed: {exc}"
        ) from exc


def _verify_eddsa(
    public_key: PublicKey, signature_bytes: bytes, canonical_bytes: bytes
) -> None:
    """Ed25519 over ``canonical_bytes``."""
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise RoutingSealVerificationError(
            f"EdDSA requires an Ed25519 key, got {_describe_key(public_key)}"
        )
    try:
        public_key.verify(signature_bytes, canonical_bytes)
    except Exception as exc:
        raise RoutingSealVerificationError(
            f"GovernanceEnvelope Ed25519 signature verification failed: {exc}"
        ) from exc


#: The accepted ``signature.algorithm`` values, matched exactly (case-sensitive),
#: each bound to the one key type and hash it may be verified with.
_VERIFIERS: dict[str, Callable[[PublicKey, bytes, bytes], None]] = {
    "ES256": _verify_es256,
    "EdDSA": _verify_eddsa,
}


def verify_envelope_signature(
    *,
    canonical_bytes: bytes,
    algorithm: str,
    signature_b64: str,
    public_key: PublicKey,
) -> None:
    """Verify ``signature_b64`` over RFC 8785 ``canonical_bytes``.

    ``algorithm`` must be exactly ``ES256`` (with an EC P-256 key) or ``EdDSA``
    (with an Ed25519 key). Any other value is rejected before the signature is
    decoded.
    """
    verifier = _VERIFIERS.get(algorithm)
    if verifier is None:
        raise RoutingSealVerificationError(
            f"Envelope signature algorithm {algorithm!r} is not accepted "
            f"(accepted: {', '.join(sorted(_VERIFIERS))})"
        )
    signature_bytes = b64url_decode(signature_b64, field_name="signature.value")
    verifier(public_key, signature_bytes, canonical_bytes)
