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

Zero vendor SDKs. Enforces strict algorithm-to-key/curve/hash binding and RFC 8785
JCS canonicalization matching ``GovernanceEnvelopeBuilder``.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    rsa,
    utils,
)
from cryptography.hazmat.primitives.asymmetric import (
    padding as rsa_padding,
)

from ._jcs import canonicalize
from .exceptions import RoutingSealVerificationError
from .jwks import PublicKey, b64url_decode, jwk_to_public_key

_MAX_SAFE_INTEGER = 2**53 - 1
_MIN_RSA_BITS = 2048

_EC_ALG_BINDINGS: dict[str, tuple[str, hashes.HashAlgorithm]] = {
    "ES256": ("secp256r1", hashes.SHA256()),
    "ECDSA_P256_SHA256": ("secp256r1", hashes.SHA256()),
    "ES384": ("secp384r1", hashes.SHA384()),
    "ECDSA_P384_SHA384": ("secp384r1", hashes.SHA384()),
    "ES512": ("secp521r1", hashes.SHA512()),
    "ECDSA_P521_SHA512": ("secp521r1", hashes.SHA512()),
}

_RSA_PKCS1_ALGS: dict[str, hashes.HashAlgorithm] = {
    "RS256": hashes.SHA256(),
    "RS384": hashes.SHA384(),
    "RS512": hashes.SHA512(),
}

_RSA_PSS_ALGS: dict[str, hashes.HashAlgorithm] = {
    "PS256": hashes.SHA256(),
    "PS384": hashes.SHA384(),
    "PS512": hashes.SHA512(),
}


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


def _validate_loaded_public_key(loaded: Any, *, kid: str) -> PublicKey:
    if isinstance(loaded, ec.EllipticCurvePublicKey):
        if loaded.curve.name not in {"secp256r1", "secp384r1", "secp521r1"}:
            raise RoutingSealVerificationError(
                f"Unsupported EC curve {loaded.curve.name!r} for kid={kid!r}"
            )
        return loaded
    if isinstance(loaded, ed25519.Ed25519PublicKey):
        return loaded
    if isinstance(loaded, rsa.RSAPublicKey):
        if loaded.key_size < _MIN_RSA_BITS:
            raise RoutingSealVerificationError(
                f"RSA key size {loaded.key_size} < {_MIN_RSA_BITS} bits for kid={kid!r}"
            )
        return loaded
    raise RoutingSealVerificationError(
        f"Unsupported public key type {type(loaded).__name__} for kid={kid!r}"
    )


def load_pinned_public_key(key_raw: Any, *, kid: str) -> PublicKey:
    """Parse and validate a pinned public key (PEM str/bytes, PublicKey, or JWK dict)."""
    if isinstance(
        key_raw,
        (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, rsa.RSAPublicKey),
    ):
        return _validate_loaded_public_key(key_raw, kid=kid)

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

    raise RoutingSealVerificationError(
        f"Unsupported pinned public key representation {type(key_raw).__name__} for kid={kid!r}"
    )


def _verify_ec_signature(
    public_key: ec.EllipticCurvePublicKey,
    alg: str,
    signature_bytes: bytes,
    canonical_bytes: bytes,
) -> None:
    binding = _EC_ALG_BINDINGS.get(alg)
    if binding is None:
        raise RoutingSealVerificationError(
            f"Algorithm {alg!r} is incompatible with EC public key"
        )
    expected_curve, hash_alg = binding
    if public_key.curve.name != expected_curve:
        raise RoutingSealVerificationError(
            f"Algorithm {alg!r} requires curve {expected_curve!r}, "
            f"got {public_key.curve.name!r}"
        )
    key_size = (public_key.curve.key_size + 7) // 8
    if len(signature_bytes) == key_size * 2:
        r = int.from_bytes(signature_bytes[:key_size], "big")
        s = int.from_bytes(signature_bytes[key_size:], "big")
        if r <= 0 or s <= 0:
            raise RoutingSealVerificationError("Invalid ECDSA IEEE P1363 zero scalar")
        der_sig = utils.encode_dss_signature(r, s)
        try:
            public_key.verify(der_sig, canonical_bytes, ec.ECDSA(hash_alg))
            return
        except Exception as p1363_err:
            if signature_bytes[:1] != b"\x30":
                raise RoutingSealVerificationError(
                    f"GovernanceEnvelope ECDSA signature verification failed: {p1363_err}"
                ) from p1363_err
    try:
        public_key.verify(signature_bytes, canonical_bytes, ec.ECDSA(hash_alg))
    except Exception as exc:
        raise RoutingSealVerificationError(
            f"GovernanceEnvelope ECDSA signature verification failed: {exc}"
        ) from exc


def _verify_rsa_signature(
    public_key: rsa.RSAPublicKey,
    alg: str,
    signature_bytes: bytes,
    canonical_bytes: bytes,
) -> None:
    if public_key.key_size < _MIN_RSA_BITS:
        raise RoutingSealVerificationError(
            f"RSA key size {public_key.key_size} < {_MIN_RSA_BITS} bits"
        )
    if alg in _RSA_PKCS1_ALGS:
        hash_alg = _RSA_PKCS1_ALGS[alg]
        pad: rsa_padding.AsymmetricPadding = rsa_padding.PKCS1v15()
    elif alg in _RSA_PSS_ALGS:
        hash_alg = _RSA_PSS_ALGS[alg]
        pad = rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hash_alg),
            salt_length=rsa_padding.PSS.AUTO,
        )
    else:
        raise RoutingSealVerificationError(
            f"Algorithm {alg!r} is incompatible with RSA public key"
        )
    try:
        public_key.verify(signature_bytes, canonical_bytes, pad, hash_alg)
    except Exception as exc:
        raise RoutingSealVerificationError(
            f"GovernanceEnvelope RSA signature verification failed: {exc}"
        ) from exc


def verify_envelope_signature(
    *,
    canonical_bytes: bytes,
    algorithm: str,
    signature_b64: str,
    public_key: PublicKey,
) -> None:
    """Verify ``signature_b64`` over RFC 8785 ``canonical_bytes`` with strict alg/key binding."""
    alg = algorithm.strip().upper()
    if not alg or alg == "NONE" or alg.startswith("HS") or alg.startswith("HMAC"):
        raise RoutingSealVerificationError(
            f"Forbidden or non-asymmetric envelope signature algorithm {algorithm!r}"
        )
    signature_bytes = b64url_decode(signature_b64, field_name="signature.value")

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        _verify_ec_signature(public_key, alg, signature_bytes, canonical_bytes)
        return
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        if alg not in {"EDDSA", "ED25519"}:
            raise RoutingSealVerificationError(
                f"Algorithm {alg!r} is incompatible with Ed25519 public key"
            )
        try:
            public_key.verify(signature_bytes, canonical_bytes)
        except Exception as exc:
            raise RoutingSealVerificationError(
                f"GovernanceEnvelope Ed25519 signature verification failed: {exc}"
            ) from exc
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        _verify_rsa_signature(public_key, alg, signature_bytes, canonical_bytes)
        return
    raise RoutingSealVerificationError(
        f"Unsupported public key type: {type(public_key).__name__}"
    )
