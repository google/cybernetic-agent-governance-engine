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

"""Cryptographic W3C WebAuthn assertion verifier for HITL approvals (POAM-2026-210).

Enforces W3C WebAuthn Level 2/3 §7.2 ``AuthenticatorAssertionResponse`` verification
against an out-of-band operator credential registry:

  - Never accepts caller-embedded public keys or trusts caller-stamped ``auth_method``
    to skip verification in enforcing postures.
  - Resolves asymmetric public keys (``ES256`` P-256, ``EdDSA`` Ed25519, ``RS256``
    >=2048-bit RSA) strictly out-of-band from ``CAGE_WEBAUTHN_CREDENTIALS_JSON`` or
    ``CAGE_WEBAUTHN_CREDENTIALS_FILE``, bound 1-to-1 to ``(operator_urn, credential_id)``,
    rejecting symmetric or private key material.
  - Validates ``clientDataJSON`` (``type == "webauthn.get"``, ``crossOrigin`` not
    ``True``, 32-byte ``challenge`` digest matching ``challenge_binding`` and
    server-derived ``expected_bindings``, and ``origin`` pinned to
    ``CAGE_WEBAUTHN_ALLOWED_ORIGINS`` within ``CAGE_WEBAUTHN_RP_ID`` scope).
  - Validates binary ``authenticatorData`` (>=37 bytes: 32-byte ``SHA-256(rp_id)``,
    ``UP`` ``0x01`` and ``UV`` ``0x04`` flags set, consistent ``BE``/``BS`` flags).
  - Cryptographically verifies ``signature`` over
    ``authenticatorData || SHA-256(clientDataJSON)``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from src.gateway.governance.env_posture import env_flag, is_enforcing

logger = logging.getLogger(__name__)

ALLOWED_WEBAUTHN_ALGS: frozenset[str] = frozenset({"ES256", "EdDSA", "RS256"})

# WebAuthn authenticatorData flag bitmasks (W3C WebAuthn §6.1)
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_BACKUP_ELIGIBLE = 0x08
FLAG_BACKUP_STATE = 0x10

_MIN_AUTH_DATA_BYTES = 37
_MAX_REGISTERED_CREDENTIALS = 256
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}\Z")
_RP_ID_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z"
)
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})
_PRIVATE_JWK_FIELDS: frozenset[str] = frozenset(
    {"d", "k", "p", "q", "dp", "dq", "qi", "oth"}
)

WebAuthnPublicKey = (
    ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | rsa.RSAPublicKey
)


class WebAuthnConfigError(ValueError):
    """Raised when out-of-band WebAuthn RP or credential configuration is missing or invalid."""


class WebAuthnVerificationError(ValueError):
    """Raised when a WebAuthn assertion fails structural, binding, or signature verification."""


@dataclass(frozen=True)
class RegisteredWebAuthnCredential:
    """Out-of-band registered WebAuthn public key bound to a single human operator."""

    credential_id: str
    operator_urn: str
    alg: str
    public_key: WebAuthnPublicKey


@dataclass(frozen=True)
class WebAuthnVerifierConfig:
    """Validated Relying Party and out-of-band operator credential trust configuration."""

    rp_id: str
    allowed_origins: frozenset[str]
    credentials_by_id: Mapping[str, RegisteredWebAuthnCredential]


@dataclass(frozen=True)
class VerifiedWebAuthnAssertion:
    """Result of a cryptographically verified W3C WebAuthn assertion."""

    credential_id: str
    operator_urn: str
    alg: str
    rp_id: str
    origin: str
    client_data_hash: str
    sign_count: int
    flags: int


def decode_base64url_strict(raw: str, *, field_name: str) -> bytes:
    """Decode a base64url string strictly without accepting non-base64url characters."""
    if not isinstance(raw, str):
        raise WebAuthnVerificationError(f"{field_name} must be a base64url string")
    cleaned = raw.strip()
    if not cleaned or not _B64URL_RE.fullmatch(cleaned):
        raise WebAuthnVerificationError(
            f"{field_name} is missing or contains invalid base64url characters"
        )
    unpadded = cleaned.rstrip("=")
    if len(unpadded) % 4 == 1:
        raise WebAuthnVerificationError(
            f"{field_name} has invalid base64url length ({len(unpadded)})"
        )
    padded = unpadded + "=" * (-len(unpadded) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except ValueError as exc:
        raise WebAuthnVerificationError(
            f"{field_name} failed base64url decoding: {exc}"
        ) from exc
    if not decoded:
        raise WebAuthnVerificationError(f"{field_name} decoded to empty bytes")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != unpadded:
        raise WebAuthnVerificationError(
            f"{field_name} has non-canonical base64url padding bits"
        )
    return decoded


def canonicalize_credential_id(raw_credential_id: str) -> str:
    """Validate and normalize a base64url ``credential_id`` to unpadded canonical form."""
    decoded = decode_base64url_strict(raw_credential_id, field_name="credential_id")
    return base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")


def _is_workload_urn(urn: str) -> bool:
    candidate = urn.strip()
    return (
        candidate.startswith("spiffe://")
        or candidate.startswith("principal://agents.")
        or ".serviceaccount.identity.linkerd." in candidate
        or candidate.endswith(".svc.cluster.local")
    )


def validate_rp_id(raw_rp_id: str) -> str:
    """Validate a WebAuthn Relying Party ID (effective domain without scheme or port)."""
    candidate = (raw_rp_id or "").strip().lower()
    if not candidate or len(candidate) > 253 or not _RP_ID_RE.fullmatch(candidate):
        raise WebAuthnConfigError(
            f"Invalid CAGE_WEBAUTHN_RP_ID {raw_rp_id!r}: expected lowercase DNS name without scheme or port"
        )
    return candidate


def normalize_and_validate_origin(
    raw_origin: str,
    *,
    rp_id: str,
    enforcing: bool,
    allow_insecure_loopback: bool = False,
) -> str:
    """Normalize and validate an origin URL against scheme and WebAuthn RP-ID scope rules."""
    candidate = (raw_origin or "").strip()
    if not candidate:
        raise WebAuthnConfigError("WebAuthn origin must not be empty")
    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise WebAuthnConfigError(f"WebAuthn origin {raw_origin!r} is missing hostname")
    if parsed.username or parsed.password:
        raise WebAuthnConfigError("WebAuthn origin must not contain userinfo")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise WebAuthnConfigError(
            f"WebAuthn origin {raw_origin!r} must not include path, query, or fragment"
        )

    if scheme == "https":
        pass
    elif (
        scheme == "http"
        and hostname in _LOOPBACK_HOSTS
        and not enforcing
        and allow_insecure_loopback
    ):
        pass
    else:
        raise WebAuthnConfigError(
            f"WebAuthn origin {raw_origin!r} must use https:// (got scheme={scheme!r})"
        )

    if hostname != rp_id and not hostname.endswith(f".{rp_id}"):
        raise WebAuthnConfigError(
            f"WebAuthn origin host {hostname!r} is outside Relying Party ID scope {rp_id!r}"
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise WebAuthnConfigError(
            f"WebAuthn origin {raw_origin!r} carries invalid port"
        ) from exc

    host_part = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        return f"{scheme}://{host_part}:{port}"
    return f"{scheme}://{host_part}"


def _load_public_key_from_jwk(jwk: Mapping[str, Any]) -> tuple[WebAuthnPublicKey, str]:
    """Parse an asymmetric RFC 7517 public JWK using ``cryptography`` (rejecting private keys)."""
    for forbidden in _PRIVATE_JWK_FIELDS:
        if forbidden in jwk:
            raise WebAuthnConfigError(
                f"WebAuthn credential JWK contains forbidden private/symmetric field {forbidden!r}"
            )
    kty = str(jwk.get("kty", "")).strip()
    if kty == "EC":
        crv = str(jwk.get("crv", "")).strip()
        if crv != "P-256":
            raise WebAuthnConfigError(
                f"Unsupported EC curve {crv!r} in WebAuthn credential JWK (expected 'P-256')"
            )
        x_bytes = decode_base64url_strict(str(jwk.get("x", "")), field_name="jwk.x")
        y_bytes = decode_base64url_strict(str(jwk.get("y", "")), field_name="jwk.y")
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            raise WebAuthnConfigError("P-256 JWK coordinates must be 32 bytes each")
        pub_nums = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"),
            int.from_bytes(y_bytes, "big"),
            ec.SECP256R1(),
        )
        return pub_nums.public_key(), "ES256"

    if kty == "OKP":
        crv = str(jwk.get("crv", "")).strip()
        if crv != "Ed25519":
            raise WebAuthnConfigError(
                f"Unsupported OKP curve {crv!r} in WebAuthn credential JWK (expected 'Ed25519')"
            )
        x_bytes = decode_base64url_strict(str(jwk.get("x", "")), field_name="jwk.x")
        if len(x_bytes) != 32:
            raise WebAuthnConfigError("Ed25519 JWK 'x' coordinate must be 32 bytes")
        return ed25519.Ed25519PublicKey.from_public_bytes(x_bytes), "EdDSA"

    if kty == "RSA":
        n_bytes = decode_base64url_strict(str(jwk.get("n", "")), field_name="jwk.n")
        e_bytes = decode_base64url_strict(str(jwk.get("e", "")), field_name="jwk.e")
        pub_rsa = rsa.RSAPublicNumbers(
            int.from_bytes(e_bytes, "big"),
            int.from_bytes(n_bytes, "big"),
        ).public_key()
        if pub_rsa.key_size < 2048:
            raise WebAuthnConfigError(
                f"RSA WebAuthn credential key size {pub_rsa.key_size} < 2048 bits"
            )
        return pub_rsa, "RS256"

    raise WebAuthnConfigError(
        f"Unsupported WebAuthn JWK kty={kty!r}; expected 'EC', 'OKP', or 'RSA'"
    )


def _load_public_key_from_pem(pem_text: str) -> tuple[WebAuthnPublicKey, str]:
    if "PRIVATE KEY" in pem_text:
        raise WebAuthnConfigError(
            "WebAuthn credential entry contains PRIVATE KEY material; only public keys are permitted"
        )
    try:
        loaded = serialization.load_pem_public_key(pem_text.encode("utf-8"))
    except ValueError as exc:
        raise WebAuthnConfigError(f"Invalid WebAuthn public_key_pem: {exc}") from exc

    if isinstance(loaded, ec.EllipticCurvePublicKey):
        if loaded.curve.name != "secp256r1":
            raise WebAuthnConfigError(
                f"Unsupported EC curve {loaded.curve.name!r} in WebAuthn PEM (expected secp256r1 / P-256)"
            )
        return loaded, "ES256"
    if isinstance(loaded, ed25519.Ed25519PublicKey):
        return loaded, "EdDSA"
    if isinstance(loaded, rsa.RSAPublicKey):
        if loaded.key_size < 2048:
            raise WebAuthnConfigError(
                f"RSA WebAuthn credential key size {loaded.key_size} < 2048 bits"
            )
        return loaded, "RS256"
    raise WebAuthnConfigError(
        f"Unsupported WebAuthn public key type {type(loaded).__name__}"
    )


def parse_webauthn_credentials_payload(
    raw_json: str,
) -> dict[str, RegisteredWebAuthnCredential]:
    """Parse out-of-band operator WebAuthn public-key credentials indexed by canonical ``credential_id``."""
    try:
        parsed = json.loads(raw_json)
    except ValueError as exc:
        raise WebAuthnConfigError(
            f"Malformed WebAuthn credentials JSON: {exc}"
        ) from exc

    entries: list[Any]
    if isinstance(parsed, dict) and isinstance(parsed.get("credentials"), list):
        entries = parsed["credentials"]
    elif isinstance(parsed, list):
        entries = parsed
    else:
        raise WebAuthnConfigError(
            "WebAuthn credentials payload must be a JSON list or {'credentials': [...]}"
        )

    if len(entries) > _MAX_REGISTERED_CREDENTIALS:
        raise WebAuthnConfigError(
            f"WebAuthn credentials registry exceeds maximum {_MAX_REGISTERED_CREDENTIALS} entries"
        )

    by_cred_id: dict[str, RegisteredWebAuthnCredential] = {}
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise WebAuthnConfigError(
                f"WebAuthn credential entry #{idx} must be a JSON object"
            )
        try:
            cred_id = canonicalize_credential_id(str(entry.get("credential_id", "")))
        except WebAuthnVerificationError as exc:
            raise WebAuthnConfigError(
                f"WebAuthn credential entry #{idx}: {exc}"
            ) from exc

        if cred_id in by_cred_id:
            raise WebAuthnConfigError(
                f"Duplicate WebAuthn credential_id {cred_id!r} in out-of-band registry"
            )

        operator_urn = str(entry.get("operator_urn", "")).strip()
        if not operator_urn or any(ch.isspace() for ch in operator_urn):
            raise WebAuthnConfigError(
                f"WebAuthn credential {cred_id!r} requires a non-empty operator_urn without whitespace"
            )
        if _is_workload_urn(operator_urn):
            raise WebAuthnConfigError(
                f"Workload identity {operator_urn!r} cannot be registered as a human WebAuthn credential owner"
            )

        pem_val = entry.get("public_key_pem")
        jwk_val = entry.get("jwk")
        pub_jwk_val = entry.get("public_key_jwk")
        has_pem = isinstance(pem_val, str) and bool(pem_val.strip())
        has_jwk = isinstance(jwk_val, Mapping)
        has_pub_jwk = isinstance(pub_jwk_val, Mapping)
        if sum((has_pem, has_jwk, has_pub_jwk)) != 1:
            raise WebAuthnConfigError(
                f"WebAuthn credential {cred_id!r} must provide exactly one of "
                f"'public_key_pem', 'jwk', or 'public_key_jwk'"
            )
        if isinstance(pem_val, str) and pem_val.strip():
            pub_key, inferred_alg = _load_public_key_from_pem(pem_val.strip())
        else:
            effective_jwk = jwk_val if isinstance(jwk_val, Mapping) else pub_jwk_val
            if not isinstance(effective_jwk, Mapping):
                raise WebAuthnConfigError(
                    f"WebAuthn credential {cred_id!r} JWK must be a JSON object"
                )
            try:
                pub_key, inferred_alg = _load_public_key_from_jwk(effective_jwk)
            except WebAuthnVerificationError as exc:
                raise WebAuthnConfigError(
                    f"WebAuthn credential {cred_id!r} invalid JWK: {exc}"
                ) from exc

        declared_alg = str(entry.get("alg", "") or inferred_alg).strip()
        if declared_alg not in ALLOWED_WEBAUTHN_ALGS:
            raise WebAuthnConfigError(
                f"WebAuthn credential {cred_id!r} has unsupported alg={declared_alg!r}; "
                f"allowed: {sorted(ALLOWED_WEBAUTHN_ALGS)}"
            )
        if declared_alg != inferred_alg:
            raise WebAuthnConfigError(
                f"WebAuthn credential {cred_id!r} alg={declared_alg!r} mismatches public key type ({inferred_alg})"
            )

        by_cred_id[cred_id] = RegisteredWebAuthnCredential(
            credential_id=cred_id,
            operator_urn=operator_urn,
            alg=declared_alg,
            public_key=pub_key,
        )

    if not by_cred_id:
        raise WebAuthnConfigError("WebAuthn credentials registry contains 0 entries")
    return by_cred_id


def load_webauthn_verifier_config_from_env(
    env: Mapping[str, str] | None = None,
) -> WebAuthnVerifierConfig:
    """Load and validate out-of-band WebAuthn RP and operator credential configuration."""
    source = os.environ if env is None else env
    enforcing = is_enforcing(source)
    allow_loopback = (
        not enforcing
        and env_flag("CAGE_ALLOW_INSECURE_LOOPBACK_WEBAUTHN", default=False)
        if env is None
        else (
            not enforcing
            and str(
                source.get("CAGE_ALLOW_INSECURE_LOOPBACK_WEBAUTHN", "false")
            ).lower()
            in ("1", "true", "yes", "on")
        )
    )

    raw_rp_id = source.get("CAGE_WEBAUTHN_RP_ID", "").strip()
    if not raw_rp_id:
        raise WebAuthnConfigError(
            "CAGE_WEBAUTHN_RP_ID is not configured; cannot verify WebAuthn assertion"
        )
    rp_id = validate_rp_id(raw_rp_id)

    raw_origins = source.get("CAGE_WEBAUTHN_ALLOWED_ORIGINS", "").strip()
    if not raw_origins:
        raise WebAuthnConfigError(
            "CAGE_WEBAUTHN_ALLOWED_ORIGINS is not configured; cannot verify WebAuthn assertion"
        )
    origins: set[str] = set()
    for part in raw_origins.split(","):
        if part.strip():
            origins.add(
                normalize_and_validate_origin(
                    part.strip(),
                    rp_id=rp_id,
                    enforcing=enforcing,
                    allow_insecure_loopback=allow_loopback,
                )
            )
    if not origins:
        raise WebAuthnConfigError(
            "CAGE_WEBAUTHN_ALLOWED_ORIGINS contains no valid origins"
        )

    raw_creds_json = source.get("CAGE_WEBAUTHN_CREDENTIALS_JSON", "").strip()
    creds_file = source.get("CAGE_WEBAUTHN_CREDENTIALS_FILE", "").strip()
    if raw_creds_json and creds_file:
        raise WebAuthnConfigError(
            "Simultaneous CAGE_WEBAUTHN_CREDENTIALS_JSON and CAGE_WEBAUTHN_CREDENTIALS_FILE configuration is forbidden; configure at most one trust source"
        )
    if not raw_creds_json and creds_file:
        try:
            raw_creds_json = Path(creds_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise WebAuthnConfigError(
                f"Failed to read CAGE_WEBAUTHN_CREDENTIALS_FILE {creds_file!r}: {exc}"
            ) from exc
    if not raw_creds_json:
        raise WebAuthnConfigError(
            "Neither CAGE_WEBAUTHN_CREDENTIALS_JSON nor CAGE_WEBAUTHN_CREDENTIALS_FILE is configured"
        )

    credentials_by_id = parse_webauthn_credentials_payload(raw_creds_json)
    return WebAuthnVerifierConfig(
        rp_id=rp_id,
        allowed_origins=frozenset(origins),
        credentials_by_id=credentials_by_id,
    )


def validate_configured_webauthn_env(env: Mapping[str, str] | None = None) -> None:
    """Validate any configured ``CAGE_WEBAUTHN_*`` environment variables at startup."""
    source = os.environ if env is None else env
    enforcing = is_enforcing(source)
    allow_loopback = not enforcing and str(
        source.get("CAGE_ALLOW_INSECURE_LOOPBACK_WEBAUTHN", "false")
    ).lower() in ("1", "true", "yes", "on")

    raw_rp_id = source.get("CAGE_WEBAUTHN_RP_ID", "").strip()
    rp_id: str | None = None
    if raw_rp_id:
        rp_id = validate_rp_id(raw_rp_id)

    raw_origins = source.get("CAGE_WEBAUTHN_ALLOWED_ORIGINS", "").strip()
    if raw_origins:
        if rp_id is None:
            raise WebAuthnConfigError(
                "CAGE_WEBAUTHN_ALLOWED_ORIGINS is set without CAGE_WEBAUTHN_RP_ID"
            )
        parsed_origins = [
            normalize_and_validate_origin(
                part.strip(),
                rp_id=rp_id,
                enforcing=enforcing,
                allow_insecure_loopback=allow_loopback,
            )
            for part in raw_origins.split(",")
            if part.strip()
        ]
        if not parsed_origins:
            raise WebAuthnConfigError(
                "CAGE_WEBAUTHN_ALLOWED_ORIGINS contains no valid origins"
            )

    raw_creds_json = source.get("CAGE_WEBAUTHN_CREDENTIALS_JSON", "").strip()
    creds_file = source.get("CAGE_WEBAUTHN_CREDENTIALS_FILE", "").strip()
    if raw_creds_json and creds_file:
        raise WebAuthnConfigError(
            "Simultaneous CAGE_WEBAUTHN_CREDENTIALS_JSON and CAGE_WEBAUTHN_CREDENTIALS_FILE configuration is forbidden; configure at most one trust source"
        )
    if raw_creds_json or creds_file:
        if not raw_creds_json:
            try:
                raw_creds_json = Path(creds_file).read_text(encoding="utf-8")
            except OSError as exc:
                raise WebAuthnConfigError(
                    f"Failed to read CAGE_WEBAUTHN_CREDENTIALS_FILE {creds_file!r}: {exc}"
                ) from exc
        parse_webauthn_credentials_payload(raw_creds_json)


def _verify_signature_bytes(
    cred: RegisteredWebAuthnCredential,
    *,
    signed_payload: bytes,
    signature_bytes: bytes,
) -> None:
    try:
        if cred.alg == "ES256" and isinstance(
            cred.public_key, ec.EllipticCurvePublicKey
        ):
            cred.public_key.verify(
                signature_bytes, signed_payload, ec.ECDSA(hashes.SHA256())
            )
            return
        if cred.alg == "EdDSA" and isinstance(
            cred.public_key, ed25519.Ed25519PublicKey
        ):
            cred.public_key.verify(signature_bytes, signed_payload)
            return
        if cred.alg == "RS256" and isinstance(cred.public_key, rsa.RSAPublicKey):
            cred.public_key.verify(
                signature_bytes,
                signed_payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return
    except InvalidSignature as exc:
        raise WebAuthnVerificationError(
            f"WebAuthn cryptographic signature verification failed for credential_id={cred.credential_id!r}"
        ) from exc
    raise WebAuthnVerificationError(
        f"Unsupported WebAuthn key/algorithm combination ({cred.alg})"
    )


def verify_webauthn_assertion(
    *,
    approver_urn: str,
    credential_id: str | None,
    client_data_json: str | None,
    authenticator_data: str | None,
    signature: str | None,
    challenge_binding: str | None,
    expected_bindings: Collection[str] | None = None,
    config: WebAuthnVerifierConfig | None = None,
    env: Mapping[str, str] | None = None,
) -> VerifiedWebAuthnAssertion:
    """Verify a W3C WebAuthn ``AuthenticatorAssertionResponse`` cryptographically."""
    clean_approver = (approver_urn or "").strip()
    if not clean_approver or any(ch.isspace() for ch in clean_approver):
        raise WebAuthnVerificationError("approver_urn must be a non-empty identifier")

    if not credential_id or not credential_id.strip():
        raise WebAuthnVerificationError("WebAuthn credential_id is required")
    if not client_data_json or not client_data_json.strip():
        raise WebAuthnVerificationError("WebAuthn client_data_json is required")
    if not authenticator_data or not authenticator_data.strip():
        raise WebAuthnVerificationError("WebAuthn authenticator_data is required")
    if not signature or not signature.strip():
        raise WebAuthnVerificationError("WebAuthn signature is required")
    if not challenge_binding or not challenge_binding.strip():
        raise WebAuthnVerificationError("WebAuthn challenge_binding is required")

    binding_hex = challenge_binding.strip().lower()
    if not _HEX_SHA256_RE.fullmatch(binding_hex):
        raise WebAuthnVerificationError(
            "WebAuthn challenge_binding must be a 64-character hex SHA-256 digest"
        )
    expected_challenge_bytes = bytes.fromhex(binding_hex)

    if expected_bindings is not None:
        matched_server_binding = any(
            isinstance(candidate, str)
            and len(candidate.strip()) == 64
            and hmac.compare_digest(binding_hex, candidate.strip().lower())
            for candidate in expected_bindings
        )
        if not matched_server_binding:
            raise WebAuthnVerificationError(
                "WebAuthn challenge_binding does not match any server-derived decision binding"
            )

    norm_cred_id = canonicalize_credential_id(credential_id)
    client_data_bytes = decode_base64url_strict(
        client_data_json, field_name="client_data_json"
    )
    auth_data_bytes = decode_base64url_strict(
        authenticator_data, field_name="authenticator_data"
    )
    signature_bytes = decode_base64url_strict(signature, field_name="signature")

    effective_config = (
        config if config is not None else load_webauthn_verifier_config_from_env(env)
    )

    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebAuthnVerificationError(
            f"client_data_json is not valid UTF-8 JSON: {exc}"
        ) from exc

    if not isinstance(client_data, dict):
        raise WebAuthnVerificationError("client_data_json must decode to a JSON object")
    if client_data.get("type") != "webauthn.get":
        raise WebAuthnVerificationError(
            f"client_data_json.type must be 'webauthn.get' (got {client_data.get('type')!r})"
        )
    cross_origin = client_data.get("crossOrigin")
    if cross_origin is not None and cross_origin is not False:
        raise WebAuthnVerificationError(
            "Cross-origin WebAuthn assertions are refused (crossOrigin must be false)"
        )

    challenge_b64 = client_data.get("challenge")
    if not isinstance(challenge_b64, str) or not challenge_b64.strip():
        raise WebAuthnVerificationError("client_data_json.challenge is missing")
    challenge_bytes = decode_base64url_strict(
        challenge_b64, field_name="client_data_json.challenge"
    )
    if not hmac.compare_digest(challenge_bytes, expected_challenge_bytes):
        raise WebAuthnVerificationError(
            "client_data_json.challenge does not match challenge_binding"
        )

    raw_origin = client_data.get("origin")
    if not isinstance(raw_origin, str) or not raw_origin.strip():
        raise WebAuthnVerificationError("client_data_json.origin is missing")
    enforcing = is_enforcing(env)
    allow_loopback = not enforcing and (
        env_flag("CAGE_ALLOW_INSECURE_LOOPBACK_WEBAUTHN", default=False)
        if env is None
        else str(env.get("CAGE_ALLOW_INSECURE_LOOPBACK_WEBAUTHN", "false")).lower()
        in ("1", "true", "yes", "on")
    )
    try:
        normalized_origin = normalize_and_validate_origin(
            raw_origin,
            rp_id=effective_config.rp_id,
            enforcing=enforcing,
            allow_insecure_loopback=allow_loopback,
        )
    except WebAuthnConfigError as exc:
        raise WebAuthnVerificationError(
            f"client_data_json.origin rejected: {exc}"
        ) from exc
    if normalized_origin not in effective_config.allowed_origins:
        raise WebAuthnVerificationError(
            f"client_data_json.origin {normalized_origin!r} is not in CAGE_WEBAUTHN_ALLOWED_ORIGINS"
        )

    if len(auth_data_bytes) < _MIN_AUTH_DATA_BYTES:
        raise WebAuthnVerificationError(
            f"authenticator_data length {len(auth_data_bytes)} < {_MIN_AUTH_DATA_BYTES} bytes"
        )
    expected_rp_id_hash = hashlib.sha256(
        effective_config.rp_id.encode("utf-8")
    ).digest()
    if not hmac.compare_digest(auth_data_bytes[:32], expected_rp_id_hash):
        raise WebAuthnVerificationError(
            f"authenticator_data rpIdHash does not match SHA-256({effective_config.rp_id!r})"
        )

    flags = auth_data_bytes[32]
    if (flags & FLAG_USER_PRESENT) == 0:
        raise WebAuthnVerificationError(
            "authenticator_data User Present (UP, 0x01) flag is not set"
        )
    if (flags & FLAG_USER_VERIFIED) == 0:
        raise WebAuthnVerificationError(
            "authenticator_data User Verified (UV, 0x04) flag is not set"
        )
    if (flags & FLAG_BACKUP_STATE) != 0 and (flags & FLAG_BACKUP_ELIGIBLE) == 0:
        raise WebAuthnVerificationError(
            "authenticator_data has invalid backup state (BS=1 with BE=0)"
        )

    sign_count = int.from_bytes(auth_data_bytes[33:37], "big")

    registered = effective_config.credentials_by_id.get(norm_cred_id)
    if registered is None:
        raise WebAuthnVerificationError(
            f"Unknown WebAuthn credential_id {norm_cred_id!r} (not in out-of-band registry)"
        )
    reg_subj = registered.operator_urn.removeprefix("urn:cage:operator:oidc:")
    app_subj = clean_approver.removeprefix("urn:cage:operator:oidc:")
    if not hmac.compare_digest(reg_subj, app_subj):
        raise WebAuthnVerificationError(
            f"WebAuthn credential_id {norm_cred_id!r} is not registered to operator {clean_approver!r}"
        )

    client_data_digest = hashlib.sha256(client_data_bytes).digest()
    signed_payload = auth_data_bytes + client_data_digest
    _verify_signature_bytes(
        registered,
        signed_payload=signed_payload,
        signature_bytes=signature_bytes,
    )

    return VerifiedWebAuthnAssertion(
        credential_id=norm_cred_id,
        operator_urn=clean_approver,
        alg=registered.alg,
        rp_id=effective_config.rp_id,
        origin=normalized_origin,
        client_data_hash=client_data_digest.hex(),
        sign_count=sign_count,
        flags=flags,
    )
