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

"""Out-of-band trust anchor and verified key manifest for Warrant Contract v0.2.

Enforces the CAGE trust-anchor invariants in the type system:
  - Never verify a warrant signature against an embedded key.
  - Resolve issuer keys by ``kid`` from an independently fetched key manifest
    whose signature has been verified against an out-of-band root public key
    pinned by ``sha256:<hex>`` fingerprint.
  - :class:`VerifiedKeyManifest` cannot be constructed without passing
    cryptographic verification against a :class:`WarrantTrustAnchor`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

#: Ed25519 SubjectPublicKeyInfo (SPKI) DER prefix (12 bytes) before the 32-byte raw key.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_RAW_KEY_LEN = 32
_ED25519_SIG_LEN = 64

#: Supported key manifest schema version.
MANIFEST_SCHEMA_VERSION_V02 = "veip-key-manifest/0.2"

_REQUIRED_MANIFEST_FIELDS: tuple[str, ...] = (
    "schema_version",
    "environment",
    "manifest_id",
    "issuer",
    "generated_at",
    "valid_until",
    "root_kid",
    "keys",
    "manifest_digest",
    "signature",
)

_MANIFEST_SEAL = object()


class KeyManifestVerificationError(ValueError):
    """Raised when a key manifest fails structural, digest, or signature verification."""


def _decode_b64_any(encoded: str) -> bytes:
    """Decode standard or URL-safe base64 (with or without padding) or PEM."""
    lines = [
        line.strip()
        for line in encoded.strip().splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    compact = "".join(lines)
    if not compact:
        raise ValueError("Empty base64 input")
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    try:
        if "-" in compact or "_" in compact:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Invalid base64 encoding: {exc}") from exc


def _extract_ed25519_raw_public_key(encoded: str) -> bytes:
    """Extract the 32-byte raw Ed25519 public key from SPKI DER, PEM, or raw base64."""
    decoded = _decode_b64_any(encoded)
    if len(decoded) == len(_ED25519_SPKI_PREFIX) + _RAW_KEY_LEN:
        if not decoded.startswith(_ED25519_SPKI_PREFIX):
            raise ValueError("SPKI DER header does not match Ed25519 OID")
        return decoded[len(_ED25519_SPKI_PREFIX) :]
    if len(decoded) == _RAW_KEY_LEN:
        return decoded
    raise ValueError(
        f"Expected 32-byte raw or 44-byte SPKI Ed25519 public key, got {len(decoded)} bytes"
    )


def _verify_ed25519(raw_public_key: bytes, signature_b64u: str, payload: bytes) -> bool:
    """Verify a base64url Ed25519 signature over ``payload``."""
    if not isinstance(signature_b64u, str) or not signature_b64u:
        return False
    try:
        sig_bytes = _decode_b64_any(signature_b64u)
        if len(sig_bytes) != _ED25519_SIG_LEN:
            return False
        pub = Ed25519PublicKey.from_public_bytes(raw_public_key)
        pub.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts:
        raise ValueError("Timestamp must be a non-empty ISO 8601 string")
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp must be timezone-aware: {ts!r}")
    return dt


@dataclass(frozen=True)
class WarrantTrustAnchor:
    """Out-of-band root of trust for verifying key manifests.

    Validates at construction that the supplied Ed25519 root public key hashes
    to ``expected_fingerprint`` (``sha256:<64-hex>`` over the 32-byte raw key).
    """

    root_kid: str
    public_key_b64: str
    expected_fingerprint: str
    _raw_key: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.root_kid, str) or not self.root_kid.strip():
            raise ValueError("WarrantTrustAnchor.root_kid must be a non-empty string")
        if (
            not isinstance(self.expected_fingerprint, str)
            or not self.expected_fingerprint.startswith("sha256:")
            or len(self.expected_fingerprint) != len("sha256:") + 64
        ):
            raise ValueError(
                "WarrantTrustAnchor.expected_fingerprint must be 'sha256:<64-hex>'"
            )
        raw_key = _extract_ed25519_raw_public_key(self.public_key_b64)
        actual_fp = f"sha256:{hashlib.sha256(raw_key).hexdigest()}"
        if actual_fp != self.expected_fingerprint.lower():
            raise ValueError(
                f"Trust anchor fingerprint mismatch for {self.root_kid!r}: "
                f"expected {self.expected_fingerprint}, computed {actual_fp}"
            )
        object.__setattr__(self, "_raw_key", raw_key)

    @property
    def fingerprint(self) -> str:
        return f"sha256:{hashlib.sha256(self._raw_key).hexdigest()}"

    def verify_signature(self, signature_b64u: str, payload: bytes) -> bool:
        """Verify an Ed25519 signature using this out-of-band root public key."""
        return _verify_ed25519(self._raw_key, signature_b64u, payload)


@dataclass(frozen=True)
class ManifestKeyEntry:
    """One issuer signing key published inside a verified key manifest."""

    kid: str
    alg: str
    public_key_b64u: str
    status: str
    not_before: str
    not_after: str
    revoked_at: str = ""
    _raw_key: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.kid, str) or not self.kid:
            raise ValueError("ManifestKeyEntry.kid must be a non-empty string")
        if self.alg != "Ed25519":
            raise ValueError(f"Unsupported key manifest algorithm: {self.alg!r}")
        raw_key = _extract_ed25519_raw_public_key(self.public_key_b64u)
        _parse_utc(self.not_before)
        _parse_utc(self.not_after)
        object.__setattr__(self, "_raw_key", raw_key)

    def is_active_at(self, now: datetime) -> bool:
        """Return whether this key is ACTIVE, unrevoked, and within [not_before, not_after]."""
        if now.tzinfo is None or self.status != "ACTIVE" or self.revoked_at:
            return False
        try:
            nb = _parse_utc(self.not_before)
            na = _parse_utc(self.not_after)
        except ValueError:
            return False
        return nb <= now <= na

    def verify_signature(self, signature_b64u: str, payload: bytes) -> bool:
        """Verify an Ed25519 warrant signature using this issuer key."""
        return _verify_ed25519(self._raw_key, signature_b64u, payload)


@dataclass(frozen=True)
class VerifiedKeyManifest:
    """Cryptographically verified key manifest anchored to a :class:`WarrantTrustAnchor`.

    Cannot be instantiated directly; callers must use :meth:`verify`.
    """

    schema_version: str
    environment: str
    manifest_id: str
    issuer: str
    generated_at: str
    valid_until: str
    root_kid: str
    manifest_digest: str
    signature: str
    keys: Mapping[str, ManifestKeyEntry]
    anchor_fingerprint: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _MANIFEST_SEAL:
            raise TypeError(
                "VerifiedKeyManifest cannot be instantiated directly; "
                "use VerifiedKeyManifest.verify(raw_manifest, trust_anchor)"
            )
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))

    @classmethod
    def verify(
        cls,
        raw_manifest: Mapping[str, Any],
        trust_anchor: WarrantTrustAnchor,
        *,
        now: datetime | None = None,
    ) -> VerifiedKeyManifest:
        """Verify a key manifest against ``trust_anchor`` and return a :class:`VerifiedKeyManifest`.

        Raises:
            TypeError: ``trust_anchor`` is not a :class:`WarrantTrustAnchor` or
                ``raw_manifest`` is not a mapping.
            KeyManifestVerificationError: Any structural, digest, signature, or
                validity-window check fails.
        """
        if not isinstance(trust_anchor, WarrantTrustAnchor):
            raise TypeError(
                f"trust_anchor must be a WarrantTrustAnchor, got {type(trust_anchor).__name__}"
            )
        if not isinstance(raw_manifest, Mapping):
            raise TypeError(
                f"raw_manifest must be a Mapping, got {type(raw_manifest).__name__}"
            )

        missing = [f for f in _REQUIRED_MANIFEST_FIELDS if f not in raw_manifest]
        if missing:
            raise KeyManifestVerificationError(
                f"Key manifest missing required fields: {missing}"
            )

        schema_version = raw_manifest["schema_version"]
        if schema_version != MANIFEST_SCHEMA_VERSION_V02:
            raise KeyManifestVerificationError(
                f"Unsupported key manifest schema_version: {schema_version!r}"
            )

        root_kid = raw_manifest["root_kid"]
        if root_kid != trust_anchor.root_kid:
            raise KeyManifestVerificationError(
                f"Key manifest root_kid {root_kid!r} does not match trust anchor "
                f"{trust_anchor.root_kid!r}"
            )

        declared_digest = raw_manifest["manifest_digest"]
        if not isinstance(declared_digest, str) or len(declared_digest) != 64:
            raise KeyManifestVerificationError(
                "Key manifest digest is missing or malformed"
            )

        unsigned_body = {
            k: v
            for k, v in raw_manifest.items()
            if k not in ("manifest_digest", "signature")
        }
        computed_digest = hashlib.sha256(
            jcs_canonicalize_plan(unsigned_body)
        ).hexdigest()
        if computed_digest != declared_digest:
            raise KeyManifestVerificationError(
                f"Key manifest digest mismatch: declared {declared_digest} "
                f"vs computed {computed_digest}"
            )

        signed_body = {k: v for k, v in raw_manifest.items() if k != "signature"}
        signature = raw_manifest["signature"]
        if not trust_anchor.verify_signature(
            signature, jcs_canonicalize_plan(signed_body)
        ):
            raise KeyManifestVerificationError(
                f"Key manifest Ed25519 signature verification failed for root_kid {root_kid!r}"
            )

        try:
            gen_dt = _parse_utc(raw_manifest["generated_at"])
            until_dt = _parse_utc(raw_manifest["valid_until"])
        except ValueError as exc:
            raise KeyManifestVerificationError(
                f"Invalid key manifest timestamps: {exc}"
            ) from exc
        if gen_dt > until_dt:
            raise KeyManifestVerificationError(
                "Key manifest generated_at is after valid_until"
            )

        raw_keys = raw_manifest["keys"]
        if not isinstance(raw_keys, list) or not raw_keys:
            raise KeyManifestVerificationError(
                "Key manifest must contain a non-empty keys list"
            )

        parsed_keys: dict[str, ManifestKeyEntry] = {}
        try:
            for item in raw_keys:
                if not isinstance(item, Mapping):
                    raise KeyManifestVerificationError(
                        "Key manifest entry must be a dict"
                    )
                entry = ManifestKeyEntry(
                    kid=str(item["kid"]),
                    alg=str(item["alg"]),
                    public_key_b64u=str(item["public_key_b64u"]),
                    status=str(item["status"]),
                    not_before=str(item["not_before"]),
                    not_after=str(item["not_after"]),
                    revoked_at=str(item.get("revoked_at", "") or ""),
                )
                if entry.kid in parsed_keys:
                    raise KeyManifestVerificationError(
                        f"Duplicate kid {entry.kid!r} in key manifest"
                    )
                parsed_keys[entry.kid] = entry
        except (KeyError, ValueError, TypeError) as exc:
            if isinstance(exc, KeyManifestVerificationError):
                raise
            raise KeyManifestVerificationError(
                f"Invalid key entry in manifest: {exc}"
            ) from exc

        manifest = cls(
            schema_version=str(schema_version),
            environment=str(raw_manifest["environment"]),
            manifest_id=str(raw_manifest["manifest_id"]),
            issuer=str(raw_manifest["issuer"]),
            generated_at=str(raw_manifest["generated_at"]),
            valid_until=str(raw_manifest["valid_until"]),
            root_kid=str(root_kid),
            manifest_digest=str(declared_digest),
            signature=str(signature),
            keys=parsed_keys,
            anchor_fingerprint=trust_anchor.fingerprint,
            _seal=_MANIFEST_SEAL,
        )
        if now is not None and not manifest.is_valid_at(now):
            raise KeyManifestVerificationError(
                f"Key manifest temporal window invalid: {now.isoformat()} outside "
                f"[{manifest.generated_at}, {manifest.valid_until}]"
            )
        return manifest

    def is_valid_at(self, now: datetime) -> bool:
        """Return whether ``now`` falls within ``[generated_at, valid_until]``."""
        if now.tzinfo is None:
            return False
        try:
            gen_dt = _parse_utc(self.generated_at)
            until_dt = _parse_utc(self.valid_until)
        except ValueError:
            return False
        return gen_dt <= now <= until_dt

    def resolve_key(self, kid: str) -> ManifestKeyEntry | None:
        """Look up a key entry by ``kid``, or ``None`` if unknown."""
        return self.keys.get(kid)


__all__ = [
    "MANIFEST_SCHEMA_VERSION_V02",
    "KeyManifestVerificationError",
    "ManifestKeyEntry",
    "VerifiedKeyManifest",
    "WarrantTrustAnchor",
]
