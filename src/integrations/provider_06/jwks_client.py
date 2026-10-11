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
JWKS Client for Out-of-Band Ed25519 Key Resolution (Provider 06).

Implements :class:`FileJWKSClient` (aliased as :class:`Provider06KeyManifestClient`)
extending :class:`~src.integrations.trust.key_manifest.Ed25519KeyManifestClient`.

Enforces:
1. **Trust Anchor Invariant**: Keys are resolved strictly by ``kid`` from an
   out-of-band provisioned JWKS manifest; unknown, expired, or revoked ``kid``
   values return ``None`` and callers fail closed.
2. **CageReceiptTrustManifestV1 Extension Verification**: When the manifest
   carries ``https://github.com/SimranPabla/agent-integrity/params/jwks/receipt-manifest/v1``
   (or when ``require_manifest_extension=True``), validates:
   - RFC 8785 JCS canonical JSON encoding and SHA-256 ``manifestDigest``
   - Detached Ed25519 authority signature over
     ``b"cage-agent-integrity-trust-manifest-v1\\x00" + bytes.fromhex(manifestDigest)``
   - Manifest ``issuedAt`` / ``validUntil`` window and ``receiptProfile`` ceilings
   - Per-key ``notBefore``, ``notAfter``, and ``revokedAt`` lifecycle metadata
   - Monotonic ``(generation, manifestDigest)`` anti-rollback state in memory
     and (when configured) atomically persisted on disk.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.integrations.trust.key_manifest import Ed25519KeyManifestClient

logger = logging.getLogger("cage.integrations.provider_06.jwks_client")

CAGE_MANIFEST_EXTENSION_URI = (
    "https://github.com/SimranPabla/agent-integrity/params/jwks/receipt-manifest/v1"
)
MANIFEST_SIGNATURE_DOMAIN = b"cage-agent-integrity-trust-manifest-v1\x00"

_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_B64URL_32_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64URL_64_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_MAX_MANIFEST_BYTES = 256 * 1024


@dataclass(frozen=True)
class CageKeyMetadata:
    """Per-key validity and revocation metadata from the trust manifest extension."""

    kid: str
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None = None


@dataclass(frozen=True)
class CageReceiptProfile:
    """Expected receipt profile constraints signed into the trust manifest."""

    issuer: str
    audience: str
    purpose: str
    engine_version: str
    maximum_receipt_lifetime_seconds: int
    maximum_future_skew_seconds: int


@dataclass(frozen=True)
class CageManifestExtension:
    """Parsed and verified CageReceiptTrustManifestV1 extension payload."""

    version: str
    generation: int
    issued_at: datetime
    valid_until: datetime
    receipt_profile: CageReceiptProfile
    key_metadata: dict[str, CageKeyMetadata]
    signature_algorithm: str
    authority_key_id: str
    manifest_digest: str
    signature: str


def _parse_iso_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} timestamp is invalid") from exc
    return parsed.astimezone(timezone.utc)


def _decode_b64url_exact(value: Any, expected_len: int, label: str) -> bytes:
    pattern = _B64URL_32_RE if expected_len == 32 else _B64URL_64_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{label} base64url is invalid")
    padding = "=" * ((4 - len(value) % 4) % 4)
    raw = base64.urlsafe_b64decode(value + padding)
    reencoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if len(raw) != expected_len or reencoded != value:
        raise ValueError(f"{label} length or encoding is invalid")
    return raw


def _normalize_manifest_url(manifest_url: str | Path) -> str:
    if isinstance(manifest_url, Path):
        return manifest_url.resolve().as_uri()
    parsed = urlparse(manifest_url)
    if not parsed.scheme:
        return Path(manifest_url).resolve().as_uri()
    return manifest_url


def _load_authority_keys_from_env() -> dict[str, Ed25519PublicKey]:
    raw_env = os.environ.get("CAGE_AGENT_INTEGRITY_AUTHORITY_KEYS", "").strip()
    if not raw_env:
        return {}
    parsed = json.loads(raw_env)
    if not isinstance(parsed, dict):
        raise ValueError("CAGE_AGENT_INTEGRITY_AUTHORITY_KEYS must be a JSON object")
    resolved: dict[str, Ed25519PublicKey] = {}
    for kid, x_val in parsed.items():
        if not isinstance(kid, str) or not _SAFE_IDENTIFIER_RE.fullmatch(kid):
            raise ValueError("authority key ID is invalid")
        pub_bytes = _decode_b64url_exact(x_val, 32, "authority public key")
        resolved[kid] = Ed25519PublicKey.from_public_bytes(pub_bytes)
    return resolved


class FileJWKSClient(Ed25519KeyManifestClient):
    """Out-of-band JWKS and CageReceiptTrustManifestV1 client for Provider 06."""

    def __init__(
        self,
        manifest_url: str | Path,
        cache_ttl_seconds: int = 3600,
        timeout_seconds: float = 5.0,
        *,
        authority_keys: dict[str, str | Ed25519PublicKey] | None = None,
        manifest_state_path: str | Path | None = None,
        require_manifest_extension: bool = False,
        maximum_future_skew_seconds: int = 60,
        maximum_receipt_lifetime_seconds: int = 3600,
    ) -> None:
        normalized_url = _normalize_manifest_url(manifest_url)
        super().__init__(
            manifest_url=normalized_url,
            cache_ttl_seconds=cache_ttl_seconds,
            timeout_seconds=timeout_seconds,
        )
        self._authority_keys: dict[str, Ed25519PublicKey] = {}
        if authority_keys is not None:
            for kid, key_or_x in authority_keys.items():
                if not isinstance(kid, str) or not _SAFE_IDENTIFIER_RE.fullmatch(kid):
                    raise ValueError(f"Invalid authority key ID: {kid!r}")
                if isinstance(key_or_x, Ed25519PublicKey):
                    self._authority_keys[kid] = key_or_x
                else:
                    raw = _decode_b64url_exact(key_or_x, 32, "authority public key")
                    self._authority_keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
        else:
            self._authority_keys = _load_authority_keys_from_env()

        env_state_path = os.environ.get(
            "CAGE_AGENT_INTEGRITY_MANIFEST_STATE_PATH", ""
        ).strip()
        resolved_state = manifest_state_path or (
            Path(env_state_path) if env_state_path else None
        )
        self._manifest_state_path: Path | None = (
            Path(resolved_state) if resolved_state is not None else None
        )
        self._require_manifest_extension = bool(
            require_manifest_extension
            or self._authority_keys
            or self._manifest_state_path is not None
        )
        self._maximum_future_skew_seconds = maximum_future_skew_seconds
        self._maximum_receipt_lifetime_seconds = maximum_receipt_lifetime_seconds
        self._manifest_extension: CageManifestExtension | None = None
        self._accepted_state: tuple[int, str] | None = self._load_persisted_state()

    @property
    def manifest_extension(self) -> CageManifestExtension | None:
        """Return the active verified CageManifestExtension, if loaded."""
        return self._manifest_extension

    @property
    def receipt_profile(self) -> CageReceiptProfile | None:
        """Return the signed receipt profile from the active manifest extension."""
        if self._manifest_extension is None:
            return None
        return self._manifest_extension.receipt_profile

    def _load_persisted_state(self) -> tuple[int, str] | None:
        if self._manifest_state_path is None or not self._manifest_state_path.exists():
            return None
        raw = json.loads(self._manifest_state_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw.keys()) != {
            "generation",
            "manifestDigest",
        }:
            raise ValueError("persisted trust manifest state is malformed")
        gen = raw.get("generation")
        digest = raw.get("manifestDigest")
        if (
            isinstance(gen, bool)
            or not isinstance(gen, int)
            or gen < 1
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
        ):
            raise ValueError("persisted trust manifest state is invalid")
        return (gen, digest)

    def _persist_state(self, generation: int, manifest_digest: str) -> None:
        if self._manifest_state_path is None:
            return
        parent = self._manifest_state_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        payload = (
            jcs_canonicalize_plan(
                {"generation": generation, "manifestDigest": manifest_digest}
            )
            + b"\n"
        )
        fd, tmp_name = tempfile.mkstemp(prefix=".manifest-state-", dir=str(parent))
        tmp_path = Path(tmp_name)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(tmp_path, self._manifest_state_path)
        finally:
            if fd >= 0:
                os.close(fd)
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    async def get_key(
        self,
        kid: str,
        *,
        now: datetime | None = None,
    ) -> Ed25519PublicKey | None:
        """Resolve an Ed25519 public key by ``kid``, enforcing lifecycle and revocation."""
        check_time = now or datetime.now(timezone.utc)
        cache_age = time.time() - self._cache_timestamp
        manifest_expired = (
            self._manifest_extension is not None
            and check_time >= self._manifest_extension.valid_until
        )
        if (
            cache_age > self._cache_ttl_seconds
            or not self._key_cache
            or manifest_expired
        ):
            await self._refresh_keys(now=check_time)

        if self._manifest_extension is not None:
            if check_time >= self._manifest_extension.valid_until:
                logger.error(
                    "Trust manifest expired at %s; failing closed for kid=%r",
                    self._manifest_extension.valid_until.isoformat(),
                    kid,
                )
                return None
            metadata = self._manifest_extension.key_metadata.get(kid)
            if metadata is None:
                logger.warning("kid=%r missing from trust manifest keyMetadata", kid)
                return None
            if metadata.revoked_at is not None:
                logger.error(
                    "kid=%r is revoked at %s; failing closed",
                    kid,
                    metadata.revoked_at.isoformat(),
                )
                return None
            if check_time < metadata.not_before or check_time >= metadata.not_after:
                logger.error(
                    "kid=%r is outside validity interval [%s, %s); failing closed",
                    kid,
                    metadata.not_before.isoformat(),
                    metadata.not_after.isoformat(),
                )
                return None

        key = self._key_cache.get(kid)
        if key is None:
            logger.warning(
                "Unknown kid=%r in key manifest (url=%s); caller must fail closed.",
                kid,
                self._manifest_url,
            )
        return key

    async def _read_manifest_bytes(self) -> bytes:
        parsed = urlparse(self._manifest_url)
        if parsed.scheme == "file":
            file_path = Path(unquote(parsed.path))
            raw_bytes = file_path.read_bytes()
        else:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.get(self._manifest_url)
                response.raise_for_status()
                raw_bytes = response.content

        if len(raw_bytes) < 1 or len(raw_bytes) > _MAX_MANIFEST_BYTES:
            raise ValueError("trust manifest size is invalid")
        return raw_bytes

    async def _refresh_keys(self, *, now: datetime | None = None) -> None:
        check_time = now or datetime.now(timezone.utc)
        raw_bytes = await self._read_manifest_bytes()
        try:
            text = raw_bytes.decode("utf-8")
            jwks_data = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("trust manifest JSON is invalid") from exc

        if not isinstance(jwks_data, dict) or "keys" not in jwks_data:
            raise ValueError("Invalid JWKS manifest: missing 'keys' array")

        has_extension = CAGE_MANIFEST_EXTENSION_URI in jwks_data
        if self._require_manifest_extension and not has_extension:
            raise ValueError(
                f"trust manifest missing required {CAGE_MANIFEST_EXTENSION_URI!r} extension"
            )

        if has_extension:
            self._validate_and_activate_extended_manifest(
                raw_bytes=raw_bytes,
                jwks_data=jwks_data,
                now=check_time,
            )
            return

        # Standard JWKS fallback for hermetic tests without manifest extension
        new_cache: dict[str, Ed25519PublicKey] = {}
        for jwk in jwks_data["keys"]:
            if not isinstance(jwk, dict):
                continue
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            kid = jwk.get("kid")
            x_b64 = jwk.get("x")
            if not kid or not x_b64:
                continue
            try:
                public_key_bytes = base64.urlsafe_b64decode(x_b64 + "==")
                new_cache[kid] = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            except Exception as exc:
                logger.warning("Failed to parse Ed25519 key kid=%s: %s", kid, exc)

        self._manifest_extension = None
        self._key_cache = new_cache
        self._cache_timestamp = time.time()

    def _validate_and_activate_extended_manifest(
        self,
        *,
        raw_bytes: bytes,
        jwks_data: dict[str, Any],
        now: datetime,
    ) -> None:
        if jcs_canonicalize_plan(jwks_data) != raw_bytes:
            raise ValueError("trust manifest must be canonical JSON")
        if set(jwks_data.keys()) != {"keys", CAGE_MANIFEST_EXTENSION_URI}:
            raise ValueError("trust manifest contains unknown or missing members")

        raw_keys = jwks_data["keys"]
        if not isinstance(raw_keys, list) or not (1 <= len(raw_keys) <= 128):
            raise ValueError("trust manifest JWK count is invalid")

        parsed_keys: dict[str, Ed25519PublicKey] = {}
        ordered_kids: list[str] = []
        for entry in raw_keys:
            if not isinstance(entry, dict) or set(entry.keys()) != {
                "alg",
                "crv",
                "kid",
                "kty",
                "use",
                "x",
            }:
                raise ValueError(
                    "trust manifest JWK contains unknown or missing members"
                )
            kid = entry["kid"]
            if not isinstance(kid, str) or not _SAFE_IDENTIFIER_RE.fullmatch(kid):
                raise ValueError("JWK kid is invalid")
            if (
                entry["kty"] != "OKP"
                or entry["crv"] != "Ed25519"
                or entry["use"] != "sig"
                or entry["alg"] != "EdDSA"
            ):
                raise ValueError("trust manifest JWK JOSE values are invalid")
            pub_bytes = _decode_b64url_exact(entry["x"], 32, "JWK public key")
            ordered_kids.append(kid)
            parsed_keys[kid] = Ed25519PublicKey.from_public_bytes(pub_bytes)

        if ordered_kids != sorted(ordered_kids) or len(set(ordered_kids)) != len(
            ordered_kids
        ):
            raise ValueError("trust manifest JWK kids must be sorted and unique")

        ext = jwks_data[CAGE_MANIFEST_EXTENSION_URI]
        if not isinstance(ext, dict) or set(ext.keys()) != {
            "authorityKeyId",
            "generation",
            "issuedAt",
            "keyMetadata",
            "manifestDigest",
            "receiptProfile",
            "signature",
            "signatureAlgorithm",
            "validUntil",
            "version",
        }:
            raise ValueError(
                "trust manifest extension contains unknown or missing members"
            )

        if ext["version"] != "1" or ext["signatureAlgorithm"] != "Ed25519":
            raise ValueError("trust manifest version or signature algorithm is invalid")
        generation = ext["generation"]
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 1
        ):
            raise ValueError("manifest generation is invalid")

        issued_at = _parse_iso_utc(ext["issuedAt"], "manifest issuedAt")
        valid_until = _parse_iso_utc(ext["validUntil"], "manifest validUntil")
        if issued_at >= valid_until:
            raise ValueError("trust manifest validity ordering is invalid")

        authority_key_id = ext["authorityKeyId"]
        if not isinstance(authority_key_id, str) or not _SAFE_IDENTIFIER_RE.fullmatch(
            authority_key_id
        ):
            raise ValueError("manifest authority key ID is invalid")

        manifest_digest = ext["manifestDigest"]
        if not isinstance(manifest_digest, str) or not _SHA256_RE.fullmatch(
            manifest_digest
        ):
            raise ValueError("trust manifest digest encoding is invalid")
        signature_bytes = _decode_b64url_exact(
            ext["signature"], 64, "trust manifest signature"
        )

        raw_profile = ext["receiptProfile"]
        if not isinstance(raw_profile, dict) or set(raw_profile.keys()) != {
            "audience",
            "engineVersion",
            "issuer",
            "maximumFutureSkewSeconds",
            "maximumReceiptLifetimeSeconds",
            "purpose",
        }:
            raise ValueError("receipt profile contains unknown or missing members")

        for field_name in ("audience", "engineVersion", "issuer", "purpose"):
            val = raw_profile[field_name]
            if (
                not isinstance(val, str)
                or len(val) == 0
                or len(val.encode("utf-8")) > 256
            ):
                raise ValueError(f"receipt profile {field_name} is invalid")

        max_skew = raw_profile["maximumFutureSkewSeconds"]
        max_lifetime = raw_profile["maximumReceiptLifetimeSeconds"]
        if (
            isinstance(max_skew, bool)
            or not isinstance(max_skew, int)
            or max_skew < 1
            or isinstance(max_lifetime, bool)
            or not isinstance(max_lifetime, int)
            or max_lifetime < 1
        ):
            raise ValueError("receipt profile numeric limits are invalid")
        if (
            max_skew > self._maximum_future_skew_seconds
            or max_lifetime > self._maximum_receipt_lifetime_seconds
        ):
            raise ValueError(
                "trust manifest receipt profile exceeds configured ceilings"
            )

        raw_metadata = ext["keyMetadata"]
        if not isinstance(raw_metadata, list) or len(raw_metadata) != len(ordered_kids):
            raise ValueError("trust manifest key metadata binding is invalid")

        key_metadata: dict[str, CageKeyMetadata] = {}
        for idx, item in enumerate(raw_metadata):
            if not isinstance(item, dict) or set(item.keys()) != {
                "kid",
                "notAfter",
                "notBefore",
                "revokedAt",
            }:
                raise ValueError("key metadata contains unknown or missing members")
            meta_kid = item["kid"]
            if meta_kid != ordered_kids[idx]:
                raise ValueError(
                    "trust manifest key metadata ordering or validity is invalid"
                )
            not_before = _parse_iso_utc(item["notBefore"], "key metadata notBefore")
            not_after = _parse_iso_utc(item["notAfter"], "key metadata notAfter")
            if not_before >= not_after:
                raise ValueError(
                    "trust manifest key metadata ordering or validity is invalid"
                )
            revoked_at: datetime | None = None
            if item["revokedAt"] is not None:
                revoked_at = _parse_iso_utc(item["revokedAt"], "key metadata revokedAt")
                if revoked_at < not_before or revoked_at >= not_after:
                    raise ValueError(
                        "trust manifest key revocation ordering is invalid"
                    )
            key_metadata[meta_kid] = CageKeyMetadata(
                kid=meta_kid,
                not_before=not_before,
                not_after=not_after,
                revoked_at=revoked_at,
            )

        unsigned_ext = {
            k: v for k, v in ext.items() if k not in ("manifestDigest", "signature")
        }
        unsigned_manifest = {
            "keys": raw_keys,
            CAGE_MANIFEST_EXTENSION_URI: unsigned_ext,
        }
        expected_digest = hashlib.sha256(
            jcs_canonicalize_plan(unsigned_manifest)
        ).hexdigest()
        if expected_digest != manifest_digest:
            raise ValueError("trust manifest digest mismatch")

        if self._authority_keys:
            authority_pub = self._authority_keys.get(authority_key_id)
            if authority_pub is None:
                raise ValueError("trust manifest authority key is unknown")
            sig_input = MANIFEST_SIGNATURE_DOMAIN + bytes.fromhex(expected_digest)
            try:
                authority_pub.verify(signature_bytes, sig_input)
            except InvalidSignature as exc:
                raise ValueError(
                    "trust manifest signature verification failed"
                ) from exc

        if issued_at > now + timedelta(seconds=self._maximum_future_skew_seconds):
            raise ValueError("trust manifest is issued too far in the future")
        if now >= valid_until:
            raise ValueError("trust manifest is expired")

        if self._accepted_state is not None:
            accepted_gen, accepted_digest = self._accepted_state
            if generation < accepted_gen:
                raise ValueError("trust manifest generation rollback")
            if generation == accepted_gen and manifest_digest != accepted_digest:
                raise ValueError("trust manifest equal-generation digest conflict")

        self._persist_state(generation, manifest_digest)
        self._accepted_state = (generation, manifest_digest)
        self._manifest_extension = CageManifestExtension(
            version="1",
            generation=generation,
            issued_at=issued_at,
            valid_until=valid_until,
            receipt_profile=CageReceiptProfile(
                issuer=raw_profile["issuer"],
                audience=raw_profile["audience"],
                purpose=raw_profile["purpose"],
                engine_version=raw_profile["engineVersion"],
                maximum_receipt_lifetime_seconds=max_lifetime,
                maximum_future_skew_seconds=max_skew,
            ),
            key_metadata=key_metadata,
            signature_algorithm="Ed25519",
            authority_key_id=authority_key_id,
            manifest_digest=manifest_digest,
            signature=ext["signature"],
        )
        self._key_cache = parsed_keys
        self._cache_timestamp = time.time()


Provider06KeyManifestClient = FileJWKSClient
