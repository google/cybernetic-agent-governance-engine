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
ConsequenceToken — Short-TTL, Single-Use JWS for FlowSignal Authority Decisions

Phase 2 (P1) implementation: Mints and verifies KMS-signed JWS tokens carrying
FlowSignal consequence authority decisions from the governance gate to downstream
execution adapters.

Architecture:
  - Minting: After a FlowSignal ALLOW decision, the provider calls ConsequenceToken.mint()
    to produce a compact JWS with claims (sub, tid, rec, act, ver, iat, exp, jti).
  - Verification: Downstream execution adapter calls ConsequenceToken.verify() before
    running the side-effect, checking signature, TTL, and claims integrity.
  - Single-use enforcement: The `rec` (authority record ID) is then consumed via
    ConsequenceAuthorityStore.consume_once() (not part of this module).

Token format: Compact JWS (RFC 7515)
  base64url(protected_header).base64url(payload).base64url(signature)

Security invariants (fail-closed):
  - Rejects `alg: none` and any header `alg` != signer.jose_alg (algorithm confusion)
  - TTL enforcement: rejects expired tokens and tokens with implausible future `iat`
  - All parse errors (malformed base64, non-JSON, missing claims, wrong types) raise
    ConsequenceTokenError

Dependencies:
  - KMSGovernanceSigner (sign_raw, verify_raw, key_id, jose_alg)
  - jcs_canonicalizer (for action digest recomputation by callers)

Usage (Phase 2 integration point, from provider_01 validate_fria):
  from src.gateway.governance.consequence_token import ConsequenceToken, ConsequenceTokenError
  from src.gateway.governance.kms_signer import get_signer
  from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

  signer = get_signer()
  action_digest = hashlib.sha256(jcs_canonicalize_plan(action_payload)).hexdigest()

  token = ConsequenceToken.mint(
      sub=actor_id,
      tid=thread_id,
      rec=authority_record_id,
      act=action_digest,
      ver=authority_state_version,
      signer=signer,
  )

  # ... token travels with execution plan ...

  # Downstream verification (execution adapter):
  try:
      claims = ConsequenceToken.verify(token, signer=signer)
      # Verify action digest matches current plan
      # consume_once(claims.rec, binding_hash(...))
      # execute side-effect
  except ConsequenceTokenError:
      # Reject execution
      pass
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

if TYPE_CHECKING:
    from src.gateway.governance.kms_signer import KMSGovernanceSigner

logger = logging.getLogger(__name__)

# Clock skew tolerance: allow tokens with `iat` up to 5 seconds in the future
# to account for minor clock drift between CAGE nodes. Conservative value per
# FlowSignal integration plan §5.4 risk mitigation (R2).
_CLOCK_SKEW_TOLERANCE_SECONDS = 5


class ConsequenceTokenError(Exception):
    """Raised on bad signature, expired token, or malformed claims."""


@dataclass(frozen=True)
class ConsequenceTokenClaims:
    """Claims payload for a ConsequenceToken JWS.

    Attributes:
        sub: Actor ID (subject making the request).
        tid: Thread ID (conversation/request identifier).
        rec: Authority record ID (single-use consumption key, equals jti).
        act: Action digest (SHA-256 hex over JCS-canonicalized action payload).
        ver: Authority state version (nullable; normalized to "" when None).
        iat: Issued-at timestamp (epoch seconds).
        exp: Expiry timestamp (epoch seconds; TTL 60s from iat).
        jti: JWT ID (unique token identifier, equals rec).
    """

    sub: str
    tid: str
    rec: str
    act: str
    ver: str | None
    iat: int
    exp: int
    jti: str


class ConsequenceToken:
    """Short-TTL, single-use JWS carrying FlowSignal authority decisions.

    Provides cryptographic binding between the governance evaluation (FlowSignal ALLOW)
    and the downstream execution adapter, preventing replay and substitution attacks.
    """

    @classmethod
    def mint(
        cls,
        *,
        sub: str,
        tid: str,
        rec: str,
        act: str,
        ver: str | None = None,
        ttl_seconds: int = 60,
        signer: KMSGovernanceSigner,
    ) -> str:
        """Mint a new ConsequenceToken JWS.

        Args:
            sub: Actor ID.
            tid: Thread ID.
            rec: Authority record ID (used for single-use consumption).
            act: Action digest (SHA-256 hex of JCS-canonicalized action payload).
            ver: Authority state version (optional, normalized to "" when None).
            ttl_seconds: Token time-to-live (default 60s).
            signer: KMSGovernanceSigner instance (must have KMS active).

        Returns:
            Compact JWS string: base64url(header).base64url(payload).base64url(signature)

        Raises:
            RuntimeError: If KMS is not active or signing fails.
        """
        now = int(time.time())

        # Protected header: MUST include alg, kid, typ per RFC 7515
        header = {
            "alg": signer.jose_alg,  # JOSE algorithm (ES256, EdDSA, etc.)
            "kid": signer.key_id,  # Key version resource name
            "typ": "JWT",  # Standard JWT type
        }

        # Normalize ver: None → "" to match ConsequenceAuthorityStore.binding_hash
        normalized_ver = ver if ver is not None else ""

        # Claims payload
        payload = {
            "sub": sub,
            "tid": tid,
            "rec": rec,
            "act": act,
            "ver": normalized_ver,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": rec,  # JWT ID equals authority record ID
        }

        # Build signing input: base64url(header).base64url(payload)
        # v3.1.0: Migrated to RFC 8785 JCS canonicalization
        # IMPORTANT: JWS requires exact byte reproduction at verification
        header_bytes = jcs_canonicalize_plan(header)
        payload_bytes = jcs_canonicalize_plan(payload)
        header_b64 = _b64url_encode(header_bytes)
        payload_b64 = _b64url_encode(payload_bytes)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        # Sign via KMS
        try:
            signature_bytes = signer.sign_raw(signing_input)
        except Exception as exc:
            logger.error(
                "[ConsequenceToken] Minting failed: KMS signing error: %s", exc
            )
            raise RuntimeError(f"ConsequenceToken minting failed: {exc}") from exc

        signature_b64 = _b64url_encode(signature_bytes)

        # Return compact JWS
        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        # Never log the full token (security requirement)
        logger.info(
            "[ConsequenceToken] Minted token for rec=%s, sub=%s, ttl=%ds",
            rec[:8] + "****",  # Mask rec
            sub[:8] + "****" if len(sub) > 8 else "****",  # Mask sub
            ttl_seconds,
        )

        return token

    @classmethod
    def verify(
        cls, token: str, *, signer: KMSGovernanceSigner
    ) -> ConsequenceTokenClaims:
        """Verify a ConsequenceToken JWS and return its claims.

        Performs the following checks (fail-closed):
        1. Parse token into three base64url segments
        2. Decode and validate protected header (alg, typ)
        3. Check TTL (not expired, not implausibly future-dated)
        4. Verify signature against KMS public key
        5. Parse and validate claims payload

        Args:
            token: Compact JWS string.
            signer: KMSGovernanceSigner instance (must have KMS active and public key loaded).

        Returns:
            ConsequenceTokenClaims with validated claims.

        Raises:
            ConsequenceTokenError: On any validation failure (bad signature, expired,
                malformed input, algorithm confusion, etc.).
        """
        # Step 1: Split into three segments
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ConsequenceTokenError(
                    f"Malformed token: expected 3 segments, got {len(parts)}"
                )
            header_b64, payload_b64, signature_b64 = parts
        except ValueError as exc:
            raise ConsequenceTokenError(f"Malformed token: {exc}") from exc

        # Step 2: Decode and validate protected header
        try:
            header_bytes = _b64url_decode(header_b64)
            header = json.loads(header_bytes)
        except Exception as exc:
            raise ConsequenceTokenError(f"Invalid header: {exc}") from exc

        # Security: Reject alg: none (critical security defect if allowed)
        header_alg = header.get("alg", "").upper()
        if header_alg == "NONE":
            raise ConsequenceTokenError("Rejected token with alg: none")

        # Security: Reject algorithm confusion (header alg != signer's expected alg)
        try:
            expected_alg = signer.jose_alg
        except RuntimeError as exc:
            raise ConsequenceTokenError(
                f"Cannot determine expected algorithm: {exc}"
            ) from exc

        if header_alg != expected_alg.upper():
            raise ConsequenceTokenError(
                f"Algorithm confusion: header alg={header_alg}, expected {expected_alg}"
            )

        # Validate typ header (should be JWT)
        header_typ = header.get("typ", "")
        if header_typ.upper() not in ("JWT", ""):
            logger.warning(
                "[ConsequenceToken] Unexpected typ header: %s (expected JWT)",
                header_typ,
            )

        # Step 3: Decode payload and check TTL (fail-fast before signature verification)
        try:
            payload_bytes = _b64url_decode(payload_b64)
            payload = json.loads(payload_bytes)
        except Exception as exc:
            raise ConsequenceTokenError(f"Invalid payload: {exc}") from exc

        now = int(time.time())

        # Check expiry (exp in the past)
        exp = payload.get("exp")
        if not isinstance(exp, int):
            raise ConsequenceTokenError(f"Invalid exp claim: {exp!r} (expected int)")
        if now > exp:
            raise ConsequenceTokenError(
                f"Token expired: exp={exp}, now={now} (age={now - exp}s)"
            )

        # Check iat (issued-at) is not implausibly in the future
        iat = payload.get("iat")
        if not isinstance(iat, int):
            raise ConsequenceTokenError(f"Invalid iat claim: {iat!r} (expected int)")
        if iat > now + _CLOCK_SKEW_TOLERANCE_SECONDS:
            raise ConsequenceTokenError(
                f"Token iat too far in future: iat={iat}, now={now} "
                f"(skew={iat - now}s > {_CLOCK_SKEW_TOLERANCE_SECONDS}s tolerance)"
            )

        # Step 4: Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        try:
            signature_bytes = _b64url_decode(signature_b64)
        except Exception as exc:
            raise ConsequenceTokenError(f"Invalid signature encoding: {exc}") from exc

        try:
            valid = signer.verify_raw(signing_input, signature_bytes)
        except RuntimeError as exc:
            # verify_raw raises RuntimeError on inactive KMS or missing public key (fail-closed)
            raise ConsequenceTokenError(
                f"Signature verification failed: {exc}"
            ) from exc

        if not valid:
            raise ConsequenceTokenError("Invalid signature")

        # Step 5: Parse and validate required claims
        try:
            claims = ConsequenceTokenClaims(
                sub=payload["sub"],
                tid=payload["tid"],
                rec=payload["rec"],
                act=payload["act"],
                ver=payload.get("ver"),  # nullable
                iat=iat,
                exp=exp,
                jti=payload["jti"],
            )
        except KeyError as exc:
            raise ConsequenceTokenError(f"Missing required claim: {exc}") from exc
        except TypeError as exc:
            raise ConsequenceTokenError(f"Invalid claim type: {exc}") from exc

        # Never log the full claims (security requirement)
        logger.debug(
            "[ConsequenceToken] Verified token for rec=%s, sub=%s",
            claims.rec[:8] + "****",
            claims.sub[:8] + "****" if len(claims.sub) > 8 else "****",
        )

        return claims


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes without padding (RFC 7515 Appendix C)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url-decode a string, adding padding as needed."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
