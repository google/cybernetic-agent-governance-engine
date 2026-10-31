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

"""Bind a verified OIDC identity to a conformance report (spec §3.1).

A report says who ran it, but only as the runner declared it. An attestation
replaces that claim with an identity an OIDC issuer vouches for:

* The token's audience is ``cage-conformance:<report digest>``, so it attests
  exactly one report, and any edit to the report breaks it.
* The issuer must be one of :data:`ISSUERS`. Its signing keys come from that
  issuer's pinned JWKS URL, never from the token, and are looked up by the
  token's ``kid``: an unknown ``kid`` fails closed. Only RS256 with keys of at
  least 2048 bits is accepted.
* The verified principal (``github:<owner>/<repo>`` or ``google:<email>``) is
  compared with the party principals pinned for the report's contract
  profile, never with the organizations the runner declared. The pins are the
  relying party's: the package's defaults, or a file the verifier supplies.

Everything here is standard library except the RSA signature check, which uses
the optional ``cryptography`` package (``pip install 'cage-conformance[attest]'``).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from types import MappingProxyType
from typing import Any

from .report import (
    ConformanceReport,
    ReportError,
    VerificationPosture,
    validate_report,
)

ATTESTED_SCHEMA_VERSION = "cage-conformance-attested-report/1"
#: Printed on the face of every attested report. The artifact exists before any
#: verifier has judged it, so it says plainly that a signature is not an
#: endorsement: the posture is the relying party's to derive.
ATTESTED_NOTICE = (
    "This attestation proves who signed the report and nothing more. It grants "
    "no verification posture: each relying party derives one by running "
    "'cage-conformance verify-report' with its own party pins, and a signer "
    "those pins do not recognize earns none."
)
PARTIES_SCHEMA_VERSION = "cage-conformance-parties/1"
AUDIENCE_PREFIX = "cage-conformance:"
OIDC_ENV_VAR = "CAGE_CONFORMANCE_OIDC_TOKEN"

#: Seconds of clock skew tolerated between the issuer, the runner and the verifier.
CLOCK_SKEW_SECONDS = 60
MIN_RSA_BITS = 2048
_MAX_JWKS_BYTES = 1 << 20

_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_GITHUB_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_PRINCIPAL = re.compile(r"(github|google):\S+")
#: Header parameters that carry a key or point to one. A verifier that honored
#: them would let the token choose its own trust anchor, so they are refused.
_EMBEDDED_KEY_HEADERS = frozenset({"jwk", "jku", "x5c", "x5u"})


class AttestationError(ReportError):
    """An attestation is malformed, untrusted or does not match its report."""


class UnpinnedPartyError(AttestationError):
    """The attestation verifies, but the party pins cannot place its principal."""


# ── Issuers ───────────────────────────────────────────────────────────────────


def _github_principal(claims: Mapping[str, Any]) -> str:
    repository = claims.get("repository")
    if not isinstance(repository, str) or not _GITHUB_REPOSITORY.fullmatch(repository):
        raise AttestationError("GitHub token has no valid 'repository' claim")
    return f"github:{repository.lower()}"


def _google_principal(claims: Mapping[str, Any]) -> str:
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email:
        raise AttestationError("Google token has no 'email' claim")
    if claims.get("email_verified") is not True:
        raise AttestationError("Google token's email is not verified")
    return f"google:{email.lower()}"


@dataclass(frozen=True)
class Issuer:
    """A trusted OIDC issuer: where its keys live and how it names a principal."""

    name: str
    jwks_url: str
    principal: Callable[[Mapping[str, Any]], str]


_GITHUB = Issuer(
    name="GitHub Actions",
    jwks_url="https://token.actions.githubusercontent.com/.well-known/jwks",
    principal=_github_principal,
)
_GOOGLE = Issuer(
    name="Google",
    jwks_url="https://www.googleapis.com/oauth2/v3/certs",
    principal=_google_principal,
)

#: Exact ``iss`` claim -> issuer. Google issues under both spellings.
ISSUERS: Mapping[str, Issuer] = MappingProxyType(
    {
        "https://token.actions.githubusercontent.com": _GITHUB,
        "https://accounts.google.com": _GOOGLE,
        "accounts.google.com": _GOOGLE,
    }
)


# ── Keys ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RsaKey:
    """An RSA public key from a pinned issuer's JWKS."""

    kid: str
    n: int
    e: int


@dataclass(frozen=True)
class KeySet:
    """The signing keys one pinned issuer publishes, looked up by ``kid``."""

    jwks_url: str
    keys: Mapping[str, RsaKey]

    def key_for(self, kid: str) -> RsaKey:
        key = self.keys.get(kid)
        if key is None:
            raise AttestationError(
                f"kid {kid!r} is not in the JWKS at {self.jwks_url}: unknown key, "
                "or one the issuer no longer publishes"
            )
        return key


#: Fetches the key set of a pinned issuer. Tests inject one; the CLI fetches.
KeyResolver = Callable[[Issuer], KeySet]


def _b64url(segment: str, what: str) -> bytes:
    if not _B64URL.fullmatch(segment):
        raise AttestationError(f"{what} is not base64url")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as exc:
        raise AttestationError(f"{what} is not base64url") from exc


def _b64url_int(value: Any, what: str) -> int:
    if not isinstance(value, str) or not value:
        raise AttestationError(f"JWK {what} is missing")
    return int.from_bytes(_b64url(value, f"JWK {what}"), "big")


def key_set_from_jwks(document: Any, jwks_url: str) -> KeySet:
    """The RS256 signing keys in a JWKS document; other keys are ignored."""
    if not isinstance(document, Mapping) or not isinstance(document.get("keys"), list):
        raise AttestationError(f"{jwks_url} did not return a JWKS document")
    keys: dict[str, RsaKey] = {}
    for jwk in document["keys"]:
        if not isinstance(jwk, Mapping) or jwk.get("kty") != "RSA":
            continue
        if jwk.get("alg", "RS256") != "RS256" or jwk.get("use", "sig") != "sig":
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        keys[kid] = RsaKey(
            kid=kid, n=_b64url_int(jwk.get("n"), "n"), e=_b64url_int(jwk.get("e"), "e")
        )
    return KeySet(jwks_url=jwks_url, keys=MappingProxyType(keys))


def _https_get(url: str) -> bytes:
    """GET a pinned https URL, reading at most one byte past the size limit."""
    if not url.startswith("https://"):
        raise AttestationError(f"JWKS URL must be https: {url}")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    # Bandit B310: the scheme is checked to be https just above.
    with urllib.request.urlopen(request, timeout=10) as resp:  # nosec B310
        return bytes(resp.read(_MAX_JWKS_BYTES + 1))


def fetch_key_set(issuer: Issuer) -> KeySet:
    """Fetch a pinned issuer's JWKS over HTTPS."""
    try:
        body = _https_get(issuer.jwks_url)
    except OSError as exc:
        raise AttestationError(f"cannot fetch {issuer.jwks_url}: {exc}") from exc
    if len(body) > _MAX_JWKS_BYTES:
        raise AttestationError(
            f"{issuer.jwks_url} returned more than {_MAX_JWKS_BYTES} bytes"
        )
    try:
        document = json.loads(body)
    except ValueError as exc:
        raise AttestationError(f"{issuer.jwks_url} did not return JSON") from exc
    return key_set_from_jwks(document, issuer.jwks_url)


# ── Tokens ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VerifiedIdentity:
    """Who an issuer vouches ran the check, from a verified token."""

    iss: str
    principal: str
    issued_at: int
    expires_at: int


def _require_cryptography() -> None:
    """Fail before any network call if the RSA check cannot run."""
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:
        raise AttestationError(
            "checking an attestation needs the 'attest' extra: "
            "pip install 'cage-conformance[attest]'"
        ) from exc


def _verify_rs256(key: RsaKey, signing_input: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    if key.n.bit_length() < MIN_RSA_BITS:
        raise AttestationError(f"kid {key.kid!r} is shorter than {MIN_RSA_BITS} bits")
    try:
        public_key = rsa.RSAPublicNumbers(key.e, key.n).public_key()
    except ValueError as exc:
        raise AttestationError(f"kid {key.kid!r} is not a valid RSA key") from exc
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise AttestationError("token signature does not verify") from exc


def _json_object(raw: bytes, what: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise AttestationError(f"token {what} is not JSON") from exc
    if not isinstance(value, dict):
        raise AttestationError(f"token {what} is not a JSON object")
    return value


def _timestamp(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AttestationError(f"token '{name}' claim must be an integer")
    return value


def audience_for(report: ConformanceReport) -> str:
    """The audience a token must carry to attest ``report``."""
    return AUDIENCE_PREFIX + report.digest()


def verify_token(
    token: str,
    *,
    audience: str,
    resolve: KeyResolver,
    now: float,
    not_before: float,
    enforce_expiry: bool,
) -> VerifiedIdentity:
    """Verify an OIDC ID token from a pinned issuer and return its principal.

    Args:
        audience: the only audience the token may carry.
        resolve: fetches a pinned issuer's keys; the token never supplies them.
        now: the verification time, in seconds since the epoch.
        not_before: the earliest acceptable issue time (the report's timestamp).
        enforce_expiry: reject an expired token. ``attest`` sets this; a later
            ``verify-report`` does not, because the audience already binds the
            token to one report.
    """
    _require_cryptography()
    if not isinstance(token, str):
        raise AttestationError("token must be a string")
    segments = token.strip().split(".")
    if len(segments) != 3:
        raise AttestationError("token is not a signed JWT (three segments)")
    header = _json_object(_b64url(segments[0], "token header"), "header")
    claims = _json_object(_b64url(segments[1], "token payload"), "payload")
    signature = _b64url(segments[2], "token signature")

    if header.get("alg") != "RS256":
        raise AttestationError(f"token alg must be RS256, not {header.get('alg')!r}")
    if header.keys() & _EMBEDDED_KEY_HEADERS:
        raise AttestationError(
            "token header carries its own key; keys come only from the pinned JWKS"
        )
    if "crit" in header:
        raise AttestationError(
            "token header has critical extensions this verifier does not implement"
        )
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AttestationError("token header has no kid")

    iss = claims.get("iss")
    if not isinstance(iss, str) or iss not in ISSUERS:
        raise AttestationError(f"token issuer {iss!r} is not a pinned issuer")
    issuer = ISSUERS[iss]
    key = resolve(issuer).key_for(kid)
    _verify_rs256(key, f"{segments[0]}.{segments[1]}".encode("ascii"), signature)

    aud = claims.get("aud")
    if aud != audience and aud != [audience]:
        raise AttestationError(
            f"token audience {aud!r} is not {audience!r}: it attests another report"
        )
    issued_at = _timestamp(claims, "iat")
    expires_at = _timestamp(claims, "exp")
    if expires_at < issued_at:
        raise AttestationError("token expires before it was issued")
    if issued_at > now + CLOCK_SKEW_SECONDS:
        raise AttestationError("token was issued in the future")
    if issued_at < not_before - CLOCK_SKEW_SECONDS:
        raise AttestationError("token was issued before the report it attests")
    if enforce_expiry:
        if now > expires_at + CLOCK_SKEW_SECONDS:
            raise AttestationError("token has expired")
        if "nbf" in claims and now < _timestamp(claims, "nbf") - CLOCK_SKEW_SECONDS:
            raise AttestationError("token is not valid yet")
    return VerifiedIdentity(
        iss=iss,
        principal=issuer.principal(claims),
        issued_at=issued_at,
        expires_at=expires_at,
    )


# ── Attested reports ──────────────────────────────────────────────────────────


def _report_time(report: ConformanceReport) -> float:
    stamp = report.provenance.runner.timestamp_utc.strip()
    if stamp.endswith("Z"):
        stamp = stamp[:-1] + "+00:00"
    return datetime.fromisoformat(stamp).timestamp()


@dataclass(frozen=True)
class AttestedReport:
    """A report and the verified token that attests it."""

    report: ConformanceReport
    oidc_token: str
    identity: VerifiedIdentity

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTESTED_SCHEMA_VERSION,
            "notice": ATTESTED_NOTICE,
            "report": self.report.to_dict(),
            "attestation": {"oidc_token": self.oidc_token},
        }


def attest(
    report: ConformanceReport, token: str, *, resolve: KeyResolver, now: float
) -> AttestedReport:
    """Bind ``token`` to ``report``; the token must be current and attest this report."""
    identity = verify_token(
        token,
        audience=audience_for(report),
        resolve=resolve,
        now=now,
        not_before=_report_time(report),
        enforce_expiry=True,
    )
    return AttestedReport(report=report, oidc_token=token.strip(), identity=identity)


_ATTESTED_KEYS = frozenset({"schema_version", "notice", "report", "attestation"})


def validate_attested_report(
    raw: Any, *, resolve: KeyResolver, now: float
) -> AttestedReport:
    """Parse an attested report strictly and re-verify its token."""
    if not isinstance(raw, Mapping) or set(raw) != _ATTESTED_KEYS:
        raise AttestationError(
            "an attested report has exactly schema_version, notice, report and "
            "attestation"
        )
    if raw["schema_version"] != ATTESTED_SCHEMA_VERSION:
        raise AttestationError(
            f"schema_version is {raw['schema_version']!r}, expected {ATTESTED_SCHEMA_VERSION!r}"
        )
    if raw["notice"] != ATTESTED_NOTICE:
        raise AttestationError(
            "the notice that the signature grants no posture is missing or altered"
        )
    attestation = raw["attestation"]
    if not isinstance(attestation, Mapping) or set(attestation) != {"oidc_token"}:
        raise AttestationError("attestation has exactly one field, oidc_token")
    report = validate_report(raw["report"])
    token = attestation["oidc_token"]
    identity = verify_token(
        token,
        audience=audience_for(report),
        resolve=resolve,
        now=now,
        not_before=_report_time(report),
        enforce_expiry=False,
    )
    return AttestedReport(report=report, oidc_token=token, identity=identity)


def is_attested(raw: Any) -> bool:
    """Whether a parsed JSON document claims to be an attested report."""
    return (
        isinstance(raw, Mapping)
        and raw.get("schema_version") == ATTESTED_SCHEMA_VERSION
    )


# ── Parties and posture ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class Parties:
    """The principals pinned for one contract profile.

    ``counterparty`` is ``None`` when the seam has no counterparty. An empty
    tuple, for either role, means the role exists but its principals are not
    pinned, so a principal outside the pins could hold it.
    """

    author: tuple[str, ...]
    counterparty: tuple[str, ...] | None


def _principals(raw: Any, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise AttestationError(f"{where} must be a list of principals")
    principals = []
    for item in raw:
        if not isinstance(item, str) or not _PRINCIPAL.fullmatch(item.lower()):
            raise AttestationError(
                f"{where}: {item!r} is not github:<owner>/<repo> or google:<email>"
            )
        principals.append(item.lower())
    return tuple(principals)


def parse_parties(raw: Any) -> Mapping[str, Parties]:
    """Profile -> pinned parties, from a ``cage-conformance-parties/1`` document."""
    if not isinstance(raw, Mapping) or set(raw) != {"schema_version", "profiles"}:
        raise AttestationError(
            "a parties document has exactly schema_version and profiles"
        )
    if raw["schema_version"] != PARTIES_SCHEMA_VERSION:
        raise AttestationError(
            f"parties schema_version must be {PARTIES_SCHEMA_VERSION!r}"
        )
    if not isinstance(raw["profiles"], Mapping):
        raise AttestationError("parties profiles must be an object")
    parties: dict[str, Parties] = {}
    for profile, entry in raw["profiles"].items():
        if not isinstance(entry, Mapping) or set(entry) != {"author", "counterparty"}:
            raise AttestationError(
                f"parties for {profile!r} have exactly author and counterparty"
            )
        counterparty = entry["counterparty"]
        parties[profile] = Parties(
            author=_principals(entry["author"], f"{profile}.author"),
            counterparty=None
            if counterparty is None
            else _principals(counterparty, f"{profile}.counterparty"),
        )
    return MappingProxyType(parties)


def default_parties() -> Mapping[str, Parties]:
    """The parties this package pins for its own contract profiles."""
    text = (
        resources.files("cage_conformance")
        .joinpath("parties.json")
        .read_text(encoding="utf-8")
    )
    return parse_parties(json.loads(text))


def attested_posture(
    principal: str, profile: str, parties: Mapping[str, Parties]
) -> VerificationPosture:
    """The posture a verified principal earns under the pinned parties.

    Raises:
        UnpinnedPartyError: if the profile has no pins, or the principal is
            outside them while a role's principals are unpinned: it might hold
            that role, so neither counterparty nor independent can be claimed.
    """
    pinned = parties.get(profile)
    if pinned is None:
        raise UnpinnedPartyError(
            f"no parties are pinned for contract profile {profile!r}. "
            "Supply them with --parties."
        )
    if principal in pinned.author:
        return VerificationPosture.AUTHOR_SELF_TEST
    if pinned.counterparty is not None and principal in pinned.counterparty:
        return VerificationPosture.COUNTERPARTY_VERIFIED
    unpinned = [
        role
        for role, principals in (
            ("author", pinned.author),
            ("counterparty", pinned.counterparty),
        )
        if principals is not None and not principals
    ]
    if unpinned:
        raise UnpinnedPartyError(
            f"{principal} is not a pinned party of {profile!r}, whose "
            f"{' and '.join(unpinned)} principals are not pinned: it could be that "
            "party. Supply the parties with --parties."
        )
    return VerificationPosture.INDEPENDENT_PARTY_VERIFIED
