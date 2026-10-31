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

"""cage-conformance attestation (CONFORMANCE_VERIFIER_SPEC.md §3.1).

Tokens are signed here with a locally generated RSA key and resolved through an
injected key resolver, so no test reaches an issuer. What the tests pin down:

* a token attests exactly one report, from a pinned issuer, under a key looked
  up by kid from that issuer's JWKS and never from the token;
* every malformed, foreign, forged or stale token fails closed;
* a verified posture comes only from the relying party's party pins, and a
  principal that an unpinned role could cover earns none.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_PACKAGE_SRC = (
    Path(__file__).resolve().parents[1] / "packages" / "cage-conformance" / "src"
)
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

import cage_conformance as cc  # noqa: E402
from cage_conformance import cli as cli_mod  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.local]

GITHUB = "https://token.actions.githubusercontent.com"
GOOGLE = "https://accounts.google.com"
CAGE_REPO = "google/cybernetic-agent-governance-engine"
KID = "kid-1"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_WEAK_KEY = rsa.generate_private_key(public_exponent=65537, key_size=1024)
_VECTOR = json.loads(
    (_PACKAGE_SRC / "cage_conformance" / "vectors" / "trace_v1.json").read_text(
        encoding="utf-8"
    )
)["conformant_trace"]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk(key: rsa.RSAPrivateKey, kid: str = KID, **extra: str) -> dict[str, str]:
    numbers = key.public_key().public_numbers()

    def raw(value: int) -> str:
        return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    return {"kty": "RSA", "kid": kid, "n": raw(numbers.n), "e": raw(numbers.e)} | extra


def _token(
    claims: dict[str, Any],
    *,
    key: rsa.RSAPrivateKey = _KEY,
    header: dict[str, Any] | None = None,
) -> str:
    head = {"alg": "RS256", "kid": KID, "typ": "JWT"} | (header or {})
    signing_input = (
        f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(claims).encode())}"
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64(signature)}"


class _Resolver:
    """Serves one JWKS per pinned issuer and records which issuers were asked."""

    def __init__(self, *jwks: dict[str, str]) -> None:
        self.document = {"keys": list(jwks) or [_jwk(_KEY)]}
        self.asked: list[cc.attestation.Issuer] = []

    def __call__(self, issuer: cc.attestation.Issuer) -> cc.KeySet:
        self.asked.append(issuer)
        return cc.key_set_from_jwks(self.document, issuer.jwks_url)


def _report(
    runner_org: str = "Google LLC", *, timestamp: float | None = None
) -> cc.ConformanceReport:
    stamp = time.time() if timestamp is None else timestamp
    adapter = cc.AdapterUnderTest(
        provider_id="cage-kernel",
        adapter_author_org="Google LLC",
        counterparty_org="Example Bank",
        adapter_version="5.0.0",
        adapter_commit="42bdd429",
        contract_profile="trace-v1",
    )
    runner = cc.RunnerProvenance(
        runner_org=runner_org,
        runner_identity="ci@example.test",
        cage_conformance_version=cc.__version__,
        timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(stamp)),
    )
    inputs = (cc.InputDigest.of_bytes("trace.jsonl", b"vector"),)
    return cc.verify_trace(
        _VECTOR, provenance=cc.build_provenance(adapter, runner), inputs=inputs
    )


def _github_claims(report: cc.ConformanceReport, now: float, **over: Any) -> dict:
    return {
        "iss": GITHUB,
        "aud": cc.audience_for(report),
        "sub": f"repo:{CAGE_REPO}:ref:refs/heads/main",
        "repository": CAGE_REPO,
        "iat": int(now),
        "nbf": int(now) - 5,
        "exp": int(now) + 300,
    } | over


def _google_claims(report: cc.ConformanceReport, now: float, **over: Any) -> dict:
    return {
        "iss": GOOGLE,
        "aud": cc.audience_for(report),
        "sub": "1234567890",
        "email": "Auditor@Example.test",
        "email_verified": True,
        "iat": int(now),
        "exp": int(now) + 300,
    } | over


# ── Binding a verified identity to one report ─────────────────────────────────


def test_attest_binds_a_github_identity_to_exactly_one_report() -> None:
    now = time.time()
    report = _report()
    resolve = _Resolver()
    attested = cc.attest(
        report, _token(_github_claims(report, now)), resolve=resolve, now=now
    )

    assert attested.identity.principal == f"github:{CAGE_REPO}"
    assert attested.identity.iss == GITHUB
    assert resolve.asked == [cc.ISSUERS[GITHUB]], "keys come from the pinned issuer"

    raw = json.loads(json.dumps(attested.to_dict()))
    assert raw["schema_version"] == cc.ATTESTED_SCHEMA_VERSION
    assert list(raw)[:2] == ["schema_version", "notice"], "the notice leads the face"
    assert raw["notice"] == cc.ATTESTED_NOTICE
    again = cc.validate_attested_report(raw, resolve=_Resolver(), now=now)
    assert again.identity == attested.identity
    assert again.report == report


def test_google_identities_need_a_verified_email() -> None:
    now = time.time()
    report = _report("Example Auditor")
    attested = cc.attest(
        report, _token(_google_claims(report, now)), resolve=_Resolver(), now=now
    )
    assert attested.identity.principal == "google:auditor@example.test"

    unverified = _token(_google_claims(report, now, email_verified=False))
    with pytest.raises(cc.AttestationError, match="not verified"):
        cc.attest(report, unverified, resolve=_Resolver(), now=now)


def test_an_expired_token_still_attests_its_report_later() -> None:
    """The audience binds the token to one report, so expiry only gates attest."""
    now = time.time()
    report = _report()
    attested = cc.attest(
        report, _token(_github_claims(report, now)), resolve=_Resolver(), now=now
    )
    ten_days = now + 10 * 86400
    later = cc.validate_attested_report(
        attested.to_dict(), resolve=_Resolver(), now=ten_days
    )
    assert later.identity.principal == f"github:{CAGE_REPO}"
    with pytest.raises(cc.AttestationError, match="expired"):
        cc.attest(report, attested.oidc_token, resolve=_Resolver(), now=ten_days)


def test_the_face_says_a_signature_grants_no_posture() -> None:
    """The artifact exists before any verifier judges it, so it must say so."""
    for claim in (
        "proves who signed the report and nothing more",
        "grants no verification posture",
        "its own party pins",
        "a signer those pins do not recognize earns none",
    ):
        assert claim in cc.ATTESTED_NOTICE

    now = time.time()
    report = _report()
    attested = cc.attest(
        report, _token(_github_claims(report, now)), resolve=_Resolver(), now=now
    )
    stripped = attested.to_dict()
    del stripped["notice"]
    reworded = attested.to_dict() | {"notice": "Verified by CAGE."}
    for raw in (stripped, reworded):
        with pytest.raises(cc.AttestationError, match="notice"):
            cc.validate_attested_report(raw, resolve=_Resolver(), now=now)


def test_any_edit_to_an_attested_report_breaks_its_attestation() -> None:
    now = time.time()
    report = _report()
    attested = cc.attest(
        report, _token(_github_claims(report, now)), resolve=_Resolver(), now=now
    )
    raw = attested.to_dict()
    raw["report"]["inputs"][0]["sha256"] = "0" * 64
    with pytest.raises(cc.AttestationError, match="attests another report"):
        cc.validate_attested_report(raw, resolve=_Resolver(), now=now)


# ── Every malformed, foreign, forged or stale token fails closed ──────────────


_NOW = time.time()
_REPORT = _report(timestamp=_NOW)


def _rejections() -> list[Any]:
    """(id, token, message) for tokens that must not attest ``_REPORT`` at ``_NOW``."""
    now = int(_NOW)
    other = _report("Someone Else", timestamp=_NOW)
    claims = _github_claims(_REPORT, _NOW)
    head, body, sig = _token(claims).split(".")
    forged_body = _b64(json.dumps(claims | {"repository": "evil/repo"}).encode())
    none_head = _b64(json.dumps({"alg": "none", "kid": KID}).encode())
    return [
        ("another-report", _token(_github_claims(other, _NOW)), "attests another"),
        ("extra-audience", _token(claims | {"aud": [claims["aud"], "x"]}), "audience"),
        ("untrusted-issuer", _token(claims | {"iss": "https://evil.test"}), "pinned"),
        ("alg-hs256", _token(claims, header={"alg": "HS256"}), "RS256"),
        ("alg-none", f"{none_head}.{body}.", "RS256"),
        ("unknown-kid", _token(claims, header={"kid": "kid-2"}), "unknown key"),
        ("attacker-key", _token(claims, key=_ATTACKER_KEY), "signature"),
        ("tampered-payload", f"{head}.{forged_body}.{sig}", "signature"),
        (
            "embedded-jwk",
            _token(claims, header={"jwk": _jwk(_ATTACKER_KEY)}),
            "own key",
        ),
        ("jku", _token(claims, header={"jku": "https://evil.test/jwks"}), "own key"),
        ("crit", _token(claims, header={"crit": ["exp"]}), "critical"),
        ("no-kid", _token(claims, header={"kid": ""}), "no kid"),
        ("future", _token(claims | {"iat": now + 3600, "exp": now + 7200}), "future"),
        ("not-yet-valid", _token(claims | {"nbf": now + 3600}), "not valid yet"),
        ("before-report", _token(claims | {"iat": now - 3600}), "before the report"),
        ("exp-before-iat", _token(claims | {"exp": now - 10}), "before it was issued"),
        ("bool-iat", _token(claims | {"iat": True}), "integer"),
        ("no-repository", _token(claims | {"repository": ""}), "repository"),
        ("two-segments", f"{head}.{body}", "three segments"),
        ("not-base64", f"{head}.{body}.!!!", "base64url"),
        ("weak-key", _token(claims, key=_WEAK_KEY, header={"kid": "weak"}), "2048"),
    ]


@pytest.mark.parametrize(
    ("token", "message"),
    [pytest.param(token, message, id=name) for name, token, message in _rejections()],
)
def test_bad_tokens_fail_closed(token: str, message: str) -> None:
    resolve = _Resolver(_jwk(_KEY), _jwk(_WEAK_KEY, kid="weak"))
    with pytest.raises(cc.AttestationError, match=message):
        cc.attest(_REPORT, token, resolve=resolve, now=_NOW)


# ── Keys: only RS256 signing keys from the pinned JWKS ────────────────────────


def test_key_sets_keep_only_rs256_signing_keys() -> None:
    document = {
        "keys": [
            _jwk(_KEY),
            _jwk(_KEY, kid="enc", use="enc"),
            _jwk(_KEY, kid="ps", alg="PS256"),
            {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
            {"kty": "RSA", "n": "AQAB", "e": "AQAB"},
        ]
    }
    keys = cc.key_set_from_jwks(document, "https://issuer.test/jwks")
    assert set(keys.keys) == {KID}
    with pytest.raises(cc.AttestationError, match="unknown key"):
        keys.key_for("enc")
    with pytest.raises(cc.AttestationError, match="JWKS document"):
        cc.key_set_from_jwks({"keys": "none"}, "https://issuer.test/jwks")


def test_issuers_pin_https_jwks_urls_and_fetching_refuses_anything_else() -> None:
    assert set(cc.ISSUERS) == {GITHUB, GOOGLE, "accounts.google.com"}
    for issuer in cc.ISSUERS.values():
        assert issuer.jwks_url.startswith("https://")
    insecure = cc.attestation.Issuer("test", "http://issuer.test/jwks", str)
    with pytest.raises(cc.AttestationError, match="must be https"):
        cc.fetch_key_set(insecure)


def test_fetch_key_set_bounds_and_parses_the_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = cc.ISSUERS[GITHUB]
    document = json.dumps({"keys": [_jwk(_KEY)]}).encode()
    monkeypatch.setattr(cc.attestation, "_https_get", lambda url: document)
    assert set(cc.fetch_key_set(issuer).keys) == {KID}

    monkeypatch.setattr(cc.attestation, "_https_get", lambda url: b"x" * (1 << 21))
    with pytest.raises(cc.AttestationError, match="more than"):
        cc.fetch_key_set(issuer)
    monkeypatch.setattr(cc.attestation, "_https_get", lambda url: b"<html>")
    with pytest.raises(cc.AttestationError, match="JSON"):
        cc.fetch_key_set(issuer)


# ── Posture: only the relying party's pins grant a verified posture ───────────

_PINS = {
    "author-only": cc.Parties(author=(f"github:{CAGE_REPO}",), counterparty=None),
    "pinned": cc.Parties(
        author=(f"github:{CAGE_REPO}",), counterparty=("google:b@x.test",)
    ),
    "counterparty-unpinned": cc.Parties(
        author=(f"github:{CAGE_REPO}",), counterparty=()
    ),
    "author-unpinned": cc.Parties(author=(), counterparty=(f"github:{CAGE_REPO}",)),
}


@pytest.mark.parametrize(
    ("principal", "profile", "expected"),
    [
        (f"github:{CAGE_REPO}", "pinned", cc.VerificationPosture.AUTHOR_SELF_TEST),
        ("google:b@x.test", "pinned", cc.VerificationPosture.COUNTERPARTY_VERIFIED),
        (
            "google:c@x.test",
            "pinned",
            cc.VerificationPosture.INDEPENDENT_PARTY_VERIFIED,
        ),
        (
            "google:c@x.test",
            "author-only",
            cc.VerificationPosture.INDEPENDENT_PARTY_VERIFIED,
        ),
        (
            f"github:{CAGE_REPO}",
            "author-unpinned",
            cc.VerificationPosture.COUNTERPARTY_VERIFIED,
        ),
    ],
)
def test_pinned_principals_earn_their_posture(
    principal: str, profile: str, expected: cc.VerificationPosture
) -> None:
    assert cc.attested_posture(principal, profile, _PINS) is expected


@pytest.mark.parametrize(
    ("profile", "message"),
    [
        ("counterparty-unpinned", "counterparty principals are not pinned"),
        ("author-unpinned", "author principals are not pinned"),
        ("unknown-profile", "no parties are pinned"),
    ],
)
def test_an_unpinned_role_withholds_any_verified_posture(
    profile: str, message: str
) -> None:
    with pytest.raises(cc.AttestationError, match=message):
        cc.attested_posture("google:c@x.test", profile, _PINS)


def test_default_pins_name_the_author_and_leave_the_operator_to_the_verifier() -> None:
    parties = cc.default_parties()
    for profile in cc.MODE_PROFILES.values():
        assert parties[profile].author == (f"github:{CAGE_REPO}",)
        assert parties[profile].counterparty == ()


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": "x", "profiles": {}},
        {"schema_version": cc.PARTIES_SCHEMA_VERSION},
        {
            "schema_version": cc.PARTIES_SCHEMA_VERSION,
            "profiles": {
                "trace-v1": {"author": ["Example Bank"], "counterparty": None}
            },
        },
        {
            "schema_version": cc.PARTIES_SCHEMA_VERSION,
            "profiles": {"trace-v1": {"author": []}},
        },
    ],
)
def test_malformed_party_pins_are_rejected(document: dict[str, Any]) -> None:
    with pytest.raises(cc.AttestationError):
        cc.parse_parties(document)


# ── CLI: verify, audience, attest, verify-report ──────────────────────────────


def _verify(tmp_path: Path, runner_org: str) -> Path:
    trace = tmp_path / "trace.jsonl"
    trace.write_text("".join(json.dumps(e) + "\n" for e in _VECTOR), encoding="utf-8")
    report = tmp_path / f"{runner_org.replace(' ', '_')}.json"
    argv = [
        "verify",
        "--trace",
        str(trace),
        "--output",
        str(report),
        "--provider-id",
        "cage-kernel",
        "--adapter-author-org",
        "Google LLC",
        "--counterparty-org",
        "Example Bank",
        "--adapter-version",
        "5.0.0",
        "--adapter-commit",
        "42bdd429",
        "--runner-org",
        runner_org,
        "--runner-identity",
        "ci@example.test",
    ]
    assert cli_mod.main(argv) == 0
    return report


def test_cli_attests_and_the_relying_party_derives_the_posture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli_mod, "fetch_key_set", _Resolver())
    now = time.time()

    # CAGE's own CI: the default pins name it the author.
    report_path = _verify(tmp_path, "Google LLC")
    capsys.readouterr()
    assert cli_mod.main(["audience", str(report_path)]) == 0
    audience = capsys.readouterr().out.strip()
    report = cc.validate_report(json.loads(report_path.read_text()))
    assert audience == cc.audience_for(report)
    token_file = tmp_path / "token"
    token_file.write_text(_token(_github_claims(report, now)))
    attested = tmp_path / "attested.json"
    argv = ["attest", str(report_path), "--output", str(attested)]
    assert cli_mod.main([*argv, "--token-file", str(token_file)]) == 0
    assert cc.ATTESTED_NOTICE in capsys.readouterr().out
    assert cli_mod.main(["verify-report", str(attested)]) == 0
    out = capsys.readouterr().out
    assert "posture=AUTHOR_SELF_TEST" in out and f"github:{CAGE_REPO}" in out
    assert "pins=package-defaults" in out

    # A bank's run: the default pins leave the operator unpinned, so no posture...
    bank_path = _verify(tmp_path, "Example Bank")
    bank = cc.validate_report(json.loads(bank_path.read_text()))
    claims = _google_claims(bank, now, email="ci@bank.test")
    monkeypatch.setenv(cc.OIDC_ENV_VAR, _token(claims))
    bank_attested = tmp_path / "bank_attested.json"
    assert cli_mod.main(["attest", str(bank_path), "--output", str(bank_attested)]) == 0
    capsys.readouterr()
    assert cli_mod.main(["verify-report", str(bank_attested)]) == 2
    assert "Supply the parties with --parties" in capsys.readouterr().err

    # ...until the relying party pins the bank as the counterparty.
    pins = tmp_path / "parties.json"
    pins.write_text(
        json.dumps(
            {
                "schema_version": cc.PARTIES_SCHEMA_VERSION,
                "profiles": {
                    "trace-v1": {
                        "author": [f"github:{CAGE_REPO}"],
                        "counterparty": ["google:ci@bank.test"],
                    }
                },
            }
        )
    )
    argv = ["verify-report", str(bank_attested), "--parties", str(pins)]
    assert cli_mod.main(argv) == 0
    out = capsys.readouterr().out
    assert "posture=COUNTERPARTY_VERIFIED" in out and "pins=parties.json" in out


def test_cli_attest_needs_a_token_and_never_takes_one_on_the_command_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(cc.OIDC_ENV_VAR, raising=False)
    report_path = _verify(tmp_path, "Google LLC")
    out = tmp_path / "attested.json"
    capsys.readouterr()
    assert cli_mod.main(["attest", str(report_path), "--output", str(out)]) == 2
    assert cc.OIDC_ENV_VAR in capsys.readouterr().err
    assert not out.exists()
    with pytest.raises(SystemExit):
        cli_mod.main(["attest", str(report_path), "--output", str(out), "--token", "x"])


def test_checking_an_attestation_without_the_extra_fails_before_any_fetch(
    tmp_path: Path,
) -> None:
    """Standard library only: a clear error, and no JWKS request is ever made."""
    now = time.time()
    report = _report(timestamp=now)
    token = _token(_github_claims(report, now))
    attested = cc.attest(report, token, resolve=_Resolver(), now=now)
    path = tmp_path / "attested.json"
    path.write_text(json.dumps(attested.to_dict()), encoding="utf-8")
    site = tmp_path / "site"
    shutil.copytree(
        _PACKAGE_SRC / "cage_conformance",
        site / "cage_conformance",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    script = "\n".join(
        [
            "import sys, urllib.request",
            f"sys.path.insert(0, {str(site)!r})",
            "def offline(*args, **kwargs):",
            "    raise AssertionError('a JWKS fetch was attempted')",
            "urllib.request.urlopen = offline",
            "from cage_conformance.cli import main",
            f"raise SystemExit(main(['verify-report', {str(path)!r}]))",
        ]
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-I", "-S", "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "'attest' extra" in proc.stderr
