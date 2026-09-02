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

"""Falsification tests for the D1-class audit findings.

See plans/d1_class_audit.md. The defect class:

    A field inside an untrusted document determines whether, or how strictly,
    that document is validated.

Each test here was written **before** its fix and observed failing against the
unfixed code. That ordering is the point: a guard that has never been seen
failing has not been shown to guard anything. Two earlier mutations in this
repository (M1, M-B) were recorded as passing against code that could not have
failed them, which is what this discipline exists to prevent.

Findings covered:

  A  envelope ``expires_at`` was never checked -> indefinite replay
  B  ``_envelope_from_dict`` defaulted absent security fields -> silent
     normalisation of "missing" into "as expected"
  C  ``signature.algorithm`` was parsed from the untrusted document and never
     compared against the key actually used
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def ec_key_pair():
    """EC P-256 keypair for signing test envelopes."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


@pytest.fixture
def governance_result():
    return {"verdict": "APPROVED", "confidence": 0.95}


@pytest.fixture
def params():
    return {"symbol": "AAPL", "amount": 1000.0}


def _sign(builder, envelope, private_key, public_pem, algorithm="ES256"):
    """Attach a genuine signature so tests exercise the real verify path."""
    from src.gateway.governance.jwks import pem_to_jwk

    digest = envelope.compute_digest()
    signature = private_key.sign(
        digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
    )
    kid = pem_to_jwk(public_pem)["kid"]
    return builder.attach_signature(envelope, signature, kid, algorithm)


def _jwks_for(public_pem):
    from src.gateway.governance.jwks import JWKSet

    jwks = JWKSet()
    jwks.add_key(public_pem)
    return jwks


# ---------------------------------------------------------------------------
# Finding A — expiry must be enforced
# ---------------------------------------------------------------------------


class TestFindingAEnvelopeExpiry:
    """A governance envelope is a bearer credential. Its TTL must be real."""

    def test_expired_envelope_is_rejected(
        self, ec_key_pair, governance_result, params
    ):
        """An envelope past ``expires_at`` must fail verification.

        Before the fix, ``verify()`` checked the signature and nothing else, so
        a captured envelope replayed indefinitely. The signature stays valid
        forever by design — only the temporal check bounds it.
        """
        from unittest.mock import patch

        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        private_key, public_pem = ec_key_pair

        # TTL of 1 second, then wait past it.
        builder = GovernanceEnvelopeBuilder(ttl_s=1)
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        )
        signed = _sign(builder, envelope, private_key, public_pem)

        time.sleep(1.5)

        with patch(
            "src.gateway.governance.jwks.get_jwks",
            return_value=_jwks_for(public_pem),
        ):
            result = builder.verify(signed)

        assert result is False, (
            "Expired envelope verified successfully. The signature is valid "
            "indefinitely by construction, so without a temporal check any "
            "captured envelope can be replayed forever."
        )

    def test_unexpired_envelope_still_verifies(
        self, ec_key_pair, governance_result, params
    ):
        """The expiry check must not reject envelopes inside their window.

        Guards against the trivial non-fix of always returning False, which
        would satisfy the test above while breaking the control entirely.
        """
        from unittest.mock import patch

        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        private_key, public_pem = ec_key_pair

        builder = GovernanceEnvelopeBuilder(ttl_s=300)
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        )
        signed = _sign(builder, envelope, private_key, public_pem)

        with patch(
            "src.gateway.governance.jwks.get_jwks",
            return_value=_jwks_for(public_pem),
        ):
            assert builder.verify(signed) is True

    def test_expiry_checked_before_signature(
        self, ec_key_pair, governance_result, params
    ):
        """Expiry must be evaluated before the crypto, not after.

        Cheap checks precede expensive ones, and an expired envelope should
        report expiry rather than burning a signature verification.

        **Why this is asserted with a call counter rather than an exception.**
        The obvious approach — make ``get_jwks`` raise and assert the raise is
        never seen — is *unfalsifiable here*: ``verify()`` wraps its whole body
        in ``try/except`` and returns ``False`` on any exception, so the
        sentinel AssertionError is swallowed and reported as the expected
        rejection. Verified empirically: that formulation passes against the
        unfixed code, which makes it worthless as evidence.

        Counting calls instead cannot be absorbed by the exception handler.
        """
        from unittest.mock import patch

        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        private_key, public_pem = ec_key_pair

        builder = GovernanceEnvelopeBuilder(ttl_s=1)
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        )
        signed = _sign(builder, envelope, private_key, public_pem)

        time.sleep(1.5)

        calls: list[str] = []
        real_jwks = _jwks_for(public_pem)

        def _counting_get_jwks():
            calls.append("get_jwks")
            return real_jwks

        with patch(
            "src.gateway.governance.jwks.get_jwks", side_effect=_counting_get_jwks
        ):
            result = builder.verify(signed)

        assert result is False
        assert calls == [], (
            "Key resolution ran for an already-expired envelope. The temporal "
            "check must short-circuit before any crypto work is performed."
        )


# ---------------------------------------------------------------------------
# Finding B — absent security fields must be rejected, not defaulted
# ---------------------------------------------------------------------------


class TestFindingBParserDefaults:
    """Absence must not be normalised into assertion."""

    def test_empty_dict_is_rejected(self):
        """Parsing ``{}`` must raise, not yield a plausible-looking envelope.

        Before the fix this returned a well-formed envelope claiming the
        current version and the *local* deployment region — values the input
        never contained.
        """
        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()

        with pytest.raises((ValueError, KeyError)):
            builder._envelope_from_dict({})

    def test_absent_deployment_region_is_rejected(
        self, governance_result, params
    ):
        """A missing region must not be silently relabelled as local.

        The sharpest case: an envelope issued under one regulatory region,
        parsed under another, would be relabelled to the parsing region before
        any region guard sees it.
        """
        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()
        data = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        ).to_dict()

        del data["governance_context"]["deployment_region"]

        with pytest.raises((ValueError, KeyError)):
            builder._envelope_from_dict(data)

    def test_absent_expires_at_is_rejected(self, governance_result, params):
        """A missing expiry must not parse as an envelope with no expiry.

        Directly compounds Finding A: if absence yields "", any expiry check
        must not read that as "never expires".
        """
        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()
        data = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        ).to_dict()

        del data["expires_at"]

        with pytest.raises((ValueError, KeyError)):
            builder._envelope_from_dict(data)

    def test_absent_envelope_version_is_rejected(self, governance_result, params):
        """A missing version must not be relabelled as the current version."""
        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()
        data = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        ).to_dict()

        del data["envelope_version"]

        with pytest.raises((ValueError, KeyError)):
            builder._envelope_from_dict(data)

    def test_absent_optional_fields_still_parse(self, governance_result, params):
        """Genuinely optional fields must keep their defaults.

        ``to_dict()`` deliberately omits ``external_attestations`` when empty
        (pinned by test_envelope_to_dict_omits_empty_attestations), so a
        blanket "reject every missing key" rule would break the round-trip the
        tamper-detection tests depend on. The strictness must be targeted.
        """
        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        builder = GovernanceEnvelopeBuilder()
        data = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        ).to_dict()

        assert "external_attestations" not in data  # documents the precondition

        parsed = builder._envelope_from_dict(data)
        assert parsed.external_attestations == []


# ---------------------------------------------------------------------------
# Finding C — the claimed algorithm must agree with the key actually used
# ---------------------------------------------------------------------------


class TestFindingCAlgorithmClaim:
    """Read the claim, never trust it, use it only to detect disagreement."""

    def test_mismatched_algorithm_claim_is_rejected(
        self, ec_key_pair, governance_result, params
    ):
        """An envelope claiming RS256 but signed with an EC key must fail.

        Currently ``verify()`` dispatches on the resolved key type and ignores
        the claim, so this is correct-by-accident: the field is parsed from
        attacker-controlled input and sits one refactor away from becoming the
        dispatch input, which is textbook algorithm confusion.

        ConsequenceToken.verify() already implements the right pattern —
        compare the claim against the signer's algorithm and reject a mismatch.
        """
        from unittest.mock import patch

        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        private_key, public_pem = ec_key_pair

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        )
        # Genuine EC signature, but the envelope claims RSA.
        signed = _sign(
            builder, envelope, private_key, public_pem, algorithm="RS256"
        )

        with patch(
            "src.gateway.governance.jwks.get_jwks",
            return_value=_jwks_for(public_pem),
        ):
            result = builder.verify(signed)

        assert result is False, (
            "Envelope claiming RS256 while signed with an EC P-256 key "
            "verified successfully. The algorithm claim must be checked "
            "against the key actually used, or removed from the parse path."
        )

    def test_matching_algorithm_claim_still_verifies(
        self, ec_key_pair, governance_result, params
    ):
        """The mismatch check must not reject correctly-labelled envelopes."""
        from unittest.mock import patch

        from src.gateway.governance.governance_envelope import (
            GovernanceEnvelopeBuilder,
        )

        private_key, public_pem = ec_key_pair

        builder = GovernanceEnvelopeBuilder()
        envelope = builder.build_unsigned(
            action="execute_trade",
            params=params,
            governance_result=governance_result,
        )
        signed = _sign(
            builder, envelope, private_key, public_pem, algorithm="ES256"
        )

        with patch(
            "src.gateway.governance.jwks.get_jwks",
            return_value=_jwks_for(public_pem),
        ):
            assert builder.verify(signed) is True
