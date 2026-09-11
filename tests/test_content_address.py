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

"""Tests for vendor-neutral content addressing primitives."""

import pytest

from src.gateway.governance.content_address import (
    ContentAddress,
    ContentAddressKind,
    MalformedContentAddress,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestContentAddressRoundTrip:
    """Verify round-trip property: parse(x.canonical) == parse(x.url_encoded) == x."""

    def test_sha256_round_trip(self) -> None:
        """SHA-256 digest round-trips through canonical and URL-encoded forms."""
        digest = "a" * 64
        addr = ContentAddress(
            algorithm="sha256",
            hex_digest=digest,
            kind=ContentAddressKind.DIGEST,
        )

        canonical_parsed = ContentAddress.parse(addr.canonical)
        url_encoded_parsed = ContentAddress.parse(addr.url_encoded)

        assert canonical_parsed == addr
        assert url_encoded_parsed == addr
        assert canonical_parsed == url_encoded_parsed

    def test_sha384_round_trip(self) -> None:
        """SHA-384 digest round-trips through canonical and URL-encoded forms."""
        digest = "b" * 96
        addr = ContentAddress(
            algorithm="sha384",
            hex_digest=digest,
            kind=ContentAddressKind.DIGEST,
        )

        canonical_parsed = ContentAddress.parse(addr.canonical)
        url_encoded_parsed = ContentAddress.parse(addr.url_encoded)

        assert canonical_parsed == addr
        assert url_encoded_parsed == addr

    def test_sha512_round_trip(self) -> None:
        """SHA-512 digest round-trips through canonical and URL-encoded forms."""
        digest = "c" * 128
        addr = ContentAddress(
            algorithm="sha512",
            hex_digest=digest,
            kind=ContentAddressKind.DIGEST,
        )

        canonical_parsed = ContentAddress.parse(addr.canonical)
        url_encoded_parsed = ContentAddress.parse(addr.url_encoded)

        assert canonical_parsed == addr
        assert url_encoded_parsed == addr

    def test_hmac_sha256_round_trip(self) -> None:
        """HMAC-SHA-256 commitment round-trips through canonical and URL-encoded forms."""
        digest = "d" * 64
        addr = ContentAddress(
            algorithm="hmac-sha256",
            hex_digest=digest,
            kind=ContentAddressKind.COMMITMENT,
        )

        canonical_parsed = ContentAddress.parse(addr.canonical)
        url_encoded_parsed = ContentAddress.parse(addr.url_encoded)

        assert canonical_parsed == addr
        assert url_encoded_parsed == addr


class TestContentAddressKindDiscriminator:
    """Verify DIGEST vs COMMITMENT kind assignment."""

    def test_sha256_is_digest(self) -> None:
        """SHA-256 addresses are DIGEST kind."""
        addr = ContentAddress.parse("sha256:" + ("a" * 64))
        assert addr.kind == ContentAddressKind.DIGEST

    def test_sha384_is_digest(self) -> None:
        """SHA-384 addresses are DIGEST kind."""
        addr = ContentAddress.parse("sha384:" + ("b" * 96))
        assert addr.kind == ContentAddressKind.DIGEST

    def test_sha512_is_digest(self) -> None:
        """SHA-512 addresses are DIGEST kind."""
        addr = ContentAddress.parse("sha512:" + ("c" * 128))
        assert addr.kind == ContentAddressKind.DIGEST

    def test_hmac_sha256_is_commitment(self) -> None:
        """HMAC-SHA-256 addresses are COMMITMENT kind."""
        addr = ContentAddress.parse("hmac-sha256:" + ("d" * 64))
        assert addr.kind == ContentAddressKind.COMMITMENT


class TestContentAddressRejection:
    """Verify all malformed address rejection cases."""

    def test_missing_separator_rejected(self) -> None:
        """Missing colon separator raises MalformedContentAddress."""
        with pytest.raises(
            MalformedContentAddress, match="Missing separator in content address"
        ):
            ContentAddress.parse("sha256" + ("a" * 64))

    def test_unknown_algorithm_rejected(self) -> None:
        """Unknown algorithm raises MalformedContentAddress."""
        with pytest.raises(MalformedContentAddress, match="Unknown algorithm 'md5'"):
            ContentAddress.parse("md5:" + ("a" * 32))

    def test_non_hex_characters_rejected(self) -> None:
        """Non-hexadecimal characters raise MalformedContentAddress."""
        with pytest.raises(
            MalformedContentAddress, match="Non-hexadecimal characters in digest"
        ):
            ContentAddress.parse("sha256:" + ("z" * 64))

    def test_wrong_digest_length_rejected(self) -> None:
        """Wrong digest length for algorithm raises MalformedContentAddress."""
        with pytest.raises(
            MalformedContentAddress, match="Invalid digest length for sha256"
        ):
            ContentAddress.parse("sha256:" + ("a" * 32))  # Too short

    def test_uuid_in_digest_position_rejected(self) -> None:
        """UUID in digest position raises MalformedContentAddress."""
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        with pytest.raises(
            MalformedContentAddress, match="UUID detected in digest position"
        ):
            ContentAddress.parse(f"sha256:{uuid_str}")

    def test_correct_length_wrong_algorithm_rejected(self) -> None:
        """64-char hex declared as sha384 (expects 96) is rejected."""
        with pytest.raises(
            MalformedContentAddress, match="Invalid digest length for sha384"
        ):
            ContentAddress.parse("sha384:" + ("a" * 64))


class TestContentAddressNormalization:
    """Verify hex normalization and case-insensitive comparison."""

    def test_uppercase_hex_normalized_to_lowercase(self) -> None:
        """Uppercase hex input normalizes to lowercase."""
        upper = ContentAddress.parse("sha256:" + ("A" * 64))
        lower = ContentAddress.parse("sha256:" + ("a" * 64))

        assert upper == lower
        assert upper.hex_digest == "a" * 64
        assert lower.hex_digest == "a" * 64

    def test_mixed_case_hex_normalized(self) -> None:
        """Mixed-case hex input normalizes to lowercase."""
        mixed = ContentAddress.parse("sha256:AbCdEf" + ("0" * 58))
        expected_digest = "abcdef" + ("0" * 58)

        assert mixed.hex_digest == expected_digest

    def test_uppercase_algorithm_normalized(self) -> None:
        """Uppercase algorithm name is normalized to lowercase."""
        addr = ContentAddress.parse("SHA256:" + ("a" * 64))
        assert addr.algorithm == "sha256"


class TestContentAddressFormatProperties:
    """Verify canonical and URL-encoded format properties."""

    def test_canonical_format(self) -> None:
        """Canonical format uses colon separator."""
        digest = "a" * 64
        addr = ContentAddress(
            algorithm="sha256",
            hex_digest=digest,
            kind=ContentAddressKind.DIGEST,
        )

        assert addr.canonical == f"sha256:{digest}"

    def test_url_encoded_format(self) -> None:
        """URL-encoded format uses %3A for colon."""
        digest = "a" * 64
        addr = ContentAddress(
            algorithm="sha256",
            hex_digest=digest,
            kind=ContentAddressKind.DIGEST,
        )

        assert addr.url_encoded == f"sha256%3A{digest}"

    def test_parse_url_encoded_input(self) -> None:
        """Parser accepts URL-encoded input."""
        digest = "a" * 64
        addr = ContentAddress.parse(f"sha256%3A{digest}")

        assert addr.algorithm == "sha256"
        assert addr.hex_digest == digest


class TestContentAddressImmutability:
    """Verify ContentAddress is immutable (frozen dataclass)."""

    def test_cannot_modify_algorithm(self) -> None:
        """Cannot modify algorithm after construction."""
        addr = ContentAddress.parse("sha256:" + ("a" * 64))

        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            addr.algorithm = "sha384"  # type: ignore[misc]

    def test_cannot_modify_hex_digest(self) -> None:
        """Cannot modify hex_digest after construction."""
        addr = ContentAddress.parse("sha256:" + ("a" * 64))

        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            addr.hex_digest = "b" * 64  # type: ignore[misc]

    def test_cannot_modify_kind(self) -> None:
        """Cannot modify kind after construction."""
        addr = ContentAddress.parse("sha256:" + ("a" * 64))

        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            addr.kind = ContentAddressKind.COMMITMENT  # type: ignore[misc]
