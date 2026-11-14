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

"""Tests for Provider02CERResolver.

Verification invariants:
  1. 200 + ETag (wrapped resolution envelope or bare governed CER) →
     resolved=True, status=UNVERIFIED (never VERIFIED), signature_checked=False
  2. 304 revalidation → re-verifies cached entry, from_cache=True
  3. 404 → STALE, finding message says "unresolvable" (never "absent"/"invalid")
  4. 400 INVALID_HASH_FORMAT → CER_MALFORMED_REF
  5. Timeout / 5xx / transport → ENDPOINT_ERROR, retryable=True
  6. Tampered bundle.evidence or mismatched outer/inner certificateHash →
     CER_DIGEST_MISMATCH, resolved=False
  7. Non-governed CER bundleType (e.g. cer.ai.execution.v1) →
     CER_UNSUPPORTED_BUNDLE_TYPE, resolved=False
  8. Untyped JSON object without bundleType → CER_MALFORMED_REF (even if raw
     HTTP bytes match the requested SHA-256 digest)
  9. UUID in hash position / COMMITMENT-kind / malformed string →
     rejected with zero network requests
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import httpx
import pytest
import respx

from src.gateway.governance.content_address import ContentAddress, ContentAddressKind
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.attestation import AttestationStatus
from src.integrations.provider_02.governed_cer import seal_governed_execution
from src.integrations.provider_02.resolver import Provider02CERResolver

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _build_governed_cer() -> dict[str, Any]:
    """Seal a deterministic governed-execution CER using CAGE's wire sealer."""
    bundle = {
        "bundleId": "7e05f9a5-6b9d-4e81-be20-f90d9c5dc713",
        "threadId": "resolver-unit-test",
        "startedAt": "2026-10-06T20:53:26Z",
        "completedAt": "2026-10-06T20:53:27Z",
        "terminalPath": "happy_path",
        "steps": [
            {
                "stepId": "5288c3a3-36f4-4212-b191-a01d7fed953e",
                "nodeName": "safety_check",
                "parentStepIds": [],
                "timestampUtc": "2026-10-06T20:53:26.500Z",
                "durationMs": 1.0,
                "stateHash": "ce0d0bdeba8ef5154a27c4b2f6dc8e9a843562033e77c26a332e7d33678a005b",
                "signals": {"safetyStatus": "APPROVED", "score": 1.0},
                "metadata": {
                    "stateHashAlg": "sha256",
                    "stateHashCanon": "RFC8785-JCS",
                    "stateHashScope": "agentstate-pii-sanitized/v1",
                },
            }
        ],
    }
    return seal_governed_execution(bundle)


def _wrap_resolution_envelope(
    cer: dict[str, Any], address: ContentAddress
) -> dict[str, Any]:
    """Wrap a CER in the live GET /v1/resolve/cer/:certificateHash envelope shape."""
    cert_canonical = jcs_canonicalize_plan(
        {k: v for k, v in cer.items() if k != "certificateHash"}
    ).decode("utf-8")
    return {
        "ok": True,
        "schemaVersion": "1.0",
        "artifactType": "cer",
        "certificateHash": cer["certificateHash"],
        "bundle": copy.deepcopy(cer),
        "canonical": {
            "certificate": {
                "payload": cert_canonical,
                "hashAlgorithm": "sha256",
                "canonicalization": "jcs",
                "matchesCertificateHash": True,
            }
        },
        "links": {
            "self": (
                "https://resolver.provider02.example.com/v1/resolve/cer/"
                f"{address.url_encoded}"
            ),
            "keyManifest": (
                "https://keys.provider02.example.com/.well-known/provider02-jwks.json"
            ),
            "verify": (
                f"https://verify.provider02.example.com/cer/{address.hex_digest}"
            ),
            "humanVerifier": (
                f"https://verify.provider02.example.com/ui/cer/{address.url_encoded}"
            ),
        },
        "anchors": [
            {"logId": "transparency-log-001", "timestamp": "2026-10-06T20:53:28Z"}
        ],
        "timestamps": [{"tsa": "rfc3161-tsa", "value": "opaque-timestamp-data"}],
    }


@pytest.fixture
def resolver() -> Provider02CERResolver:
    """Fixture providing a CER resolver instance."""
    return Provider02CERResolver(
        base_url="https://resolver.provider02.example.com",
        timeout=5.0,
    )


@pytest.fixture
def sealed_cer() -> dict[str, Any]:
    """Deterministic sealed cer.governed.execution.v1 certificate."""
    return _build_governed_cer()


@pytest.fixture
def valid_address(sealed_cer: dict[str, Any]) -> ContentAddress:
    """ContentAddress matching sealed_cer['certificateHash']."""
    return ContentAddress.parse(sealed_cer["certificateHash"])


@pytest.fixture
def wrapped_envelope(
    sealed_cer: dict[str, Any], valid_address: ContentAddress
) -> dict[str, Any]:
    """Wrapped /v1/resolve/cer/:certificateHash resolution envelope."""
    return _wrap_resolution_envelope(sealed_cer, valid_address)


class TestSuccessfulResolution:
    """Tests for successful CER resolution with 200 OK and 304 caching."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_200_wrapped_envelope_returns_unverified_never_verified(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
    ) -> None:
        """Wrapped /v1/resolve/cer/:hash envelope resolves via inner governed CER JCS digest.

        Pretty-printed JSON ensures raw HTTP wrapper bytes do NOT hash to
        valid_address.hex_digest, proving inner CER extraction + JCS hashing.
        """
        pretty_bytes = json.dumps(wrapped_envelope, indent=2).encode("utf-8")
        assert hashlib.sha256(pretty_bytes).hexdigest() != valid_address.hex_digest

        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=pretty_bytes,
                headers={"ETag": '"abc123"', "Content-Type": "application/json"},
            )
        )

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.status == AttestationStatus.UNVERIFIED.value
        assert result.status != AttestationStatus.VERIFIED.value
        assert result.resolved is True
        assert result.signature_checked is False
        assert result.etag == '"abc123"'
        assert result.from_cache is False
        assert result.evidence == wrapped_envelope
        assert result.links == wrapped_envelope["links"]
        assert result.anchors == wrapped_envelope["anchors"]
        assert result.timestamps == wrapped_envelope["timestamps"]
        assert result.findings == []

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_200_bare_governed_cer_resolves_unverified(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        sealed_cer: dict[str, Any],
    ) -> None:
        """Direct cer.governed.execution.v1 JSON object without outer wrapper resolves."""
        pretty_bytes = json.dumps(sealed_cer, indent=2).encode("utf-8")
        assert hashlib.sha256(pretty_bytes).hexdigest() != valid_address.hex_digest

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=pretty_bytes,
                headers={"Content-Type": "application/json"},
            )
        )

        result = await resolver.resolve(valid_address)

        assert result.resolved is True
        assert result.status == AttestationStatus.UNVERIFIED.value
        assert result.signature_checked is False
        assert result.evidence == sealed_cer
        assert result.etag == ""
        assert valid_address.canonical not in resolver._cache

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_accepts_bare_hex_certificate_hash_and_omitted_inner_hash(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
    ) -> None:
        """Outer bare 64-hex certificateHash and omitted inner certificateHash verify cleanly."""
        envelope = copy.deepcopy(wrapped_envelope)
        envelope["certificateHash"] = valid_address.hex_digest
        envelope["bundle"].pop("certificateHash")

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(200, json=envelope))

        result = await resolver.resolve(valid_address)
        assert result.resolved is True
        assert result.status == AttestationStatus.UNVERIFIED.value
        assert result.signature_checked is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_etag_caching_and_304_revalidation(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
    ) -> None:
        """Second request with matching ETag returns re-verified cached data with from_cache=True."""
        route_200 = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                json=wrapped_envelope,
                headers={"ETag": '"cache-key-001"', "Content-Type": "application/json"},
            )
        )

        result1 = await resolver.resolve(valid_address)
        assert route_200.called
        assert result1.resolved is True
        assert result1.from_cache is False
        assert result1.etag == '"cache-key-001"'

        route_304 = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(304))

        result2 = await resolver.resolve(valid_address)
        assert route_304.called
        assert (
            route_304.calls.last.request.headers.get("If-None-Match")
            == '"cache-key-001"'
        )
        assert result2.resolved is True
        assert result2.from_cache is True
        assert result2.signature_checked is False
        assert result2.etag == '"cache-key-001"'
        assert result2.evidence == wrapped_envelope
        assert result2.status == AttestationStatus.UNVERIFIED.value

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_etag_304_re_verifies_and_evicts_mutated_cache_entry(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
    ) -> None:
        """304 cache hit re-verifies inner CER JCS digest and evicts tampered cache entries."""
        url = f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        respx.get(url).mock(
            side_effect=[
                httpx.Response(
                    200, json=wrapped_envelope, headers={"ETag": '"etag-v1"'}
                ),
                httpx.Response(304),
            ]
        )

        first = await resolver.resolve(valid_address)
        assert first.resolved is True

        # Mutate cached inner CER evidence in memory before 304 revalidation
        resolver._cache[valid_address.canonical].body["bundle"]["evidence"]["bundle"][
            "terminalPath"
        ] = "tampered_in_memory"

        second = await resolver.resolve(valid_address)
        assert second.resolved is False
        assert second.status == AttestationStatus.ERROR.value
        assert second.findings[0]["code"] == "CER_DIGEST_MISMATCH"
        assert valid_address.canonical not in resolver._cache

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_accepts_string_address(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
    ) -> None:
        """Resolver accepts string addresses and parses before network call."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                json=wrapped_envelope,
                headers={"ETag": '"test-etag"', "Content-Type": "application/json"},
            )
        )

        result = await resolver.resolve(valid_address.canonical)

        assert route.called
        assert result.resolved is True
        assert result.status == AttestationStatus.UNVERIFIED.value
        assert result.signature_checked is False

        await resolver.close()


class TestErrorHandling:
    """Tests for error conditions and fail-closed semantics."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_404_maps_to_stale_with_unresolvable_message(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """404 response maps to STALE with 'unresolvable' message."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(404))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.STALE.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_UNRESOLVABLE"
        assert result.findings[0]["retryable"] is False

        message = result.findings[0]["message"].lower()
        assert "unresolvable" in message
        assert "absent" not in message
        assert "invalid" not in message
        assert "missing" not in message

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_400_invalid_hash_format(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """400 INVALID_HASH_FORMAT maps to CER_MALFORMED_REF."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(400, text="INVALID_HASH_FORMAT"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_unsolicited_304_without_cache_returns_endpoint_error(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """Unsolicited 304 on cold cache fails closed as ENDPOINT_ERROR."""
        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(304))

        result = await resolver.resolve(valid_address)
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["retryable"] is True

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_endpoint_error_retryable(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """Timeout maps to ENDPOINT_ERROR with retryable=True."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(side_effect=httpx.TimeoutException("Connection timeout"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["retryable"] is True

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_5xx_server_error_retryable(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """5xx server errors map to ENDPOINT_ERROR with retryable=True."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(503, text="Service Unavailable"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["retryable"] is True

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_transport_error_retryable(
        self, resolver: Provider02CERResolver, valid_address: ContentAddress
    ) -> None:
        """Transport errors map to ENDPOINT_ERROR with retryable=True."""
        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(side_effect=httpx.TransportError("Connection reset"))

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["retryable"] is True

        await resolver.close()


class TestDigestAndBundleTypeVerification:
    """Tests for inner CER extraction, JCS digest binding, and bundleType checks."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_tampered_bundle_evidence_fails_digest_mismatch(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
    ) -> None:
        """Tampering inside bundle.evidence fails closed with CER_DIGEST_MISMATCH."""
        tampered = copy.deepcopy(wrapped_envelope)
        tampered["bundle"]["evidence"]["bundle"]["terminalPath"] = "forged_path"

        route = respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                json=tampered,
                headers={"ETag": '"mismatch-test"'},
            )
        )

        result = await resolver.resolve(valid_address)

        assert route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_DIGEST_MISMATCH"
        assert result.findings[0]["retryable"] is False
        assert "mismatch" in result.findings[0]["message"].lower()
        assert valid_address.canonical not in resolver._cache

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_outer_hash",
        ["sha256:" + "0" * 64, "f" * 64, 12345, None],
    )
    async def test_mismatched_outer_certificate_hash_fails_digest_mismatch(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
        bad_outer_hash: Any,
    ) -> None:
        """Mismatched outer resolution-envelope certificateHash fails CER_DIGEST_MISMATCH."""
        tampered = copy.deepcopy(wrapped_envelope)
        tampered["certificateHash"] = bad_outer_hash

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(200, json=tampered))

        result = await resolver.resolve(valid_address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "CER_DIGEST_MISMATCH"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_inner_hash",
        ["sha256:" + "0" * 64, "b" * 64, None],
    )
    async def test_mismatched_inner_certificate_hash_fails_digest_mismatch(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        sealed_cer: dict[str, Any],
        bad_inner_hash: Any,
    ) -> None:
        """Mismatched inner CER certificateHash fails CER_DIGEST_MISMATCH even when JCS matches."""
        tampered_cer = copy.deepcopy(sealed_cer)
        tampered_cer["certificateHash"] = bad_inner_hash

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(200, json=tampered_cer))

        result = await resolver.resolve(valid_address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "CER_DIGEST_MISMATCH"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_envelope_ok_false_fails_closed(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
    ) -> None:
        """Wrapped resolution envelope with ok != True fails closed."""
        not_ok = copy.deepcopy(wrapped_envelope)
        not_ok["ok"] = False

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(return_value=httpx.Response(200, json=not_ok))

        result = await resolver.resolve(valid_address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("wrapped", [True, False])
    @pytest.mark.parametrize(
        "bundle_type", ["cer.ai.execution.v1", "cer.unknown.v1", ""]
    )
    async def test_unsupported_bundle_type_fails_closed(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        wrapped_envelope: dict[str, Any],
        sealed_cer: dict[str, Any],
        wrapped: bool,
        bundle_type: str,
    ) -> None:
        """Non-governed CER bundle types (e.g. cer.ai.execution.v1) fail closed with CER_UNSUPPORTED_BUNDLE_TYPE."""
        if wrapped:
            payload: dict[str, Any] = copy.deepcopy(wrapped_envelope)
            payload["bundle"]["bundleType"] = bundle_type
        else:
            payload = copy.deepcopy(sealed_cer)
            payload["bundleType"] = bundle_type

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200, json=payload, headers={"ETag": '"unsupported-etag"'}
            )
        )

        result = await resolver.resolve(valid_address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_UNSUPPORTED_BUNDLE_TYPE"
        assert result.findings[0]["retryable"] is False
        assert valid_address.canonical not in resolver._cache

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_untyped_payload_rejected_even_when_raw_bytes_match_digest(
        self, resolver: Provider02CERResolver
    ) -> None:
        """Generic JSON dict without bundleType fails closed even if raw HTTP bytes hash to address."""
        untyped_body = {"version": "1.0", "decision": {"allowed": True}}
        raw_bytes = json.dumps(untyped_body, separators=(",", ":")).encode("utf-8")
        raw_digest = hashlib.sha256(raw_bytes).hexdigest()
        address = ContentAddress.parse(f"sha256:{raw_digest}")

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=raw_bytes,
                headers={"Content-Type": "application/json"},
            )
        )

        result = await resolver.resolve(address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.parametrize("raw_content", [b"[1, 2, 3]", b"{invalid-json"])
    async def test_non_object_or_invalid_json_fails_closed(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        raw_content: bytes,
    ) -> None:
        """Non-dict JSON payloads and invalid JSON fail closed with CER_MALFORMED_REF."""
        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=raw_content,
                headers={"Content-Type": "application/json"},
            )
        )

        result = await resolver.resolve(valid_address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_jcs_nan_float_fails_closed(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        sealed_cer: dict[str, Any],
    ) -> None:
        """Non-JCS-canonicalizable NaN values fail closed as CER_MALFORMED_REF."""
        cer_with_nan = copy.deepcopy(sealed_cer)
        cer_with_nan["evidence"]["nanValue"] = float("nan")
        nan_bytes = json.dumps(cer_with_nan, allow_nan=True).encode("utf-8")

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{valid_address.url_encoded}"
        ).mock(
            return_value=httpx.Response(
                200,
                content=nan_bytes,
                headers={"Content-Type": "application/json"},
            )
        )

        result = await resolver.resolve(valid_address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_sha256_address_fails_digest_mismatch(
        self,
        resolver: Provider02CERResolver,
        valid_address: ContentAddress,
        sealed_cer: dict[str, Any],
    ) -> None:
        """Non-sha256 ContentAddress cannot match sha256 governed CER digest even if hex_digest collides."""
        cer_without_inner_hash = {
            k: v for k, v in sealed_cer.items() if k != "certificateHash"
        }
        wrong_alg_address = ContentAddress(
            algorithm="sha512",
            hex_digest=valid_address.hex_digest,
            kind=ContentAddressKind.DIGEST,
        )

        respx.get(
            f"https://resolver.provider02.example.com/v1/resolve/cer/{wrong_alg_address.url_encoded}"
        ).mock(return_value=httpx.Response(200, json=cer_without_inner_hash))

        result = await resolver.resolve(wrong_alg_address)

        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert result.findings[0]["code"] == "CER_DIGEST_MISMATCH"
        assert result.findings[0]["retryable"] is False

        await resolver.close()


class TestFailClosedBoundaries:
    """Tests for fail-closed rejection of invalid inputs."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_uuid_in_hash_position_rejected_zero_requests(
        self, resolver: Provider02CERResolver
    ) -> None:
        """UUID in digest position is rejected before any network call."""
        uuid_string = "sha256:550e8400-e29b-41d4-a716-446655440000"

        route = respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={})
        )

        result = await resolver.resolve(uuid_string)

        assert not route.called
        assert route.call_count == 0
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_commitment_kind_rejected_zero_requests(
        self, resolver: Provider02CERResolver
    ) -> None:
        """COMMITMENT-kind addresses are rejected before any network call."""
        commitment = ContentAddress(
            algorithm="hmac-sha256",
            hex_digest="a" * 64,
            kind=ContentAddressKind.COMMITMENT,
        )

        route = respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={})
        )

        result = await resolver.resolve(commitment)

        assert not route.called
        assert route.call_count == 0
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False
        assert "COMMITMENT" in result.findings[0]["message"]
        assert "not dereferenceable" in result.findings[0]["message"]

        await resolver.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_malformed_string_rejected_before_network(
        self, resolver: Provider02CERResolver
    ) -> None:
        """Malformed string addresses are rejected before any network call."""
        malformed = "not-a-valid-address"

        route = respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={})
        )

        result = await resolver.resolve(malformed)

        assert not route.called
        assert result.resolved is False
        assert result.status == AttestationStatus.ERROR.value
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CER_MALFORMED_REF"
        assert result.findings[0]["retryable"] is False

        await resolver.close()
