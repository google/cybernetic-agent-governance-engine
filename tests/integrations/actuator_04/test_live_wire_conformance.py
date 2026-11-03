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

"""Tier 1 (Feature Coverage) and Tier 2 (Boundary & Corner Cases) Over-The-Wire Tests.

Tests all 6 CAGE substrate endpoints over real OS TCP loopback sockets against a live
running killswitch-server instance. Adheres to the Zero-Mock mandate.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.integrations.actuator_04.constants import (
    ATTESTATION_RECEIPT_DOMAIN_TAG,
    HEADER_CORRELATION_ID,
    HEADER_ENVELOPE_DIGEST,
    HEADER_QUARANTINE_ASSERTION,
    HEADER_QUARANTINE_RELEASE,
    HEADER_SIGNER_KID,
    NORMATIVE_VALIDATION_DOMAIN_TAG,
    QUARANTINE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RECEIPT_DOMAIN_TAG,
    QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG,
)

pytestmark = [pytest.mark.live_external]

CONFORMAL_BASELINE_DOMAIN_TAG: bytes = b"CAGE_CONFORMAL_BASELINE_V1:"


def _get_server_pub_key(base_url: str) -> tuple[ed25519.Ed25519PublicKey, str]:
    """Retrieve and construct Ed25519 verifying key from live /.well-known/jwks.json."""
    with httpx.Client(timeout=2.0) as client:
        r = client.get(f"{base_url}/.well-known/jwks.json")
        assert r.status_code == 200
        data = r.json()
        key_entry = data["keys"][0]
        x_b64 = key_entry["x"]
        padding = "=" * ((4 - len(x_b64) % 4) % 4)
        raw_pub = base64.urlsafe_b64decode(x_b64 + padding)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
        return pub_key, key_entry["kid"]


def _verify_server_receipt(
    resp_body: dict[str, Any],
    domain_tag: bytes,
    server_pub_key: ed25519.Ed25519PublicKey,
) -> None:
    """Verify detached Ed25519 signature returned by server in receipt."""
    assert "signature" in resp_body, "Receipt must contain detached signature"
    sig_b64 = resp_body["signature"]
    padding = "=" * ((4 - len(sig_b64) % 4) % 4)
    sig_bytes = base64.urlsafe_b64decode(sig_b64 + padding)
    assert len(sig_bytes) == 64, f"Signature length must be 64, got {len(sig_bytes)}"

    unsigned = {k: v for k, v in resp_body.items() if k != "signature"}
    canonical = jcs_canonicalize_plan(unsigned)
    preimage = domain_tag + canonical
    server_pub_key.verify(sig_bytes, preimage)


def _build_quarantine_payload(
    workload_id: str = "spiffe://cage.local/ns/default/sa/agent-alpha",
    target_pid: int | None = 12345,
    rule_id: str = "RULE-SC-7-CBF-LETHAL",
    trigger_reason: str = "Lethal barrier breach",
    nonce: str | None = None,
) -> tuple[bytes, dict[str, str], str]:
    """Build canonical body, headers, and envelope digest for quarantine directive."""
    n = nonce or str(uuid.uuid4())
    payload = {
        "workload_id": workload_id,
        "source_rule_id": rule_id,
        "trigger_reason": trigger_reason,
        "enforcement_plane": "HOST_OS_KERNEL",
        "refusal_proof_hash": hashlib.sha256(b"refusal_proof_seed").hexdigest(),
        "nonce": n,
        "timestamp_utc": "2026-11-03T05:00:00Z",
    }
    if target_pid is not None:
        payload["target_pid"] = target_pid

    canonical = jcs_canonicalize_plan(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    return canonical, payload, digest


def _build_release_payload(
    workload_id: str = "spiffe://cage.local/ns/default/sa/agent-alpha",
    quorum_count: int = 2,
    digest: str | None = None,
    nonce: str | None = None,
) -> tuple[bytes, dict[str, Any], str]:
    """Build canonical body, headers, and envelope digest for release directive."""
    n = nonce or str(uuid.uuid4())
    q_digest = digest or hashlib.sha256(b"operator_multi_signatures_quorum").hexdigest()
    payload = {
        "workload_id": workload_id,
        "quorum_approval_digest": q_digest,
        "quorum_count": quorum_count,
        "nonce": n,
        "timestamp_utc": "2026-11-03T05:10:00Z",
    }
    canonical = jcs_canonicalize_plan(payload)
    env_digest = hashlib.sha256(canonical).hexdigest()
    return canonical, payload, env_digest


# ==============================================================================
# Tier 1: Feature Coverage (30 Test Cases, 5 Per Endpoint)
# ==============================================================================


def test_t1_1_1_jwks_fetch_loopback(killswitch_server_harness: dict[str, Any]) -> None:
    """T1.1.1: Live JWKS fetch over loopback socket returns HTTP 200 with keys array."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/.well-known/jwks.json")
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")
    data = resp.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1


def test_t1_1_2_jwks_rfc8037_conformance(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.1.2: JWKS strictly conforms to RFC 8037 parameters (kty=OKP, crv=Ed25519)."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/.well-known/jwks.json")
    key = resp.json()["keys"][0]
    assert key.get("kty") == "OKP"
    assert key.get("crv") == "Ed25519"
    assert key.get("use") == "sig"
    assert key.get("alg") == "EdDSA"


def test_t1_1_3_jwks_kid_derivation_integrity(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.1.3: Substrate kid is exactly 64-hex SHA-256 of the unpadded raw public key bytes."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/.well-known/jwks.json")
    key = resp.json()["keys"][0]
    kid = key["kid"]
    assert len(kid) == 64
    x_b64 = key["x"]
    padding = "=" * ((4 - len(x_b64) % 4) % 4)
    raw_pub = base64.urlsafe_b64decode(x_b64 + padding)
    expected_kid = hashlib.sha256(raw_pub).hexdigest()
    assert kid == expected_kid


def test_t1_1_4_jwks_public_key_length_and_format(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.1.4: Parameter x decodes to exactly 32 raw bytes of valid Ed25519 public key."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/.well-known/jwks.json")
    key = resp.json()["keys"][0]
    x_b64 = key["x"]
    padding = "=" * ((4 - len(x_b64) % 4) % 4)
    raw_pub = base64.urlsafe_b64decode(x_b64 + padding)
    assert len(raw_pub) == 32
    # Verify instantiable by cryptography library
    ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)


def test_t1_1_5_jwks_public_key_cryptographic_verification(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.1.5: VerifyingKey can verify cryptographic signatures emitted by the substrate."""
    base_url = killswitch_server_harness["base_url"]
    pub_key, _kid = _get_server_pub_key(base_url)
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/attest")
    assert resp.status_code == 200
    _verify_server_receipt(resp.json(), ATTESTATION_RECEIPT_DOMAIN_TAG, pub_key)


def test_t1_2_1_quarantine_workload_level(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.2.1: Workload-level quarantine directive succeeds over physical loopback."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _payload, env_digest = _build_quarantine_payload(target_pid=None)

    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: env_digest,
    }

    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "QUARANTINED"
    assert body["quarantined"] is True
    assert body["enforcement_plane"] == "HOST_OS_KERNEL"


def test_t1_2_2_quarantine_target_pid_freeze(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.2.2: Process PID targeted freeze records target_pid in receipt."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _payload, env_digest = _build_quarantine_payload(target_pid=4242)

    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: env_digest,
    }

    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_pid"] == 4242


def test_t1_2_3_quarantine_receipt_signature_verification(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.2.3: Quarantine receipt contains valid detached Ed25519 signature over JCS body."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    pub_key, _ = _get_server_pub_key(base_url)
    canonical, _payload, env_digest = _build_quarantine_payload()

    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: env_digest,
    }

    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 200
    _verify_server_receipt(resp.json(), QUARANTINE_RECEIPT_DOMAIN_TAG, pub_key)


def test_t1_2_4_quarantine_envelope_digest_binding(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.2.4: Receipt envelope_digest matches sha256(JCS(request_body))."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _payload, env_digest = _build_quarantine_payload()

    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: env_digest,
    }

    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["envelope_digest"] == env_digest


def test_t1_2_5_quarantine_rule_and_reason_propagation(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.2.5: Custom rule_id is accurately bound to receipt."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _payload, env_digest = _build_quarantine_payload(
        rule_id="RULE-CUSTOM-LETHAL-99"
    )

    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: env_digest,
    }

    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == "RULE-CUSTOM-LETHAL-99"


def test_t1_3_1_attest_probe(killswitch_server_harness: dict[str, Any]) -> None:
    """T1.3.1: Hardware TPM attestation probe returns HTTP 200 with HOST_TPM_PCR."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/attest")
    assert resp.status_code == 200
    body = resp.json()
    assert body["attestation_type"] == "HOST_TPM_PCR"


def test_t1_3_2_attest_pcr_measurements(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.3.2: PCR measurement map contains keys 0, 1, 7 as 64-char hex SHA-256 strings."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/attest")
    pcr_map = resp.json()["pcr_values"]
    for idx in ("0", "1", "7"):
        assert idx in pcr_map
        assert len(pcr_map[idx]) == 64
        int(pcr_map[idx], 16)  # must be valid hex


def test_t1_3_3_attest_tpm_quote_binding(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.3.3: TPM quote field matches PCR 7 measurement."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/attest")
    body = resp.json()
    assert body["tpm_pcr_quote"] == body["pcr_values"]["7"]


def test_t1_3_4_attest_ring0_posture(killswitch_server_harness: dict[str, Any]) -> None:
    """T1.3.4: Substrate reports valid active Ring-0 posture."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/attest")
    posture = resp.json()["ring0_posture"]
    assert posture in (
        "ACTIVE_WFP_FILTERED",
        "ACTIVE_RING0_ENFORCED",
        "VERIFIED_STAGED",
    )


def test_t1_3_5_attest_signature_verification(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.3.5: Attestation receipt signature cryptographically verifies against server JWKS."""
    base_url = killswitch_server_harness["base_url"]
    pub_key, _ = _get_server_pub_key(base_url)
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/attest")
    _verify_server_receipt(resp.json(), ATTESTATION_RECEIPT_DOMAIN_TAG, pub_key)


def test_t1_4_1_release_quorum_execution(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.4.1: Quorum release execution returns HTTP 200, released=True, outcome=RELEASED."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]

    # 1. Quarantine first
    q_canon, _, q_env = _build_quarantine_payload(
        workload_id="spiffe://cage.local/ns/test/sa/release-1"
    )
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + q_canon)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: q_env,
    }
    with httpx.Client(timeout=2.0) as client:
        q_resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=q_canon, headers=headers
        )
    assert q_resp.status_code == 200

    # 2. Release with quorum_count=2
    rel_canon, _, rel_env = _build_release_payload(
        workload_id="spiffe://cage.local/ns/test/sa/release-1"
    )
    rel_sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + rel_canon)
    rel_sig_b64 = base64.urlsafe_b64encode(rel_sig).decode("ascii").rstrip("=")
    rel_headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: rel_sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: rel_env,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=rel_canon, headers=rel_headers
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["released"] is True
    assert body["outcome"] == "RELEASED"
    assert body["enforcement_plane"] == "HOST_OS_KERNEL"


def test_t1_4_2_release_monotonic_epoch_autotomy(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.4.2: Release advances epoch monotonically (epoch_after > epoch_before)."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    workload = f"spiffe://cage.local/ns/test/sa/epoch-{uuid.uuid4().hex[:8]}"

    # Quarantine
    q_canon, _, q_env = _build_quarantine_payload(workload_id=workload)
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + q_canon)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: q_env,
    }
    with httpx.Client(timeout=2.0) as client:
        client.post(f"{base_url}/v1/cage/quarantine", content=q_canon, headers=headers)

    # Release
    rel_canon, _, rel_env = _build_release_payload(workload_id=workload)
    rel_sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + rel_canon)
    rel_sig_b64 = base64.urlsafe_b64encode(rel_sig).decode("ascii").rstrip("=")
    rel_headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: rel_sig_b64,
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: rel_env,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=rel_canon, headers=rel_headers
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["epoch_before"] == 1
    assert body["epoch_after"] == 2
    assert body["epoch_after"] > body["epoch_before"]


def test_t1_4_3_release_quorum_scaling(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.4.3: Quorum scaling supports quorum_count >= 2 (e.g. count=3, count=5)."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]

    for count in (3, 5):
        w = f"spiffe://cage.local/ns/test/sa/quorum-{count}-{uuid.uuid4().hex[:6]}"
        q_canon, _, q_env = _build_quarantine_payload(workload_id=w)
        sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + q_canon)
        headers = {
            "Content-Type": "application/json",
            HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
            .decode("ascii")
            .rstrip("="),
            HEADER_SIGNER_KID: signer.key_id,
            HEADER_ENVELOPE_DIGEST: q_env,
        }
        with httpx.Client(timeout=2.0) as client:
            client.post(
                f"{base_url}/v1/cage/quarantine", content=q_canon, headers=headers
            )

        rel_canon, _, rel_env = _build_release_payload(
            workload_id=w, quorum_count=count
        )
        rel_sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + rel_canon)
        rel_headers = {
            "Content-Type": "application/json",
            HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(rel_sig)
            .decode("ascii")
            .rstrip("="),
            HEADER_SIGNER_KID: signer.key_id,
            HEADER_ENVELOPE_DIGEST: rel_env,
        }
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(
                f"{base_url}/v1/cage/release", content=rel_canon, headers=rel_headers
            )
        assert resp.status_code == 200
        assert resp.json()["released"] is True


def test_t1_4_4_release_receipt_signature_verification(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.4.4: Release receipt contains valid detached Ed25519 signature."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    pub_key, _ = _get_server_pub_key(base_url)
    w = f"spiffe://cage.local/ns/test/sa/sig-{uuid.uuid4().hex[:8]}"

    q_canon, _, q_env = _build_quarantine_payload(workload_id=w)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(
            signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + q_canon)
        )
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: q_env,
    }
    with httpx.Client(timeout=2.0) as client:
        client.post(f"{base_url}/v1/cage/quarantine", content=q_canon, headers=headers)

    rel_canon, _, rel_env = _build_release_payload(workload_id=w)
    rel_headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(
            signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + rel_canon)
        )
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: rel_env,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=rel_canon, headers=rel_headers
        )
    assert resp.status_code == 200
    _verify_server_receipt(resp.json(), QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG, pub_key)


def test_t1_4_5_release_host_isolation_lift(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.4.5: Release envelope_digest matches request envelope digest."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    w = f"spiffe://cage.local/ns/test/sa/lift-{uuid.uuid4().hex[:8]}"

    q_canon, _, q_env = _build_quarantine_payload(workload_id=w)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(
            signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + q_canon)
        )
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: q_env,
    }
    with httpx.Client(timeout=2.0) as client:
        client.post(f"{base_url}/v1/cage/quarantine", content=q_canon, headers=headers)

    rel_canon, _, rel_env = _build_release_payload(workload_id=w)
    rel_headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(
            signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + rel_canon)
        )
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: rel_env,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=rel_canon, headers=rel_headers
        )
    assert resp.status_code == 200
    assert resp.json()["envelope_digest"] == rel_env


def test_t1_5_1_baseline_fetch_primary(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.5.1: Primary baseline fetch for europe-west1 returns alpha=0.05, calibration_size=500."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/normative-baseline/europe-west1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["region"] == "europe-west1"
    assert data["alpha"] == 0.05
    assert data["calibration_size"] == 500


def test_t1_5_2_baseline_multi_region(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.5.2: Multi-region baseline fetches accurately reflect queried region in path."""
    base_url = killswitch_server_harness["base_url"]
    for reg in ("us-central1", "asia-southeast1"):
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{base_url}/v1/cage/normative-baseline/{reg}")
        assert resp.status_code == 200
        assert resp.json()["region"] == reg


def test_t1_5_3_baseline_nonconformity_threshold(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.5.3: Substrate returns calibrated nonconformity_threshold=4.25."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/normative-baseline/europe-west1")
    assert resp.status_code == 200
    assert resp.json()["nonconformity_threshold"] == 4.25


def test_t1_5_4_baseline_signature_verification(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.5.4: Baseline signature verifies over CAGE_CONFORMAL_BASELINE_V1:<JCS>."""
    base_url = killswitch_server_harness["base_url"]
    pub_key, _ = _get_server_pub_key(base_url)
    with httpx.Client(timeout=2.0) as client:
        resp = client.get(f"{base_url}/v1/cage/normative-baseline/europe-west1")
    assert resp.status_code == 200
    _verify_server_receipt(resp.json(), CONFORMAL_BASELINE_DOMAIN_TAG, pub_key)


def test_t1_5_5_baseline_routing_resilience(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.5.5: Both /v1/cage/normative-baseline/... and /api/v1/cage/... resolve HTTP 200."""
    base_url = killswitch_server_harness["base_url"]
    with httpx.Client(timeout=2.0) as client:
        r1 = client.get(f"{base_url}/v1/cage/normative-baseline/europe-west1")
        r2 = client.get(f"{base_url}/api/v1/cage/normative-baseline/europe-west1")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["region"] == r2.json()["region"]


def test_t1_6_1_conformal_conforming_score_allow(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.6.1: High-conformity score (0.1) results in admitted=True, CONSENSUS_ALLOW."""
    base_url = killswitch_server_harness["base_url"]
    body = {
        "scores": [0.1],
        "alpha": 0.05,
        "action": "execute_read_query",
        "nonce": str(uuid.uuid4()),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["admitted"] is True
    assert data["p_value"] > 0.05
    assert data["voter_consensus"] == "CONSENSUS_ALLOW"


def test_t1_6_2_conformal_anomaly_score_deny(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.6.2: Non-conforming anomalous score (25.0) results in admitted=False, CONSENSUS_DENY."""
    base_url = killswitch_server_harness["base_url"]
    body = {
        "scores": [25.0],
        "alpha": 0.05,
        "action": "privilege_escalation_attempt",
        "nonce": str(uuid.uuid4()),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["admitted"] is False
    assert data["p_value"] <= 0.05
    assert data["voter_consensus"] == "CONSENSUS_DENY"


def test_t1_6_3_conformal_multidimensional_vector(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.6.3: Multi-dimensional feature vector projected into calibrated space yields valid p-value."""
    base_url = killswitch_server_harness["base_url"]
    body = {
        "scores": [0.1, 0.2, 0.15, 0.05],
        "alpha": 0.05,
        "action": "multi_dimensional_metric",
        "nonce": str(uuid.uuid4()),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert 0.0 <= data["p_value"] <= 1.0


def test_t1_6_4_conformal_action_and_alpha_tuning(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.6.4: Custom action and strict alpha (0.01) evaluated properly."""
    base_url = killswitch_server_harness["base_url"]
    body = {
        "scores": [0.2],
        "alpha": 0.01,
        "action": "wire_transfer_operation",
        "nonce": str(uuid.uuid4()),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
    assert resp.status_code == 200
    assert resp.json()["alpha"] == 0.01


def test_t1_6_5_conformal_signature_verification(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T1.6.5: Conformal validation receipt signature verifies over CAGE_CONFORMAL_VALIDATION_V1:<JCS>."""
    base_url = killswitch_server_harness["base_url"]
    pub_key, _ = _get_server_pub_key(base_url)
    body = {
        "scores": [0.3],
        "alpha": 0.05,
        "action": "signature_check_action",
        "nonce": str(uuid.uuid4()),
    }
    canonical = jcs_canonicalize_plan(body)
    expected_digest = hashlib.sha256(canonical).hexdigest()

    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/conformal/validate",
            content=canonical,
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["envelope_digest"] == expected_digest
    _verify_server_receipt(data, NORMATIVE_VALIDATION_DOMAIN_TAG, pub_key)


# ==============================================================================
# Tier 2: Boundary, Edge & Corner Cases (27 Test Cases)
# ==============================================================================


def test_t2_1_1_quarantine_missing_assertion_header(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.1.1: Missing X-CAGE-Quarantine-Assertion header returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    headers = {
        "Content-Type": "application/json",
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_1_2_quarantine_missing_signer_kid_header(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.1.2: Missing X-CAGE-Signer-Kid header returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_1_3_release_missing_assertion_header(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.1.3: Missing X-CAGE-Quarantine-Release header returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_release_payload()
    headers = {
        "Content-Type": "application/json",
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_1_4_release_missing_signer_kid_header(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.1.4: Missing X-CAGE-Signer-Kid header on release returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_release_payload()
    sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_2_1_forged_random_signature(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.2.1: Cryptographically forged 64 random signature bytes returns HTTP 401."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    forged_sig = b"\xaa" * 64
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(forged_sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 401


def test_t2_2_2_truncated_signature_32_bytes(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.2.2: Truncated signature (<64 bytes) returns HTTP 401."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    truncated_sig = b"\xbb" * 32
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(truncated_sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 401


def test_t2_2_3_inflated_signature_96_bytes(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.2.3: Inflated signature (>64 bytes) returns HTTP 401."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    inflated_sig = b"\xcc" * 96
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(inflated_sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 401


def test_t2_2_4_corrupted_base64_symbols(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.2.4: Non-base64 characters in signature header returns HTTP 401."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: "!@#$%^&*()_+~`",
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 401


def test_t2_2_5_tampered_body_after_signing(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.2.5: Tampered payload bytes after signature generation fails verification with HTTP 401."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, payload, _ = _build_quarantine_payload(
        workload_id="spiffe://cage.local/legit"
    )
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)

    # Tamper body
    payload["workload_id"] = "spiffe://cage.local/adversary_tampered"
    tampered_bytes = jcs_canonicalize_plan(payload)

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=tampered_bytes, headers=headers
        )
    assert resp.status_code == 401


def test_t2_3_1_unknown_signer_kid(killswitch_server_harness: dict[str, Any]) -> None:
    """T2.3.1: Signer kid not registered in CAGE_TRUSTED_JWKS returns HTTP 403."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: "unknown-kid-00000000000000000000000000000000000000000000000000000000",
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 403


def test_t2_3_2_empty_signer_kid(killswitch_server_harness: dict[str, Any]) -> None:
    """T2.3.2: Empty string kid returns HTTP 403."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: "",
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 403


def test_t2_3_3_kid_case_mutated(killswitch_server_harness: dict[str, Any]) -> None:
    """T2.3.3: Case-mutated kid (uppercase) fails exact match and returns HTTP 403."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_quarantine_payload()
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)

    mutated_kid = signer.key_id.upper()
    if mutated_kid == signer.key_id:
        mutated_kid = signer.key_id + "A"

    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: mutated_kid,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 403


def test_t2_4_1_quarantine_duplicate_nonce_replay(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.4.1: Replaying duplicate quarantine nonce returns HTTP 409 Conflict."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    fixed_nonce = f"nonce-replay-{uuid.uuid4()}"
    canonical, _, env = _build_quarantine_payload(nonce=fixed_nonce)
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: env,
    }
    with httpx.Client(timeout=2.0) as client:
        r1 = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
        assert r1.status_code == 200
        r2 = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
        assert r2.status_code == 409


def test_t2_4_2_release_duplicate_nonce_replay(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.4.2: Replaying duplicate release nonce returns HTTP 409 Conflict."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    fixed_nonce = f"nonce-release-replay-{uuid.uuid4()}"
    canonical, _, env = _build_release_payload(nonce=fixed_nonce)
    sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
        HEADER_ENVELOPE_DIGEST: env,
    }
    with httpx.Client(timeout=2.0) as client:
        r1 = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
        assert r1.status_code == 200
        r2 = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
        assert r2.status_code == 409


def test_t2_4_3_conformal_duplicate_nonce_replay(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.4.3: Replaying duplicate conformal validation nonce returns HTTP 409 Conflict."""
    base_url = killswitch_server_harness["base_url"]
    fixed_nonce = f"nonce-conformal-replay-{uuid.uuid4()}"
    body = {"scores": [0.2], "alpha": 0.05, "action": "test", "nonce": fixed_nonce}
    with httpx.Client(timeout=2.0) as client:
        r1 = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
        assert r1.status_code == 200
        r2 = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
        assert r2.status_code == 409


def test_t2_5_1_keys_unsorted_order(killswitch_server_harness: dict[str, Any]) -> None:
    """T2.5.1: Keys sent in unsorted arbitrary order are canonicalized identically per JCS."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    unsorted_dict = {
        "timestamp_utc": "2026-11-03T05:00:00Z",
        "workload_id": f"spiffe://cage.local/unsorted-{uuid.uuid4().hex[:6]}",
        "trigger_reason": "Out of order keys test",
        "source_rule_id": "RULE-TEST",
        "refusal_proof_hash": "a" * 64,
        "nonce": str(uuid.uuid4()),
        "enforcement_plane": "HOST_OS_KERNEL",
    }
    canonical = jcs_canonicalize_plan(unsorted_dict)
    sig = signer.sign_raw(QUARANTINE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=canonical, headers=headers
        )
    assert resp.status_code == 200


def test_t2_5_2_malformed_json_syntax(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.5.2: Malformed JSON syntax returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    bad_bytes = b'{"workload_id": "bad", "nonce": '
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: "dummy",
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", content=bad_bytes, headers=headers
        )
    assert resp.status_code == 400


def test_t2_5_3_payload_too_large_exceeding_max_bytes(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.5.3: Overly large request body exceeding max_body_bytes returns HTTP 413 or 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    huge_padding = "x" * (3 * 1024 * 1024)  # 3 MB
    payload = {"workload_id": "huge", "padding": huge_padding}
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_ASSERTION: "dummy",
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=5.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/quarantine", json=payload, headers=headers
        )
    assert resp.status_code in (413, 400)


def test_t2_6_1_quorum_count_insufficient_1(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.6.1: Quorum release with quorum_count == 1 returns HTTP 400 (quorum >= 2 required)."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_release_payload(quorum_count=1)
    sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_6_2_quorum_count_zero(killswitch_server_harness: dict[str, Any]) -> None:
    """T2.6.2: Quorum release with quorum_count == 0 returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    canonical, _, _ = _build_release_payload(quorum_count=0)
    sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_6_3_digest_length_invalid_63_chars(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.6.3: Digest with invalid length (63 hex chars) returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    short_digest = "f" * 63
    canonical, _, _ = _build_release_payload(digest=short_digest)
    sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_6_4_digest_characters_non_hex(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.6.4: Digest containing non-hex characters (e.g. 'z') returns HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    signer = killswitch_server_harness["signer"]
    non_hex_digest = ("a" * 62) + "zz"
    canonical, _, _ = _build_release_payload(digest=non_hex_digest)
    sig = signer.sign_raw(QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical)
    headers = {
        "Content-Type": "application/json",
        HEADER_QUARANTINE_RELEASE: base64.urlsafe_b64encode(sig)
        .decode("ascii")
        .rstrip("="),
        HEADER_SIGNER_KID: signer.key_id,
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{base_url}/v1/cage/release", content=canonical, headers=headers
        )
    assert resp.status_code == 400


def test_t2_7_1_extreme_float_saturation_2pow63_minus_1(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.7.1: Extreme float saturation at 2^63 - 1 handled cleanly without crash."""
    base_url = killswitch_server_harness["base_url"]
    val = float(2**63 - 1)
    body = {
        "scores": [val],
        "alpha": 0.05,
        "action": "saturation_test",
        "nonce": str(uuid.uuid4()),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
    assert resp.status_code == 200


def test_t2_7_2_extreme_negative_float_2pow63(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.7.2: Extreme negative float -2^63 handled cleanly."""
    base_url = killswitch_server_harness["base_url"]
    val = float(-(2**63))
    body = {
        "scores": [val],
        "alpha": 0.05,
        "action": "neg_test",
        "nonce": str(uuid.uuid4()),
    }
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
    assert resp.status_code == 200


def test_t2_7_3_scientific_notation_10e20_vs_10e21(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.7.3: Scientific notation boundaries (1e20, 1e21) parsed successfully."""
    base_url = killswitch_server_harness["base_url"]
    for val in (1e20, 1e21):
        body = {
            "scores": [val],
            "alpha": 0.05,
            "action": "sci_test",
            "nonce": str(uuid.uuid4()),
        }
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
        assert resp.status_code == 200


def test_t2_7_4_subnormal_float_10e_minus_6_vs_10e_minus_7(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.7.4: Small subnormal floats (1e-6, 1e-7) handled accurately."""
    base_url = killswitch_server_harness["base_url"]
    for val in (1e-6, 1e-7):
        body = {
            "scores": [val],
            "alpha": 0.05,
            "action": "small_test",
            "nonce": str(uuid.uuid4()),
        }
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(f"{base_url}/v1/cage/conformal/validate", json=body)
        assert resp.status_code == 200


def test_t2_7_5_unrepresentable_floats_nan_inf(
    killswitch_server_harness: dict[str, Any],
) -> None:
    """T2.7.5: Unrepresentable floats (NaN, Infinity) rejected with HTTP 400."""
    base_url = killswitch_server_harness["base_url"]
    for token in (
        b'{"scores": [NaN], "nonce": "n1"}',
        b'{"scores": [Infinity], "nonce": "n2"}',
    ):
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(
                f"{base_url}/v1/cage/conformal/validate",
                content=token,
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 400
