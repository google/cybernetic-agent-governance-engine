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

"""G8: ground-truth snapshots are verified by kid against reconciler-only anchors.

Uses real asymmetric keys (hermetic Ed25519 / P-384) so every fail-closed
path is observed failing on actual signature verification, not on mocks.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required for CBF tests")

import fakeredis  # type: ignore[import]
import fakeredis.aioredis  # type: ignore[import]

from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.governance.reconciliation import daemon, trust
from src.gateway.governance.reconciliation.daemon import (
    GroundTruthReconciler,
    ReconciliationResult,
    read_verified_balance,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

RECONCILER_KID = (
    "projects/p/locations/l/keyRings/r/cryptoKeys/"
    "cage-reconciler-snapshot-signer/cryptoKeyVersions/1"
)
GATEWAY_KID = (
    "projects/p/locations/l/keyRings/r/cryptoKeys/"
    "cage-gateway-seal-signer/cryptoKeyVersions/1"
)
_TRUST_VERIFIER = "src.gateway.governance.reconciliation.trust.get_reconciler_verifier"


def _signer(kid: str) -> KMSGovernanceSigner:
    return KMSGovernanceSigner(provider=SoftwareEd25519Provider(key_id=kid))


def _signed_snapshot(signer: KMSGovernanceSigner, **overrides) -> ReconciliationResult:
    snap = ReconciliationResult(
        source="simulated:ground_truth",
        state_scalar=75_000.0,
        verified_at=time.time(),
        sequence=3,
        invariant_id="test.invariant",
    )
    record = signer.sign_decision(trust.snapshot_signing_payload(snap))
    snap.signature = record.signature
    snap.kms_key_id = record.kid
    snap.signing_algorithm = record.algorithm
    for key, value in overrides.items():
        setattr(snap, key, value)
    return snap


def _verifier_for(signer: KMSGovernanceSigner, kid: str) -> KMSGovernanceSigner:
    return trust.build_reconciler_verifier({kid: signer.get_public_key_pem()})


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(trust.RECONCILER_KMS_KEY_ENV, raising=False)
    monkeypatch.delenv(trust.GATEWAY_KMS_KEY_ENV, raising=False)
    trust.reset_reconciler_trust()
    yield
    trust.reset_reconciler_trust()


# ---------------------------------------------------------------------------
# verify_snapshot_signature — positive control and fail-closed paths
# ---------------------------------------------------------------------------


def test_reconciler_signed_snapshot_verifies() -> None:
    reconciler = _signer(RECONCILER_KID)
    snap = _signed_snapshot(reconciler)
    assert snap.kms_key_id == RECONCILER_KID
    assert trust.verify_snapshot_signature(
        snap, _verifier_for(reconciler, RECONCILER_KID)
    )


def test_unknown_kid_fails_closed() -> None:
    reconciler = _signer(RECONCILER_KID)
    rogue = _signer("projects/p/cryptoKeys/rogue/cryptoKeyVersions/1")
    snap = _signed_snapshot(rogue)
    assert not trust.verify_snapshot_signature(
        snap, _verifier_for(reconciler, RECONCILER_KID)
    )


def test_gateway_kid_on_reconciler_snapshot_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a trusted, cryptographically valid gateway signature is refused."""
    monkeypatch.setenv(trust.GATEWAY_KMS_KEY_ENV, GATEWAY_KID)
    gateway = _signer(GATEWAY_KID)
    snap = _signed_snapshot(gateway)
    # The verifier deliberately (mis)trusts the gateway key: the explicit
    # gateway-kid rejection must still fail closed.
    assert not trust.verify_snapshot_signature(
        snap, _verifier_for(gateway, GATEWAY_KID)
    )


def test_gateway_key_other_version_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(trust.GATEWAY_KMS_KEY_ENV, GATEWAY_KID)
    other_version = GATEWAY_KID.replace("/cryptoKeyVersions/1", "/cryptoKeyVersions/7")
    assert trust.is_gateway_kid(other_version)


def test_gateway_signer_cannot_verify_via_default_anchor() -> None:
    """The reconciler verifier has no own key and no 'default' anchor."""
    reconciler = _signer(RECONCILER_KID)
    gateway = _signer(GATEWAY_KID)
    snap = _signed_snapshot(gateway, kms_key_id="default")
    assert not trust.verify_snapshot_signature(
        snap, _verifier_for(reconciler, RECONCILER_KID)
    )


@pytest.mark.parametrize("field", ["kms_key_id", "signing_algorithm", "signature"])
def test_missing_signature_metadata_fails_closed(field: str) -> None:
    reconciler = _signer(RECONCILER_KID)
    snap = _signed_snapshot(reconciler, **{field: ""})
    assert not trust.verify_snapshot_signature(
        snap, _verifier_for(reconciler, RECONCILER_KID)
    )


def test_tampered_scalar_fails_closed() -> None:
    reconciler = _signer(RECONCILER_KID)
    snap = _signed_snapshot(reconciler)
    snap.state_scalar = 9_999_999.0
    assert not trust.verify_snapshot_signature(
        snap, _verifier_for(reconciler, RECONCILER_KID)
    )


def test_software_algorithm_rejected_in_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reconciler = _signer(RECONCILER_KID)
    snap = _signed_snapshot(reconciler)
    verifier = _verifier_for(reconciler, RECONCILER_KID)
    monkeypatch.setenv("CAGE_ENV", "production")
    assert not trust.verify_snapshot_signature(snap, verifier)


def test_no_reconciler_key_means_no_anchors() -> None:
    reconciler = _signer(RECONCILER_KID)
    snap = _signed_snapshot(reconciler)
    assert trust.load_reconciler_trust_anchors() == {}
    assert not trust.verify_snapshot_signature(snap)


def test_reconciler_key_equal_to_gateway_key_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(trust.GATEWAY_KMS_KEY_ENV, GATEWAY_KID)
    monkeypatch.setenv(trust.RECONCILER_KMS_KEY_ENV, GATEWAY_KID)
    with pytest.raises(RuntimeError, match="must not reference the gateway key"):
        trust.load_reconciler_trust_anchors()
    with pytest.raises(RuntimeError, match="must not reference the gateway key"):
        trust.build_reconciler_signer()


def test_verify_only_instance_handles_p384_digest() -> None:
    """A provider-less verifier must derive SHA-384 from a P-384 key."""
    import hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    from src.gateway.governance.kms_signer import _canonicalise_plan

    key = ec.generate_private_key(ec.SECP384R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    snap = ReconciliationResult(
        source="s", state_scalar=1.0, verified_at=time.time(), sequence=1
    )
    digest = hashlib.sha384(
        _canonicalise_plan(trust.snapshot_signing_payload(snap))
    ).digest()
    snap.signature = key.sign(
        digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA384()))
    ).hex()
    snap.kms_key_id = RECONCILER_KID
    snap.signing_algorithm = "gcp_kms"
    assert trust.verify_snapshot_signature(
        snap, trust.build_reconciler_verifier({RECONCILER_KID: pem})
    )


# ---------------------------------------------------------------------------
# Daemon write path records kid/algorithm; read path enforces anchors
# ---------------------------------------------------------------------------


class _FixedSource:
    initial_scalar = 60_000.0

    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        return ReconciliationResult(
            source="simulated:ground_truth",
            state_scalar=60_000.0,
            invariant_id="test.invariant",
        )


def test_daemon_records_kid_and_roundtrips_through_redis() -> None:
    reconciler_signer = _signer(RECONCILER_KID)
    r = fakeredis.FakeRedis(decode_responses=True)
    worker = GroundTruthReconciler(
        provider=_FixedSource(),
        redis_client=r,
        account_id="acct",
        signer=reconciler_signer,
    )
    result = worker.reconcile("test.invariant")
    assert result.is_valid, result.error
    assert result.kms_key_id == RECONCILER_KID
    assert result.signing_algorithm == "SOFTWARE_ED25519"

    verifier = _verifier_for(reconciler_signer, RECONCILER_KID)
    snap = read_verified_balance(r, "test.invariant", signer=verifier)
    assert snap is not None
    assert snap.kms_key_id == RECONCILER_KID

    other = _verifier_for(_signer(RECONCILER_KID), RECONCILER_KID)
    assert read_verified_balance(r, "test.invariant", signer=other) is None


# ---------------------------------------------------------------------------
# CBF: unknown kid / gateway kid → BLOCK in strict mode
# ---------------------------------------------------------------------------


async def _resolve_strict(make_cbf, verified, verifier):
    from src.gateway.governance.governor.governor import GovernanceError

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cbf, _ = make_cbf()
    await fake_redis.set(cbf.redis_key, "50000.0")
    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            MagicMock(get_raw_client=MagicMock(return_value=fake_redis)),
        ),
        patch(
            "src.gateway.governance.safety.cbf_engine.asyncio.to_thread",
            AsyncMock(return_value=verified),
        ),
        patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", True),
        patch(
            "src.gateway.governance.safety.cbf_engine._REPLAY_DEFENSE_ENABLED", False
        ),
        patch(_TRUST_VERIFIER, return_value=verifier),
    ):
        try:
            balance, meta = await cbf._resolve_ground_truth_balance()
        except GovernanceError as exc:
            return exc
    return balance, meta


@pytest.mark.asyncio
async def test_cbf_accepts_reconciler_signed_snapshot_in_strict_mode(make_cbf):
    reconciler = _signer(RECONCILER_KID)
    out = await _resolve_strict(
        make_cbf,
        _signed_snapshot(reconciler),
        _verifier_for(reconciler, RECONCILER_KID),
    )
    assert isinstance(out, tuple), out
    assert out[0] == 75_000.0
    assert out[1]["source"] == "reconciliation"


@pytest.mark.asyncio
async def test_cbf_unknown_kid_blocks_in_strict_mode(make_cbf):
    reconciler = _signer(RECONCILER_KID)
    rogue = _signer("projects/p/cryptoKeys/rogue/cryptoKeyVersions/1")
    out = await _resolve_strict(
        make_cbf,
        _signed_snapshot(rogue),
        _verifier_for(reconciler, RECONCILER_KID),
    )
    assert not isinstance(out, tuple), "unknown kid must BLOCK"
    assert out.payload["audit_code"] == "CBF_STRICT_RECONCILIATION_UNAVAILABLE"


@pytest.mark.asyncio
async def test_cbf_gateway_kid_on_reconciler_snapshot_blocks_in_strict_mode(
    make_cbf, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(trust.GATEWAY_KMS_KEY_ENV, GATEWAY_KID)
    gateway = _signer(GATEWAY_KID)
    out = await _resolve_strict(
        make_cbf,
        _signed_snapshot(gateway),
        _verifier_for(gateway, GATEWAY_KID),
    )
    assert not isinstance(out, tuple), "gateway-signed ground truth must BLOCK"
    assert out.payload["audit_code"] == "CBF_STRICT_RECONCILIATION_UNAVAILABLE"


# ---------------------------------------------------------------------------
# RECONCILIATION_SINGLE_SHOT entry point
# ---------------------------------------------------------------------------


def _patch_from_env(results: dict[str, ReconciliationResult]):
    fake = MagicMock()
    fake.reconcile_all.return_value = results
    return patch.object(GroundTruthReconciler, "from_env", return_value=fake), fake


def test_single_shot_success_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECONCILIATION_SINGLE_SHOT", "true")
    ctx, fake = _patch_from_env(
        {"a": ReconciliationResult(source="s", state_scalar=1.0)}
    )
    with ctx:
        assert daemon.main() == 0
    fake.run_loop.assert_not_called()


def test_single_shot_failure_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECONCILIATION_SINGLE_SHOT", "true")
    ctx, fake = _patch_from_env(
        {"a": ReconciliationResult(source="s", state_scalar=1.0, error="KMS down")}
    )
    with ctx:
        assert daemon.main() == 1
    fake.run_loop.assert_not_called()


def test_single_shot_with_no_results_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RECONCILIATION_SINGLE_SHOT", "true")
    ctx, _ = _patch_from_env({})
    with ctx:
        assert daemon.main() == 1


def test_loop_mode_when_single_shot_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECONCILIATION_SINGLE_SHOT", raising=False)
    ctx, fake = _patch_from_env({})
    with ctx:
        assert daemon.main() == 0
    fake.run_loop.assert_called_once()
