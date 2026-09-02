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

"""Hermetic FTRA registry signing harness for tests.

Why this exists
---------------
``IrreversibilityClassifier`` verifies the terminal registry signature on
**every** load, with no posture gate and no version-based bypass (plan §13,
R2). Any test that loads a registry therefore needs a validly signed one.

The repository deliberately ships **no** signed registry and **no** committed
key material:

* a committed signature carries an ``expires_at`` and would break CI on a
  future date with no code change;
* signing at commit time would put a KMS dependency on every local dev run.

Instead, tests generate a throwaway EC P-256 keypair in-process and sign their
own fixtures with it. This proves the *enforcement mechanism* — a valid
signature admits, a missing or invalid one fails closed — which is what the
suite is for. It does **not** attest the shipped registry to a real KMS; that
remains a deploy-pipeline responsibility (plan §6, §13 R2a).

Scope of the guarantee
----------------------
A green suite means the control correctly rejects an unsigned or tampered
registry. It does **not** mean VEC-005 is closed in a deployed environment —
that additionally requires a signed registry to exist there.

Usage::

    def test_something(tmp_path, hermetic_signer, signed_registry):
        path = signed_registry(tmp_path, {"execute_trade": "IRREVERSIBLE_TERMINAL"})
        classifier = IrreversibilityClassifier(registry_path=path)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import Mock

# Module-level cache: generating an EC keypair costs a few milliseconds, and a
# large suite would otherwise repeat it for every test that touches a registry.
_CACHED_KEYPAIR: tuple[Any, bytes] | None = None


def generate_ec_p256_keypair() -> tuple[Any, bytes]:
    """Return a cached ``(private_key, public_pem)`` EC P-256 pair.

    The pair is process-local and never written to disk. It exists only to make
    signature verification exercisable without KMS credentials.
    """
    global _CACHED_KEYPAIR
    if _CACHED_KEYPAIR is None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _CACHED_KEYPAIR = (private_key, public_pem)
    return _CACHED_KEYPAIR


def build_hermetic_signer() -> Any:
    """Construct a ``KMSGovernanceSigner`` backed by the in-process keypair.

    A stub provider performs the actual ECDSA operation with the local private
    key. The real ``verify()`` code path runs unmodified — the function under
    test is never mocked, only the key source behind it.
    """
    from src.gateway.governance.kms_signer import (
        BaseKMSProvider,
        KMSGovernanceSigner,
    )

    private_key, public_pem = generate_ec_p256_keypair()

    class _HermeticProvider(BaseKMSProvider):
        @property
        def digest_algorithm(self) -> str:
            return "sha256"

        @property
        def provider_name(self) -> str:
            return "hermetic_test"

        def sign_digest(self, digest: bytes) -> bytes:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric import (
                utils as asym_utils,
            )

            return private_key.sign(
                digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
            )

        def get_public_key_pem(self) -> bytes:
            return public_pem

        def sign_raw(self, message: bytes) -> bytes:
            import hashlib

            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric import (
                utils as asym_utils,
            )

            digest = hashlib.sha256(message).digest()
            return private_key.sign(
                digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
            )

    return KMSGovernanceSigner(
        kms_client=Mock(),  # never called; the stub provider handles signing
        key_version_name=(
            "projects/test/locations/global/keyRings/test/"
            "cryptoKeys/test/cryptoKeyVersions/1"
        ),
        public_key_pem=public_pem,
        provider=_HermeticProvider(),
    )


def build_registry_dict(
    terminals: dict[str, str] | None = None,
    serial: int = 42,
    validity_days: int = 90,
) -> dict[str, Any]:
    """Build a well-formed v2.0 registry envelope.

    Note there is deliberately no ``signed_at`` key: ``KMSGovernanceSigner.verify()``
    rejects any payload carrying one after 300 seconds, which would be correct
    for reconciliation payloads and fatal for a registry meant to live for
    months (plan §3).
    """
    if terminals is None:
        terminals = {
            "check_balance": "READ_ONLY",
            "execute_trade": "IRREVERSIBLE_TERMINAL",
        }

    now_utc = datetime.now(timezone.utc)
    return {
        "version": "2.0",
        "serial": serial,
        "issued_at": now_utc.isoformat(),
        "expires_at": (now_utc + timedelta(days=validity_days)).isoformat(),
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": (
            "Any action absent from this registry is treated as "
            "IRREVERSIBLE_TERMINAL by IrreversibilityClassifier at runtime."
        ),
        "terminals": terminals,
    }


def write_signed_registry(
    directory: Path,
    signer: Any,
    terminals: dict[str, str] | None = None,
    serial: int = 42,
    validity_days: int = 90,
    filename: str = "terminal_registry.json",
) -> tuple[Path, dict[str, Any]]:
    """Write a signed v2.0 registry plus its detached ``.sig``.

    Returns ``(registry_path, registry_dict)``.
    """
    registry = build_registry_dict(
        terminals=terminals, serial=serial, validity_days=validity_days
    )

    signature_hex = signer.sign(registry)
    sig_envelope = {
        "alg": "ES256",
        "key_id": signer.key_id,
        "canonicalization": "RFC8785-JCS",
        "signature": signature_hex,
    }

    directory.mkdir(parents=True, exist_ok=True)
    registry_path = directory / filename
    registry_path.write_text(json.dumps(registry, indent=2))
    Path(str(registry_path) + ".sig").write_text(json.dumps(sig_envelope, indent=2))

    return registry_path, registry
