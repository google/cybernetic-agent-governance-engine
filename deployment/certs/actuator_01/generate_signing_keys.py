#!/usr/bin/env python3
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

"""Generate dedicated Ed25519 signing keypairs for actuator_01 sandbox runs.

Creates gitignored private key files (*.key, mode 0600) in
``deployment/certs/actuator_01/`` and writes the corresponding public keys
(64-char lowercase hex) and URN bindings to ``sandbox_public_keys.json``.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CERT_DIR = Path(__file__).resolve().parent

KEY_SPECS: tuple[tuple[str, str, str, str], ...] = (
    (
        "policy_authority",
        "ed25519_policy.key",
        "urn:archytan:cage:policy-authority",
        "governance.decision_signature (ARCHYTAN_POLICY_DECISION_V1:)",
    ),
    (
        "operator_1_and_assertion",
        "ed25519_op1.key",
        "urn:archytan:cage:operator:test-alice",
        "X-Execution-Assertion (ARCHYTAN_ASSERTION_V1:) & X-Archytan-Signatures[0] (ARCHYTAN_QUORUM_V1:)",
    ),
    (
        "operator_2",
        "ed25519_op2.key",
        "urn:archytan:cage:operator:test-bob",
        "X-Archytan-Signatures[1] (ARCHYTAN_QUORUM_V1:)",
    ),
    (
        "step_up_approver",
        "ed25519_approver.key",
        "urn:archytan:cage:operator:test-approver",
        "approval.signature (WebAuthn FIDO2 Ed25519 over authenticator_data || SHA-256(client_data_json))",
    ),
)


def generate_sandbox_keys(
    target_dir: Path = CERT_DIR, *, overwrite: bool = False
) -> dict:
    """Generate or load Ed25519 keypairs and write sandbox_public_keys.json."""
    resolved_dir = target_dir.resolve()
    manifest_entries: dict[str, dict[str, str]] = {}

    for role_id, filename, urn, purpose in KEY_SPECS:
        key_path = (resolved_dir / Path(filename).name).resolve()
        if not str(key_path).startswith(str(resolved_dir) + os.sep):
            raise ValueError(f"Refusing path outside target directory: {key_path}")

        if key_path.exists() and not overwrite:
            pem_bytes = key_path.read_bytes()
            priv = serialization.load_pem_private_key(pem_bytes, password=None)
            if not isinstance(priv, Ed25519PrivateKey):
                raise TypeError(f"{key_path} is not an Ed25519 private key")
        else:
            priv = Ed25519PrivateKey.generate()
            pem_bytes = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(pem_bytes)

        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        manifest_entries[role_id] = {
            "urn": urn,
            "public_key_hex": pub_raw.hex().lower(),
            "private_key_file": filename,
            "purpose": purpose,
        }

    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "algorithm": "Ed25519",
        "keys": manifest_entries,
    }
    manifest_path = resolved_dir / "sandbox_public_keys.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    result = generate_sandbox_keys()
    print(json.dumps(result, indent=2))
