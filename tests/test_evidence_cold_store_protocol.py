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

"""test_evidence_cold_store_protocol.py — Protocol Conformance & Layer 1 Isolation Tests

Verifies:
1. AST Static Vendor Isolation: Zero cloud vendor SDK imports in Layer 1 cold_store.py
2. Immutability invariants of ColdStoreReceipt and ColdStoreHealth
3. NullColdStore compliance with the EvidenceColdStore protocol
4. Fail-closed production environment guard on NullColdStore
"""

import ast
import dataclasses
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.gateway.governance.evidence.cold_store import (
    ColdStoreError,
    ColdStoreHealth,
    ColdStoreReceipt,
    EvidenceColdStore,
)
from src.gateway.governance.null_components import NullColdStore

pytestmark = [pytest.mark.unit]


def test_layer1_cold_store_ast_zero_vendor_imports():
    """Gate G3/Layer 1 isolation: cold_store.py must contain zero vendor imports."""
    cold_store_path = Path("src/gateway/governance/evidence/cold_store.py")
    assert cold_store_path.exists(), (
        "src/gateway/governance/evidence/cold_store.py must exist"
    )

    tree = ast.parse(cold_store_path.read_text(encoding="utf-8"))

    prohibited_vendor_prefixes = ("google", "boto", "azure", "botocore")

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(alias.name.startswith(p) for p in prohibited_vendor_prefixes):
                    violations.append(f"import {alias.name} (line {node.lineno})")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if any(module.startswith(p) for p in prohibited_vendor_prefixes):
                violations.append(f"from {module} import ... (line {node.lineno})")

    assert not violations, (
        f"Layer 1 cold_store.py contains prohibited vendor imports: {violations}"
    )


def test_cold_store_receipt_immutable():
    """ColdStoreReceipt must be a frozen dataclass."""
    now = datetime.now(timezone.utc)
    receipt = ColdStoreReceipt(
        uri="gs://test-bucket/test-key",
        key="test-key",
        content_sha256="abc123",
        backend_id="gcs",
        written_at=now,
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.uri = "gs://other-bucket/test-key"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.backend_id = "s3"  # type: ignore[misc]


def test_cold_store_health_immutable():
    """ColdStoreHealth must be a frozen dataclass."""
    health = ColdStoreHealth(
        available=True,
        backend_id="null",
        detail="healthy",
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        health.available = False  # type: ignore[misc]


@pytest.mark.asyncio
async def test_null_cold_store_conforms_to_protocol(monkeypatch):
    """NullColdStore must satisfy the EvidenceColdStore protocol at runtime."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    store = NullColdStore()

    assert isinstance(store, EvidenceColdStore)
    assert store.backend_id == "null"

    health = store.health()
    assert health.available is True
    assert health.backend_id == "null"

    # Test put_batch
    payload = b'{"event": "AUDIT_TEST", "seq": 1}\n'
    expected_sha = hashlib.sha256(payload).hexdigest()
    receipt = await store.put_batch("batch/2026-09-05.ndjson", payload)

    assert receipt.uri == "null://batch/2026-09-05.ndjson"
    assert receipt.key == "batch/2026-09-05.ndjson"
    assert receipt.content_sha256 == expected_sha
    assert receipt.backend_id == "null"

    # Test exists
    assert await store.exists("batch/2026-09-05.ndjson") is True
    assert await store.exists("batch/nonexistent.ndjson") is False

    # Test put_if_absent on existing key
    receipt2, created = await store.put_if_absent("batch/2026-09-05.ndjson", payload)
    assert created is False
    assert receipt2.content_sha256 == expected_sha

    # Test put_if_absent on new key
    receipt3, created3 = await store.put_if_absent("batch/another.ndjson", payload)
    assert created3 is True
    assert receipt3.content_sha256 == expected_sha


def test_null_cold_store_fails_closed_in_production(monkeypatch):
    """NullColdStore must refuse to instantiate in production (CAGE_ENV=prod)."""
    monkeypatch.setenv("CAGE_ENV", "prod")

    with pytest.raises(RuntimeError, match="requires durable cold storage"):
        NullColdStore()


def test_cold_store_error_preserves_cause():
    """ColdStoreError must correctly wrap underlying causes."""
    cause = ValueError("Connection timeout")
    err = ColdStoreError("GCS failure", backend_id="gcs")
    err.__cause__ = cause

    assert err.backend_id == "gcs"
    assert str(err) == "GCS failure"
    assert err.__cause__ is cause
