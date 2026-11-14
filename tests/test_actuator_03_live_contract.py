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

"""Hermetic contract & mutation tests for the Actuator 03 live conformance suite (POAM-2026-166).

Spins up a real localhost mTLS HTTP server (``ThreadingHTTPServer`` wrapped in a
strict TLS 1.3 ``SSLContext`` with mutual certificate verification) plus an
out-of-band ``file://`` Ed25519 JWKS manifest, and executes the exact live test
functions from ``tests/integrations/actuator_03/test_actuator_03_live.py`` over
real sockets.

Verifies:
  - All 4 live conformance scenarios pass end-to-end when the server honors the
    ``POAM-2026-149`` / ``POAM-2026-166`` wire contract.
  - Planted server bugs / mutants are killed:
    * M1: Server accepting a directive carrying BOTH ``refusal_proof_hash`` and
      ``governance_decision_digest`` fails test 4.
    * M2: Server accepting a directive carrying NEITHER digest field fails test 4.
    * M3a/M3b: Server returning an unsigned receipt or a signed receipt bound to
      a wrong ``envelope_digest`` fails tests 2 & 3 with ``ActuationOutcome.UNKNOWN``.
    * M4: Running under ``-p tests.fixtures.require_live`` with missing
      ``ACTUATOR_03_ENDPOINT`` fails the pytest session (zero silent skips).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ExecutionClearance,
    ReceiptVerification,
)
from src.gateway.governance.seams.quarantine import (
    QuarantineDirective,
    QuarantineTriggerReason,
)
from src.integrations.actuator_03.adapter import Actuator03Adapter
from src.integrations.actuator_03.constants import (
    QUARANTINE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RECEIPT_DOMAIN_TAG,
)
from src.integrations.trust.key_manifest import Ed25519KeyManifestClient
from tests.integrations.actuator_03 import test_actuator_03_live as live_suite

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LIVE_SUITE_REL_PATH = "tests/integrations/actuator_03/test_actuator_03_live.py"
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_KID = "dpu-quarantine-receipt-2026-01"

_REQUIRED_DIRECTIVE_FIELDS: frozenset[str] = frozenset(
    {
        "thread_id",
        "agent_svid",
        "sandbox_id",
        "reason",
        "violation_codes",
        "issued_at",
        "correlation_id",
        "nonce",
        "ttl_seconds",
    }
)


class ServerFaultMode(StrEnum):
    """Planted server protocol mutations used to verify the live suite kills defects."""

    NONE = "NONE"
    ACCEPT_DUAL_DIGESTS = "ACCEPT_DUAL_DIGESTS"  # M1
    ACCEPT_MISSING_DIGEST = "ACCEPT_MISSING_DIGEST"  # M2
    UNSIGNED_RECEIPT = "UNSIGNED_RECEIPT"  # M3a
    WRONG_RECEIPT_ENVELOPE_DIGEST = "WRONG_RECEIPT_ENVELOPE_DIGEST"  # M3b


@dataclass(frozen=True)
class _MtlsBundle:
    ca_path: Path
    server_cert_path: Path
    server_key_path: Path
    client_cert_path: Path
    client_key_path: Path


def _generate_mtls_bundle(directory: Path) -> _MtlsBundle:
    """Mint a strict X.509 v3 EC P-256 CA, localhost server cert, and client cert."""
    now = datetime.now(tz=timezone.utc)
    valid_from = now - timedelta(hours=1)
    valid_until = now + timedelta(days=1)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "CAGE Actuator 03 Test Root CA")]
    )
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    def _issue_leaf(
        common_name: str,
        eku: ExtendedKeyUsageOID,
        san_entries: list[x509.GeneralName],
    ) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            )
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_until)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return leaf_key, leaf_cert

    server_key, server_cert = _issue_leaf(
        "127.0.0.1",
        ExtendedKeyUsageOID.SERVER_AUTH,
        [
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.DNSName("localhost"),
        ],
    )
    client_key, client_cert = _issue_leaf(
        "cage-gateway-quarantine-client",
        ExtendedKeyUsageOID.CLIENT_AUTH,
        [
            x509.UniformResourceIdentifier(
                "spiffe://cluster.local/ns/cage/sa/quarantine-conformance-agent"
            )
        ],
    )

    def _write_pem(path: Path, data: bytes) -> Path:
        path.write_bytes(data)
        return path

    ca_path = _write_pem(
        directory / "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    server_cert_path = _write_pem(
        directory / "server.crt", server_cert.public_bytes(serialization.Encoding.PEM)
    )
    server_key_path = _write_pem(
        directory / "server.key",
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    client_cert_path = _write_pem(
        directory / "client.crt", client_cert.public_bytes(serialization.Encoding.PEM)
    )
    client_key_path = _write_pem(
        directory / "client.key",
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return _MtlsBundle(
        ca_path=ca_path,
        server_cert_path=server_cert_path,
        server_key_path=server_key_path,
        client_cert_path=client_cert_path,
        client_key_path=client_key_path,
    )


@dataclass
class _QuarantineServerState:
    """Mutable state and cryptographic keys for the local DPU quarantine endpoint."""

    assertion_pub: Ed25519PublicKey
    receipt_priv: Ed25519PrivateKey
    receipt_kid: str = _RECEIPT_KID
    fault_mode: ServerFaultMode = ServerFaultMode.NONE
    accepted_payloads: list[dict[str, Any]] = field(default_factory=list)
    _rule_seq: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def next_rule_id(self) -> str:
        with self._lock:
            self._rule_seq += 1
            return f"dpu-flow-rule-{self._rule_seq:04d}"

    def record_accepted(self, payload: dict[str, Any]) -> None:
        with self._lock:
            self.accepted_payloads.append(payload)


def _sign_receipt_body(
    priv_key: Ed25519PrivateKey,
    *,
    kid: str,
    unsigned_body: dict[str, Any],
) -> dict[str, Any]:
    msg = QUARANTINE_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(unsigned_body)
    sig_bytes = priv_key.sign(msg)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
    return {
        **unsigned_body,
        "signature": {
            "alg": "EdDSA",
            "kid": kid,
            "value": sig_b64,
        },
    }


def _validate_decision_digests(
    payload: dict[str, Any],
    *,
    fault_mode: ServerFaultMode,
) -> tuple[bool, str]:
    has_refusal = "refusal_proof_hash" in payload
    has_clearance = "governance_decision_digest" in payload

    for field_name in ("refusal_proof_hash", "governance_decision_digest"):
        if field_name in payload:
            val = payload[field_name]
            if not isinstance(val, str) or not _SHA256_HEX_RE.match(val):
                return False, f"invalid_sha256_hex:{field_name}"

    if has_refusal and has_clearance:
        if fault_mode is ServerFaultMode.ACCEPT_DUAL_DIGESTS:
            return True, "ok"
        return False, "mutually_exclusive_decision_digests"

    if not has_refusal and not has_clearance:
        if fault_mode is ServerFaultMode.ACCEPT_MISSING_DIGEST:
            return True, "ok"
        return False, "missing_decision_digest"

    return True, "ok"


def _make_handler_class(state: _QuarantineServerState) -> type[BaseHTTPRequestHandler]:
    class _DpuQuarantineHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            del format, args

        def _send_json(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send_json(200, {"status": "ok"})
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/dpu/quarantine":
                self._send_json(404, {"error": "not_found"})
                return

            content_len = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_len)

            # 1. Verify X-CAGE-Envelope-Digest against exact wire bytes.
            computed_digest = hashlib.sha256(raw_body).hexdigest()
            header_digest = (self.headers.get("X-CAGE-Envelope-Digest") or "").strip()
            if not header_digest or header_digest != computed_digest:
                self._send_json(401, {"error": "envelope_digest_mismatch"})
                return

            # 2. Verify X-CAGE-Quarantine-Assertion over CAGE_QUARANTINE_ASSERTION_V1: + JCS bytes.
            assertion_hdr = (
                self.headers.get("X-CAGE-Quarantine-Assertion") or ""
            ).strip()
            if not assertion_hdr:
                self._send_json(401, {"error": "missing_quarantine_assertion"})
                return
            try:
                padded = assertion_hdr + "=" * (-len(assertion_hdr) % 4)
                sig_bytes = base64.urlsafe_b64decode(padded)
                state.assertion_pub.verify(
                    sig_bytes, QUARANTINE_ASSERTION_DOMAIN_TAG + raw_body
                )
            except (InvalidSignature, ValueError):
                self._send_json(401, {"error": "invalid_quarantine_assertion"})
                return

            # 3. Parse JSON and verify RFC 8785 JCS canonical encoding.
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "malformed_json"})
                return
            if not isinstance(payload, dict):
                self._send_json(400, {"error": "json_object_required"})
                return
            if jcs_canonicalize_plan(payload) != raw_body:
                self._send_json(400, {"error": "non_canonical_jcs"})
                return

            missing_core = _REQUIRED_DIRECTIVE_FIELDS - set(payload)
            if missing_core:
                self._send_json(
                    422, {"error": "missing_fields", "fields": sorted(missing_core)}
                )
                return

            corr_hdr = (self.headers.get("X-CAGE-Correlation-ID") or "").strip()
            if not corr_hdr or corr_hdr != payload.get("correlation_id"):
                self._send_json(400, {"error": "correlation_id_mismatch"})
                return

            # 4. Enforce POAM-2026-149 / POAM-2026-166 mutual exclusion on decision digests.
            valid_digests, err_code = _validate_decision_digests(
                payload, fault_mode=state.fault_mode
            )
            if not valid_digests:
                self._send_json(422, {"error": err_code})
                return

            state.record_accepted(payload)
            rule_id = state.next_rule_id()

            if state.fault_mode is ServerFaultMode.UNSIGNED_RECEIPT:
                self._send_json(
                    200,
                    {
                        "quarantined": True,
                        "rule_id": rule_id,
                        "envelope_digest": computed_digest,
                    },
                )
                return

            receipt_digest = (
                "0" * 64
                if state.fault_mode is ServerFaultMode.WRONG_RECEIPT_ENVELOPE_DIGEST
                else computed_digest
            )
            signed_receipt = _sign_receipt_body(
                state.receipt_priv,
                kid=state.receipt_kid,
                unsigned_body={
                    "quarantined": True,
                    "rule_id": rule_id,
                    "envelope_digest": receipt_digest,
                },
            )
            self._send_json(200, signed_receipt)

    return _DpuQuarantineHandler


@dataclass
class _RunningDpuHarness:
    endpoint: str
    manifest_url: str
    signing_key_hex: str
    mtls: _MtlsBundle
    state: _QuarantineServerState

    def env_vars(self) -> dict[str, str]:
        return {
            "ACTUATOR_03_ENDPOINT": self.endpoint,
            "ACTUATOR_03_CERT_PATH": str(self.mtls.client_cert_path),
            "ACTUATOR_03_KEY_PATH": str(self.mtls.client_key_path),
            "ACTUATOR_03_CA_PATH": str(self.mtls.ca_path),
            "ACTUATOR_03_RECEIPT_KEY_MANIFEST_URL": self.manifest_url,
            "ACTUATOR_03_SIGNING_KEY_HEX": self.signing_key_hex,
        }


@contextmanager
def _running_dpu_quarantine_server(
    tmp_path: Path,
    *,
    fault_mode: ServerFaultMode = ServerFaultMode.NONE,
) -> Iterator[_RunningDpuHarness]:
    mtls = _generate_mtls_bundle(tmp_path)
    assertion_priv = Ed25519PrivateKey.generate()
    receipt_priv = Ed25519PrivateKey.generate()

    receipt_pub_x = (
        base64.urlsafe_b64encode(receipt_priv.public_key().public_bytes_raw())
        .decode("ascii")
        .rstrip("=")
    )
    jwks_path = tmp_path / "receipt_jwks.json"
    jwks_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "use": "sig",
                        "alg": "EdDSA",
                        "kid": _RECEIPT_KID,
                        "x": receipt_pub_x,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    state = _QuarantineServerState(
        assertion_pub=assertion_priv.public_key(),
        receipt_priv=receipt_priv,
        fault_mode=fault_mode,
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler_class(state))
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    server_ssl.verify_mode = ssl.CERT_REQUIRED
    server_ssl.load_verify_locations(cafile=str(mtls.ca_path))
    server_ssl.load_cert_chain(
        certfile=str(mtls.server_cert_path),
        keyfile=str(mtls.server_key_path),
    )
    httpd.socket = server_ssl.wrap_socket(httpd.socket, server_side=True)

    port = httpd.server_address[1]
    thread = threading.Thread(
        target=httpd.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    try:
        yield _RunningDpuHarness(
            endpoint=f"https://127.0.0.1:{port}",
            manifest_url=jwks_path.resolve().as_uri(),
            signing_key_hex=assertion_priv.private_bytes_raw().hex(),
            mtls=mtls,
            state=state,
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5.0)


@asynccontextmanager
async def _configured_live_components(
    monkeypatch: pytest.MonkeyPatch,
    harness: _RunningDpuHarness,
) -> AsyncIterator[
    tuple[
        live_suite.Actuator03LiveConfig,
        Actuator03Adapter,
        Ed25519KeyManifestClient,
    ]
]:
    for key, value in harness.env_vars().items():
        monkeypatch.setenv(key, value)
    config = live_suite.load_live_config_or_skip()
    signer = live_suite.resolve_live_signer()
    manifest_client = Ed25519KeyManifestClient(
        config.receipt_key_manifest_url,
        timeout_seconds=5.0,
    )
    http_client = live_suite.build_live_http_client(config)
    try:
        adapter = Actuator03Adapter(
            endpoint=config.endpoint,
            signer=signer,
            http_client=http_client,
            receipt_key_resolver=manifest_client,
            require_signed_receipts=True,
        )
        yield config, adapter, manifest_client
    finally:
        await http_client.aclose()


def _run_live_suite_subprocess(
    env_overrides: dict[str, str | None],
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    for var in (*live_suite.REQUIRED_ENV_VARS, "ACTUATOR_03_SIGNING_KEY_HEX"):
        env.pop(var, None)
    for key, value in env_overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    env["CAGE_ENV"] = "test"
    env["LANGSMITH_TRACING"] = "false"
    env["LANGCHAIN_TRACING_V2"] = "false"

    argv = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-n",
        "0",
        "-p",
        "no:cacheprovider",
        "-p",
        "tests.fixtures.require_live",
        "--run-live-external",
        _LIVE_SUITE_REL_PATH,
    ]
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv,
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.asyncio
async def test_live_suite_all_four_scenarios_pass_against_compliant_mtls_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All 4 live conformance tests pass end-to-end against a compliant mTLS DPU server."""
    with _running_dpu_quarantine_server(tmp_path) as harness:
        async with _configured_live_components(monkeypatch, harness) as (
            config,
            adapter,
            manifest_client,
        ):
            signer = live_suite.resolve_live_signer()
            http_client = live_suite.build_live_http_client(config)
            try:
                await live_suite.test_live_health_and_receipt_key_manifest(
                    adapter, manifest_client
                )
                await live_suite.test_live_refusal_triggered_quarantine_directive(
                    adapter
                )
                await live_suite.test_live_clearance_bridged_quarantine_actuation(
                    adapter
                )
                await live_suite.test_live_partner_rejects_malformed_dual_or_missing_digest_wire_body(
                    config, http_client, signer
                )
            finally:
                await http_client.aclose()

        # Confirm the server accepted exactly the 2 well-formed directives (1 refusal,
        # 1 clearance) and rejected both malformed bodies from test 4.
        assert len(harness.state.accepted_payloads) == 2
        first, second = harness.state.accepted_payloads
        assert (
            "refusal_proof_hash" in first and "governance_decision_digest" not in first
        )
        assert (
            "governance_decision_digest" in second
            and "refusal_proof_hash" not in second
        )


@pytest.mark.asyncio
async def test_mutant_m1_server_accepting_dual_digests_is_killed_by_test_4(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M1: A server that accepts BOTH digest fields simultaneously is caught by test 4."""
    with _running_dpu_quarantine_server(
        tmp_path, fault_mode=ServerFaultMode.ACCEPT_DUAL_DIGESTS
    ) as harness:
        for key, value in harness.env_vars().items():
            monkeypatch.setenv(key, value)
        config = live_suite.load_live_config_or_skip()
        signer = live_suite.resolve_live_signer()
        http_client = live_suite.build_live_http_client(config)
        try:
            with pytest.raises(
                AssertionError,
                match="carrying both refusal_proof_hash and governance_decision_digest",
            ):
                await live_suite.test_live_partner_rejects_malformed_dual_or_missing_digest_wire_body(
                    config, http_client, signer
                )
        finally:
            await http_client.aclose()


@pytest.mark.asyncio
async def test_mutant_m2_server_accepting_missing_digest_is_killed_by_test_4(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M2: A server that accepts NEITHER digest field is caught by test 4."""
    with _running_dpu_quarantine_server(
        tmp_path, fault_mode=ServerFaultMode.ACCEPT_MISSING_DIGEST
    ) as harness:
        for key, value in harness.env_vars().items():
            monkeypatch.setenv(key, value)
        config = live_suite.load_live_config_or_skip()
        signer = live_suite.resolve_live_signer()
        http_client = live_suite.build_live_http_client(config)
        try:
            with pytest.raises(
                AssertionError,
                match="missing both refusal_proof_hash and governance_decision_digest",
            ):
                await live_suite.test_live_partner_rejects_malformed_dual_or_missing_digest_wire_body(
                    config, http_client, signer
                )
        finally:
            await http_client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault_mode", "expected_verification", "expected_finding_code"),
    [
        (
            ServerFaultMode.UNSIGNED_RECEIPT,
            ReceiptVerification.UNVERIFIED,
            "SIGNED_RECEIPT_REQUIRED",
        ),
        (
            ServerFaultMode.WRONG_RECEIPT_ENVELOPE_DIGEST,
            ReceiptVerification.INVALID,
            "RECEIPT_ENVELOPE_MISMATCH",
        ),
    ],
)
async def test_mutant_m3_unsigned_or_mismatched_receipt_fails_tests_2_and_3_with_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_mode: ServerFaultMode,
    expected_verification: ReceiptVerification,
    expected_finding_code: str,
) -> None:
    """M3: Unsigned or wrong-envelope_digest receipts produce UNKNOWN and fail tests 2 & 3."""
    with _running_dpu_quarantine_server(tmp_path, fault_mode=fault_mode) as harness:
        async with _configured_live_components(monkeypatch, harness) as (
            _config,
            adapter,
            _manifest_client,
        ):
            directive = QuarantineDirective(
                thread_id="thread-m3-refusal",
                agent_svid="spiffe://cluster.local/ns/cage/sa/quarantine-conformance-agent",
                sandbox_id="sbx-m3",
                reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
                violation_codes=("CBF_SAFETY_BARRIER_BREACH",),
                issued_at=1710000000,
                correlation_id="11111111-2222-4333-8444-555555555555",
                refusal_proof_hash=hashlib.sha256(b"m3-refusal").hexdigest(),
                nonce="a" * 32,
                ttl_seconds=300,
            )
            q_receipt = await adapter.quarantine_workload(directive)
            assert q_receipt.quarantined is False
            assert q_receipt.outcome is ActuationOutcome.UNKNOWN
            assert q_receipt.verification is expected_verification
            assert any(
                f.get("code") == expected_finding_code for f in q_receipt.findings
            )

            clearance = ExecutionClearance(
                thread_id="thread-m3-clearance",
                decision="ALLOW",
                decision_path="DIRECT",
                action="quarantine.isolate_workload",
                target="sbx-m3",
                operator_urn="spiffe://cluster.local/ns/cage/sa/quarantine-conformance-agent",
                issued_at=1710000000,
                issued_at_provenance="CONSTRUCTION_TIME",
                correlation_id="66666666-7777-4888-8999-aaaaaaaaaaaa",
                correlation_id_source="INGRESS_MINTED",
                governance_decision_digest=hashlib.sha256(b"m3-seal").hexdigest(),
                opa_input_digest=hashlib.sha256(b"m3-opa").hexdigest(),
                nonce="b" * 32,
                executor_id="actuator_03",
                ttl_seconds=30,
            )
            a_receipt = await adapter.actuate(clearance)
            assert a_receipt.accepted is False
            assert a_receipt.outcome is ActuationOutcome.UNKNOWN
            assert a_receipt.verification is expected_verification

            with pytest.raises(
                AssertionError, match="outcome=ActuationOutcome.UNKNOWN"
            ):
                await live_suite.test_live_refusal_triggered_quarantine_directive(
                    adapter
                )

            with pytest.raises(
                AssertionError, match="outcome=ActuationOutcome.UNKNOWN"
            ):
                await live_suite.test_live_clearance_bridged_quarantine_actuation(
                    adapter
                )


def test_mutant_m4_require_live_fails_closed_when_endpoint_missing_and_passes_when_set(
    tmp_path: Path,
) -> None:
    """M4: Under require_live, missing ACTUATOR_03_ENDPOINT fails the session; full config passes."""
    with _running_dpu_quarantine_server(tmp_path) as harness:
        missing_endpoint_env: dict[str, str | None] = {
            **harness.env_vars(),
            "ACTUATOR_03_ENDPOINT": None,
        }
        failed_run = _run_live_suite_subprocess(missing_endpoint_env)
        assert failed_run.returncode == int(pytest.ExitCode.TESTS_FAILED), (
            f"Expected TESTS_FAILED (1) when ACTUATOR_03_ENDPOINT is unset:\n"
            f"STDOUT:\n{failed_run.stdout}\nSTDERR:\n{failed_run.stderr}"
        )
        assert (
            "Actuator 03 live credentials not configured — missing: ACTUATOR_03_ENDPOINT"
            in failed_run.stdout
        )
        assert "0 passed, 4 not run (FAILED: every selected test must run)" in (
            failed_run.stdout
        )

        passing_run = _run_live_suite_subprocess(dict(harness.env_vars()))
        assert passing_run.returncode == 0, (
            f"Expected exit 0 when all Actuator 03 live credentials are configured:\n"
            f"STDOUT:\n{passing_run.stdout}\nSTDERR:\n{passing_run.stderr}"
        )
        assert "4 passed, 0 not run (ok)" in passing_run.stdout
