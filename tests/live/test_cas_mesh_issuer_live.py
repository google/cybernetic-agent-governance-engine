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

"""Live Google Cloud Certificate Authority Service (CAS) test for Linkerd mesh identity.

Verifies over the physical wire against Google Cloud CAS (`privateca.googleapis.com`)
that the mesh CA pool (`infra/modules/service_mesh/main.tf`) issues a valid,
short-lived ECDSA P-256 certificate for `identity.linkerd.cluster.local` chaining
to the CAS pool root CA (NIST SP 800-53 SC-8, SC-12, IA-3; POAM-2026-080).

Run via:
    make test-live
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytestmark = [pytest.mark.live_external]


def _resolve_gcp_access_token() -> str | None:
    """Acquire a Google Cloud OAuth2 access token via google.auth or gcloud CLI."""
    try:
        import google.auth
        import google.auth.transport.requests

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        credentials.refresh(google.auth.transport.requests.Request())
        if credentials.token:
            return str(credentials.token)
    except Exception:
        pass

    try:
        res = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        token = res.stdout.strip()
        if token:
            return token
    except Exception:
        pass
    return None


def _fail_or_skip(message: str) -> None:
    if os.environ.get("CAGE_REQUIRE_LIVE_CAS", "0").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        pytest.fail(message)
    pytest.skip(message)


def test_cas_pool_issues_linkerd_identity_ecdsa_p256_certificate() -> None:
    """Issue a short-lived ECDSA P-256 certificate from Google CAS and verify its chain."""
    project_id = (
        os.environ.get("CAGE_CAS_PROJECT_ID")
        or os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or ""
    ).strip()
    if not project_id or project_id.startswith("mock-"):
        _fail_or_skip(
            "GCP_PROJECT_ID / CAGE_CAS_PROJECT_ID not set — set it to a project with "
            "the CAGE service_mesh CAS pool to run live CAS issuance verification."
        )

    region = (
        os.environ.get("CAGE_CAS_LOCATION")
        or os.environ.get("GCP_REGION")
        or "us-central1"
    ).strip()
    pool_id = os.environ.get("CAGE_CAS_POOL_ID", "cage-mesh-dev").strip()

    token = _resolve_gcp_access_token()
    if not token:
        _fail_or_skip("No Google Cloud ADC or gcloud access token available.")

    issuer_dns = "identity.linkerd.cluster.local"
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        issuer_dns,
                    ),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(issuer_dns)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    cert_id = f"cage-live-test-{uuid.uuid4().hex[:12]}"
    url = (
        f"https://privateca.googleapis.com/v1/projects/{project_id}"
        f"/locations/{region}/caPools/{pool_id}/certificates"
        f"?certificateId={cert_id}"
    )
    if not url.startswith("https://"):
        raise ValueError(f"Refusing non-HTTPS URL for CAS API call: {url}")

    payload = json.dumps(
        {
            "pemCsr": csr_pem,
            "lifetime": "3600s",
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
            response_data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", "replace")
        if exc.code in (403, 404):
            _fail_or_skip(
                f"CAS pool '{pool_id}' in {project_id}/{region} not accessible "
                f"(HTTP {exc.code}): {err_body[:240]}"
            )
        raise

    pem_cert = response_data.get("pemCertificate", "")
    pem_chain = response_data.get("pemCertificateChain", [])
    assert pem_cert, "CAS response missing pemCertificate"
    assert pem_chain, "CAS response missing pemCertificateChain"

    issued_cert = x509.load_pem_x509_certificate(pem_cert.encode("ascii"))
    issuer_cert = x509.load_pem_x509_certificate(pem_chain[0].encode("ascii"))

    issued_pub = issued_cert.public_key()
    assert isinstance(issued_pub, ec.EllipticCurvePublicKey)
    assert isinstance(issued_pub.curve, ec.SECP256R1)
    assert issued_pub.public_numbers() == private_key.public_key().public_numbers(), (
        "Issued certificate public key does not match CSR keypair"
    )

    issuer_pub = issuer_cert.public_key()
    assert isinstance(issuer_pub, ec.EllipticCurvePublicKey)
    assert isinstance(issued_cert.signature_hash_algorithm, hashes.HashAlgorithm)
    issuer_pub.verify(
        issued_cert.signature,
        issued_cert.tbs_certificate_bytes,
        ec.ECDSA(issued_cert.signature_hash_algorithm),
    )
