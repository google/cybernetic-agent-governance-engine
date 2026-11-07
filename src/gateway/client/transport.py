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

"""mTLS transport configuration for secure client connections.

Fail-closed: Missing certificate files raise FileNotFoundError, and
half-configured client certificate/key pairs raise ValueError. Note that
channel TLS/mTLS protects only the point-to-point transport hop and does NOT
substitute for end-to-end GovernanceEnvelope.signature verification.
"""

import importlib.util
import ssl
from pathlib import Path

import httpx

# Check for optional HTTP/2 support (h2 package)
_HTTP2_AVAILABLE = importlib.util.find_spec("h2") is not None


def create_mtls_transport(
    cert_path: str | None = None,
    key_path: str | None = None,
    ca_path: str | None = None,
) -> httpx.AsyncHTTPTransport:
    """Create HTTP/2-enabled async transport with optional mTLS.

    Security Note:
        Channel TLS/mTLS configured here protects only the point-to-point
        transport channel and does NOT substitute for end-to-end
        ``GovernanceEnvelope.signature`` verification.

    Args:
        cert_path: Path to client certificate PEM file (optional)
        key_path: Path to client private key PEM file (optional)
        ca_path: Path to CA certificate bundle for server verification (optional)

    Returns:
        Configured httpx.AsyncHTTPTransport instance

    Raises:
        ValueError: If only one of cert_path or key_path is supplied
        FileNotFoundError: If mTLS paths are supplied but files do not exist (fail-closed)
    """
    if (cert_path is None) != (key_path is None):
        raise ValueError(
            "Both cert_path and key_path must be provided together for mutual TLS"
        )

    if cert_path is not None:
        cert_file = Path(cert_path)
        if not cert_file.exists():
            raise FileNotFoundError(f"Client certificate not found: {cert_path}")

    if key_path is not None:
        key_file = Path(key_path)
        if not key_file.exists():
            raise FileNotFoundError(f"Client private key not found: {key_path}")

    if ca_path is not None:
        ca_file = Path(ca_path)
        if not ca_file.exists():
            raise FileNotFoundError(f"CA certificate bundle not found: {ca_path}")

    verify: bool | ssl.SSLContext | str
    if cert_path or key_path or ca_path:
        ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=ca_path,
        )
        if cert_path and key_path:
            ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        verify = ssl_context
    else:
        verify = True

    return httpx.AsyncHTTPTransport(http2=_HTTP2_AVAILABLE, verify=verify)
