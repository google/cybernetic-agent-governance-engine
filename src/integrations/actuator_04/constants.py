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

"""Cryptographic domain tags, headers, and protocol constants for actuator_04.

All identifiers are vendor-anonymized per CAGE AGENTS.md (Generic in Code,
Specific in Prose).
"""

from __future__ import annotations

ACTUATOR_04_ID: str = "actuator_04"
ENFORCEMENT_PLANE_HOST_OS_KERNEL: str = "HOST_OS_KERNEL"

# Preimage domain separation tags (RFC 8785 JCS canonicalization follows tag)
QUARANTINE_ASSERTION_DOMAIN_TAG: bytes = b"CAGE_QUARANTINE_ASSERTION_V1:"
QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG: bytes = b"CAGE_QUARANTINE_RELEASE_V1:"
QUARANTINE_RECEIPT_DOMAIN_TAG: bytes = b"CAGE_QUARANTINE_RECEIPT_V1:"
QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG: bytes = b"CAGE_QUARANTINE_RELEASE_RECEIPT_V1:"
ATTESTATION_RECEIPT_DOMAIN_TAG: bytes = b"CAGE_ATTESTATION_RECEIPT_V1:"
OCSF_EVENT_DOMAIN_TAG: bytes = b"CAGE_OCSF_EVENT_V1:"
NORMATIVE_VALIDATION_DOMAIN_TAG: bytes = b"CAGE_CONFORMAL_VALIDATION_V1:"
CONFORMAL_VALIDATION_DOMAIN_TAG: bytes = NORMATIVE_VALIDATION_DOMAIN_TAG

# HTTP Headers
HEADER_ENVELOPE_DIGEST: str = "X-CAGE-Envelope-Digest"
HEADER_QUARANTINE_ASSERTION: str = "X-CAGE-Quarantine-Assertion"
HEADER_QUARANTINE_RELEASE: str = "X-CAGE-Quarantine-Release"
HEADER_CORRELATION_ID: str = "X-CAGE-Correlation-ID"
HEADER_SIGNER_KID: str = "X-CAGE-Signer-Kid"
HEADER_ROUTING_SEAL: str = "X-CAGE-Routing-Seal"

# Environment Variable Names
ENV_ENDPOINT: str = "ACTUATOR_04_ENDPOINT"
ENV_NODE_ENDPOINTS: str = "ACTUATOR_04_NODE_ENDPOINTS"
ENV_CERT_PATH: str = "ACTUATOR_04_CERT_PATH"
ENV_KEY_PATH: str = "ACTUATOR_04_KEY_PATH"
ENV_CA_PATH: str = "ACTUATOR_04_CA_PATH"
ENV_RECEIPT_KEY_MANIFEST_URL: str = "ACTUATOR_04_RECEIPT_KEY_MANIFEST_URL"
ENV_REQUIRE_SIGNED_RECEIPTS: str = "ACTUATOR_04_REQUIRE_SIGNED_RECEIPTS"
ENV_EXPECTED_TPM_PCR_QUOTE: str = "ACTUATOR_04_EXPECTED_TPM_PCR_QUOTE"
ENV_CONFORMAL_ALPHA: str = "ACTUATOR_04_CONFORMAL_ALPHA"

# Cryptographic Sizes & Standards
ED25519_SIGNATURE_BYTES: int = 64
SHA256_HEX_LENGTH: int = 64

# OCSF Schema Constants
ALLOWED_OCSF_CLASS_UIDS: frozenset[int] = frozenset({1001, 1007, 4001})
MAX_OCSF_METADATA_BYTES: int = 64 * 1024
