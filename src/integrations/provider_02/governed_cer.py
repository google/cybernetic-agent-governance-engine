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

"""Provider 02 governed-execution CER sealing and attestation-receipt verification.

Provider 02 attests a CAGE ``AttestationBundle`` only after it is sealed into a
``cer.governed.execution.v1`` certificate (profile ``cage-governance-v1``,
CER version ``0.1``) and submitted to ``POST /api/attest``. This module is the
wire contract on CAGE's side:

``seal_governed_execution()``
    Builds the CER. ``certificateHash`` is ``sha256:`` + SHA-256 of the RFC 8785
    JCS canonicalization of every member except ``certificateHash``.
    ``createdAt`` is the bundle's ``completedAt``: the node rejects a second
    submission of the same ``bundleId`` with different canonical content
    (``EXECUTION_MUTATION_DETECTED``), so the seal must be deterministic.

``verify_attestation()``
    Verifies the node's response fail-closed. The node's own ``ok`` flag is
    never trusted on its own: both Ed25519 signatures are checked against a key
    resolved by ``kid`` from the independently fetched key manifest, and every
    signed value is bound to the CER CAGE actually sent.

    * ``signature`` covers ``JCS(receipt)``.
    * ``verificationEnvelopeSignature`` covers
      ``JCS({"bundle": <signedFields.bundle of CAGE's CER>,
      "attestation": <signedFields.attestation of verificationEnvelope.attestation>})``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.graph_topology import GraphTopology

CER_BUNDLE_TYPE = "cer.governed.execution.v1"
CER_VERSION = "0.1"
CAGE_GOVERNANCE_PROFILE: dict[str, Any] = {
    "id": "cage-governance-v1",
    "version": "1",
    "contract": "urn:cage:governance:v1:attestation-bundle",
    "source": {"system": "CAGE", "profile": "provider_02"},
}
PROTECTED_FIELDS: tuple[str, ...] = (
    "bundleType",
    "createdAt",
    "version",
    "profile",
    "evidence",
)
PROTECTED_SET: dict[str, Any] = {
    "stabilitySchemeId": "jcs-v1",
    "protectedSetId": "nexart.governed.execution.v1.protected-set.v1",
    "protectedFields": list(PROTECTED_FIELDS),
}
RECEIPT_ALGORITHM = "Ed25519"
RECEIPT_CANONICALIZATION = "jcs"

# Every governedVerification check that must read "valid". topologyValidation
# is checked separately because "not-supplied" is legitimate without topology.
_REQUIRED_VALID_CHECKS = (
    "certificateIntegrity",
    "cageSchemaValidity",
    "causalGraphValidity",
    "resourceSafety",
)
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)

KeyResolver = Callable[[str], Ed25519PublicKey | None]


class GovernedCerError(ValueError):
    """The bundle cannot be sealed into a governed-execution CER."""


@dataclass(frozen=True)
class AttestationVerdict:
    """Outcome of a Provider 02 attestation, as verified by CAGE.

    ``verified`` is True only when every check in ``verify_attestation()``
    passed. A failed verdict carries a stable ``code`` and human ``error``.
    """

    verified: bool
    certificate_hash: str = ""
    code: str = ""
    error: str = ""
    attestation_id: str = ""
    kid: str = ""
    verification_url: str = ""
    governed_verification: Mapping[str, Any] = field(default_factory=dict)
    receipt: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def reject(
        cls, code: str, error: str, certificate_hash: str = ""
    ) -> AttestationVerdict:
        return cls(
            verified=False, code=code, error=error, certificate_hash=certificate_hash
        )


def topology_to_wire(topology: GraphTopology) -> dict[str, Any]:
    """Serialize a kernel ``GraphTopology`` to the Provider 02 wire shape."""
    wire: dict[str, Any] = {
        "nodes": sorted(topology.nodes),
        "parentEdges": {
            node: list(parents) for node, parents in topology.parent_edges.items()
        },
        "terminalNode": topology.terminal_node,
        "attestationNodes": sorted(topology.attestation_nodes),
    }
    if topology.interrupt_node is not None:
        wire["interruptNode"] = topology.interrupt_node
    return wire


def _sha256_jcs(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonicalize_plan(dict(value))).hexdigest()


def seal_governed_execution(
    bundle: Mapping[str, Any], topology: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Seal ``bundle`` (and optional wire ``topology``) into a governed CER.

    Raises:
        GovernedCerError: ``completedAt`` is missing or not RFC 3339.
    """
    created_at = bundle.get("completedAt")
    if not isinstance(created_at, str) or not _RFC3339.match(created_at):
        raise GovernedCerError(
            "bundle.completedAt must be an RFC 3339 timestamp; it is the "
            "deterministic CER createdAt"
        )
    evidence: dict[str, Any] = {"bundle": dict(bundle)}
    if topology is not None:
        evidence["topology"] = dict(topology)
    unsigned = {
        "bundleType": CER_BUNDLE_TYPE,
        "createdAt": created_at,
        "version": CER_VERSION,
        "profile": CAGE_GOVERNANCE_PROFILE,
        "evidence": evidence,
        "protectedSet": PROTECTED_SET,
    }
    return {**unsigned, "certificateHash": _sha256_jcs(unsigned)}


def certificate_hash_of(cer: Mapping[str, Any]) -> str:
    """Recompute a CER's ``certificateHash`` from its protected members."""
    return _sha256_jcs({k: v for k, v in cer.items() if k != "certificateHash"})


def _verify_ed25519(
    key: Ed25519PublicKey, signature_b64url: Any, message: bytes
) -> bool:
    import base64

    if not isinstance(signature_b64url, str) or not signature_b64url:
        return False
    try:
        signature = base64.urlsafe_b64decode(
            signature_b64url + "=" * (-len(signature_b64url) % 4)
        )
        key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_attestation(
    cer: Mapping[str, Any],
    response: Mapping[str, Any],
    resolve_key: KeyResolver,
    *,
    topology_supplied: bool,
) -> AttestationVerdict:
    """Verify a ``POST /api/attest`` response against the CER CAGE submitted.

    Fails closed on any missing, mismatched or unverifiable member. The public
    key comes only from ``resolve_key(kid)``; nothing in ``response`` can supply
    or override it.
    """
    expected_hash = str(cer.get("certificateHash", ""))
    if certificate_hash_of(cer) != expected_hash:
        return AttestationVerdict.reject(
            "CER_HASH_INCONSISTENT",
            "submitted CER does not hash to its certificateHash",
        )

    def reject(code: str, error: str) -> AttestationVerdict:
        return AttestationVerdict.reject(code, error, expected_hash)

    if response.get("ok") is not True:
        return reject("NODE_NOT_OK", "node response is not ok")

    receipt = response.get("receipt")
    attestation = response.get("attestation")
    envelope = response.get("verificationEnvelope")
    if not (
        isinstance(receipt, Mapping)
        and isinstance(attestation, Mapping)
        and isinstance(envelope, Mapping)
    ):
        return reject("RESPONSE_INCOMPLETE", "receipt, attestation or envelope missing")
    env_attestation = envelope.get("attestation")
    signed_fields = envelope.get("signedFields")
    if not isinstance(env_attestation, Mapping) or not isinstance(
        signed_fields, Mapping
    ):
        return reject("RESPONSE_INCOMPLETE", "verificationEnvelope is incomplete")

    for where, value in (
        ("response", response.get("certificateHash")),
        ("receipt", receipt.get("certificateHash")),
        ("attestation", attestation.get("certificateHash")),
    ):
        if value != expected_hash:
            return reject(
                "CERTIFICATE_HASH_MISMATCH",
                f"{where}.certificateHash does not match the submitted CER",
            )

    kid = response.get("kid")
    if not isinstance(kid, str) or not kid:
        return reject("KID_MISSING", "response carries no kid")
    for where, value in (
        ("receipt.attestorKeyId", receipt.get("attestorKeyId")),
        ("verificationEnvelope.kid", envelope.get("kid")),
        ("verificationEnvelope.attestation.kid", env_attestation.get("kid")),
    ):
        if value != kid:
            return reject("KID_MISMATCH", f"{where} does not match kid {kid!r}")
    if envelope.get("algorithm") != RECEIPT_ALGORITHM:
        return reject("ALGORITHM_UNSUPPORTED", "verificationEnvelope.algorithm")
    if envelope.get("canonicalization") != RECEIPT_CANONICALIZATION:
        return reject(
            "CANONICALIZATION_UNSUPPORTED", "verificationEnvelope.canonicalization"
        )

    attestation_id = response.get("attestationId")
    if not attestation_id or not (
        attestation_id
        == receipt.get("attestationId")
        == attestation.get("attestationId")
        == env_attestation.get("attestationId")
    ):
        return reject("ATTESTATION_ID_MISMATCH", "attestationId differs across members")

    key = resolve_key(kid)
    if key is None:
        return reject("UNKNOWN_KEY", f"kid {kid!r} not in the trusted key manifest")

    if not _verify_ed25519(
        key, response.get("signature"), jcs_canonicalize_plan(dict(receipt))
    ):
        return reject("RECEIPT_SIGNATURE_INVALID", "receipt signature does not verify")

    signed_bundle = signed_fields.get("bundle")
    signed_attestation = signed_fields.get("attestation")
    if not isinstance(signed_bundle, list) or not isinstance(signed_attestation, list):
        return reject("RESPONSE_INCOMPLETE", "signedFields is incomplete")
    required = {*PROTECTED_FIELDS, "protectedSet"}
    if not required.issubset(signed_bundle):
        return reject(
            "ENVELOPE_SCOPE_INSUFFICIENT",
            f"envelope does not sign {sorted(required - set(signed_bundle))}",
        )
    if any(f not in cer for f in signed_bundle) or any(
        f not in env_attestation for f in signed_attestation
    ):
        return reject("ENVELOPE_SCOPE_INVALID", "envelope signs a field that is absent")
    envelope_message = jcs_canonicalize_plan(
        {
            "bundle": {f: cer[f] for f in signed_bundle},
            "attestation": {f: env_attestation[f] for f in signed_attestation},
        }
    )
    if not _verify_ed25519(
        key, response.get("verificationEnvelopeSignature"), envelope_message
    ):
        return reject(
            "ENVELOPE_SIGNATURE_INVALID",
            "verification envelope signature does not verify",
        )

    checks = response.get("governedVerification")
    if not isinstance(checks, Mapping):
        return reject("GOVERNED_VERIFICATION_MISSING", "governedVerification missing")
    for name in _REQUIRED_VALID_CHECKS:
        if checks.get(name) != "valid":
            return reject("GOVERNED_CHECK_FAILED", f"{name}={checks.get(name)!r}")
    expected_topology = "valid" if topology_supplied else "not-supplied"
    if checks.get("topologyValidation") != expected_topology:
        return reject(
            "GOVERNED_CHECK_FAILED",
            f"topologyValidation={checks.get('topologyValidation')!r}, "
            f"expected {expected_topology!r}",
        )

    return AttestationVerdict(
        verified=True,
        certificate_hash=expected_hash,
        attestation_id=str(attestation_id),
        kid=kid,
        verification_url=str(response.get("verificationUrl", "")),
        governed_verification=dict(checks),
        receipt=dict(receipt),
    )
