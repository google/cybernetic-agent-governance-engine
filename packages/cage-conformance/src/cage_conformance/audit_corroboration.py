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

"""Bidirectional Cloud Audit Log corroboration for CAGE HSM-signed artifacts.

Stdlib-only verifier for ``AS-6`` (NIST SP 800-53 AU-2, AU-6, AU-9, AU-10,
AU-12, SC-12, SI-7; ``POAM-2026-169`` Instance 11, ``POAM-2026-192``,
``POAM-2026-197``). It checks four properties:

1. **Artifact -> Cloud KMS ``AsymmetricSign``.** Every signed artifact must
   consume a distinct, successful ``AsymmetricSign`` Data Access record on the
   same key (and the same key version when the artifact names one) whose
   ``protoPayload.request.digest.sha256`` equals the base64 SHA-256 of the
   artifact's exact signing preimage, logged within ``max_skew_seconds`` of
   the artifact's own timestamp.
2. **Cloud KMS ``AsymmetricSign`` -> artifact.** Every successful
   ``AsymmetricSign`` on a corroborated key family must be consumed by a
   supplied artifact. An unconsumed call is a signature over something the
   archive does not hold: rogue use of the key, or a decision that was never
   recorded.
3. **Caller isolation.** Every ``AsymmetricSign`` on ``gateway-seal``,
   ``compliance-evidence``, or ``reconciler-snapshot`` must come from that
   key's single workload service account and succeed, whether or not its key
   family is corroborated.
4. **Control-plane mutations.** Admin Activity records that change KMS keys,
   WORM buckets, IAM, audit sinks, the GKE cluster, or any object in the
   ``governance-stack`` namespace (plus cluster-scoped RBAC and admission
   webhooks) must come from a trusted deployer principal.

Signing preimages (Cloud KMS logs the RFC 4648 base64 SHA-256 of these bytes):

========================================  ===================  =========================================
Artifact                                  Key                  Signing preimage
========================================  ===================  =========================================
``cage-evidence-batch/1`` attestation     compliance-evidence  RFC 8785 JCS of the attestation without
                                                               ``signature``
Governance decision record (SignedRecord) gateway-seal         RFC 8785 JCS of ``payload``
Routing seal (compact JWS)                gateway-seal         ASCII JWS signing input
                                                               ``<b64url header>.<b64url payload>``
Ground-truth snapshot                     reconciler-snapshot  RFC 8785 JCS of ``snapshot_signing_payload``
                                                               (source, state_scalar, verified_at,
                                                               sequence, settled_through)
Reconciliation discrepancy fence          reconciler-snapshot  RFC 8785 JCS of the fence without
                                                               ``signature``, ``kms_key_id``,
                                                               ``signing_algorithm``
========================================  ===================  =========================================

The verifier recomputes every digest from the artifact body. It never trusts a
digest, key family, or caller an artifact asserts about itself, and an artifact
whose preimage or timestamp cannot be reconstructed fails closed
(``UNVERIFIABLE_ARTIFACT``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import math
import re
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TextIO

from .stream_invariants import jcs_bytes

AUDIT_CORROBORATION_SCHEMA_VERSION = "cage-audit-corroboration-report/1"

GATEWAY_SEAL_KEY = "gateway-seal"
COMPLIANCE_EVIDENCE_KEY = "compliance-evidence"
RECONCILER_SNAPSHOT_KEY = "reconciler-snapshot"

KNOWN_SIGNING_KEYS: frozenset[str] = frozenset(
    {GATEWAY_SEAL_KEY, COMPLIANCE_EVIDENCE_KEY, RECONCILER_SNAPSHOT_KEY}
)

EVIDENCE_BATCH_SCHEMA = "cage-evidence-batch/1"
DISCREPANCY_FENCE_TYPE = "RECONCILIATION_DISCREPANCY_FENCE"

EVIDENCE_BATCH_ARTIFACT = "evidence-batch-attestation"
GOVERNANCE_RECORD_ARTIFACT = "governance-record"
ROUTING_SEAL_ARTIFACT = "routing-seal"
RECONCILER_SNAPSHOT_ARTIFACT = "reconciler-snapshot"
DISCREPANCY_FENCE_ARTIFACT = "discrepancy-fence"

#: Kubernetes namespace whose objects form the governance posture.
GOVERNANCE_NAMESPACE = "governance-stack"

DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300.0

#: Workload service-account email prefix per signing key (``kms_signing.tf``).
#: Prefix matching accepts any project; pass
#: :func:`expected_key_callers_for_project` to pin exact emails.
DEFAULT_EXPECTED_KEY_CALLERS: Mapping[str, str] = {
    GATEWAY_SEAL_KEY: "cage-gateway@",
    COMPLIANCE_EVIDENCE_KEY: "cage-compliance-bridge@",
    RECONCILER_SNAPSHOT_KEY: "cage-reconciler@",
}

_KMS_RESOURCE_RE = re.compile(
    r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/(?P<key>[^/]+)"
    r"(?:/cryptoKeyVersions/[^/]+)?"
)

_RFC3339_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<zone>[Zz]|[+-]\d{2}:\d{2})$"
)

_EVIDENCE_SIGNATURE_FIELDS: frozenset[str] = frozenset({"signature"})
_FENCE_SIGNATURE_FIELDS: frozenset[str] = frozenset(
    {"signature", "kms_key_id", "signing_algorithm"}
)
_SNAPSHOT_FIELDS: tuple[str, ...] = (
    "source",
    "state_scalar",
    "verified_at",
    "sequence",
)
_SEAL_FIELDS: tuple[str, ...] = ("routing_seal", "seal")

_K8S_MUTATING_VERBS: frozenset[str] = frozenset(
    {
        "create",
        "update",
        "patch",
        "delete",
        "deletecollection",
        "bind",
        "escalate",
        "impersonate",
    }
)

#: Resources Kubernetes rewrites continuously as part of normal operation.
_K8S_NOISE_RESOURCES: frozenset[str] = frozenset(
    {
        "leases",
        "events",
        "endpoints",
        "endpointslices",
        "tokenreviews",
        "subjectaccessreviews",
        "selfsubjectaccessreviews",
        "selfsubjectrulesreviews",
        "localsubjectaccessreviews",
    }
)

_K8S_CLUSTER_SENSITIVE_RESOURCES: frozenset[str] = frozenset(
    {
        "clusterroles",
        "clusterrolebindings",
        "validatingwebhookconfigurations",
        "mutatingwebhookconfigurations",
        "validatingadmissionpolicies",
        "validatingadmissionpolicybindings",
    }
)

_K8S_RESOURCE_CATEGORIES: Mapping[str, str] = {
    **dict.fromkeys(
        (
            "pods",
            "deployments",
            "statefulsets",
            "daemonsets",
            "replicasets",
            "replicationcontrollers",
            "jobs",
            "cronjobs",
        ),
        "workload",
    ),
    **dict.fromkeys(
        (
            "roles",
            "rolebindings",
            "clusterroles",
            "clusterrolebindings",
            "serviceaccounts",
        ),
        "RBAC",
    ),
    "configmaps": "ConfigMap",
    "secrets": "Secret",
    "networkpolicies": "NetworkPolicy",
    "namespaces": "namespace",
    **dict.fromkeys(
        (
            "validatingwebhookconfigurations",
            "mutatingwebhookconfigurations",
            "validatingadmissionpolicies",
            "validatingadmissionpolicybindings",
        ),
        "admission control",
    ),
}

_K8S_SYSTEM_PRINCIPALS: frozenset[str] = frozenset(
    {
        "system:kube-controller-manager",
        "system:kube-scheduler",
        "system:apiserver",
        "system:cluster-autoscaler",
    }
)

_K8S_SYSTEM_PRINCIPAL_PREFIXES: tuple[str, ...] = (
    "system:node:",
    "system:serviceaccount:kube-system:",
    "system:serviceaccount:gke-managed-",
    "system:serviceaccount:gmp-system:",
    "system:gke-",
)

_K8S_VERSION_RE = re.compile(r"v\d+(?:(?:alpha|beta)\d+)?")

#: GKE ``ClusterManager`` operations that change the cluster.
_CLUSTER_MANAGER_MUTATIONS: tuple[str, ...] = (
    "create",
    "update",
    "delete",
    "set",
    "start",
    "complete",
    "rollback",
    "cancel",
)

#: Per-service Admin Activity method fragments that change CAGE posture.
_GCP_POSTURE_MUTATIONS: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "cloudkms.googleapis.com": (
        "KMS key/IAM mutation",
        (
            "setiampolicy",
            "createcryptokey",
            "updatecryptokey",
            "destroycryptokeyversion",
            "restorecryptokeyversion",
            "importcryptokeyversion",
        ),
    ),
    "storage.googleapis.com": (
        "Storage bucket/IAM/retention mutation",
        (
            "delete",
            "update",
            "patch",
            "setiampermissions",
            "setiampolicy",
            "lockretentionpolicy",
        ),
    ),
    "iam.googleapis.com": (
        "IAM service-account/key mutation",
        (
            "createserviceaccountkey",
            "uploadserviceaccountkey",
            "deleteserviceaccount",
            "disableserviceaccount",
            "setiampolicy",
        ),
    ),
    "cloudresourcemanager.googleapis.com": (
        "Project IAM/audit-config mutation",
        ("setiampolicy",),
    ),
    "logging.googleapis.com": (
        "Audit log sink/exclusion/bucket mutation",
        (
            "deletesink",
            "updatesink",
            "createexclusion",
            "updateexclusion",
            "updatebucket",
            "deletebucket",
            "updatesettings",
            "updatecmeksettings",
        ),
    ),
}


@dataclass(frozen=True)
class SignedArtifactRef:
    """A CAGE HSM-signed artifact reduced to what Cloud KMS logs about it.

    ``digest_sha256`` is empty and ``timestamp_epoch`` is ``0.0`` when the
    artifact's signing preimage or timestamp cannot be reconstructed; such an
    artifact fails closed as ``UNVERIFIABLE_ARTIFACT``.
    """

    artifact_type: str
    artifact_id: str
    key_family: str
    key_version_id: str
    digest_sha256: str
    timestamp_epoch: float


@dataclass(frozen=True)
class KmsSignLogEvent:
    """A Cloud KMS ``AsymmetricSign`` Data Access audit record."""

    insert_id: str
    resource_name: str
    key_family: str
    principal_email: str
    digest_sha256: str
    timestamp_epoch: float
    status_code: int


@dataclass(frozen=True)
class ControlPlaneMutationEvent:
    """An Admin Activity record that changes CAGE posture."""

    insert_id: str
    service_name: str
    method_name: str
    resource_name: str
    principal_email: str
    timestamp_epoch: float
    reason: str


@dataclass(frozen=True)
class AuditFinding:
    """A single corroboration failure."""

    code: str
    subject: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "subject": self.subject, "detail": self.detail}


@dataclass(frozen=True)
class AuditCorroborationReport:
    """Result of bidirectional Cloud Audit Log corroboration."""

    schema_version: str
    corroborated: bool
    checked_artifacts: int
    checked_kms_events: int
    checked_admin_events: int
    matched_pairs: int
    findings: tuple[AuditFinding, ...]
    verification_window: tuple[float, float] | None = None

    def to_dict(self) -> dict[str, Any]:
        window = None
        if self.verification_window is not None:
            window = {
                "start_utc": _format_utc(self.verification_window[0]),
                "end_utc": _format_utc(self.verification_window[1]),
            }
        return {
            "schema_version": self.schema_version,
            "corroborated": self.corroborated,
            "checked_artifacts": self.checked_artifacts,
            "checked_kms_events": self.checked_kms_events,
            "checked_admin_events": self.checked_admin_events,
            "matched_pairs": self.matched_pairs,
            "verification_window": window,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def summary_lines(self, label: str) -> list[str]:
        """Human-readable summary, one line per counter and finding."""
        status = "CORROBORATED" if self.corroborated else "FAILED"
        lines = [f"{label}: {status}"]
        if self.verification_window is not None:
            start, end = self.verification_window
            lines.append(
                f"  verification_window:  {_format_utc(start)} .. {_format_utc(end)}"
            )
        lines.extend(
            [
                f"  checked_artifacts:    {self.checked_artifacts}",
                f"  checked_kms_events:   {self.checked_kms_events}",
                f"  checked_admin_events: {self.checked_admin_events}",
                f"  matched_pairs:        {self.matched_pairs}",
            ]
        )
        lines.extend(
            f"  [FAIL] {finding.code} ({finding.subject}): {finding.detail}"
            for finding in self.findings
        )
        return lines


# ---------------------------------------------------------------------------
# Primitive parsing helpers
# ---------------------------------------------------------------------------


def _format_utc(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_timestamp_epoch(raw: Any) -> float:
    """Parse a UNIX epoch number or an RFC 3339 timestamp into epoch seconds.

    Cloud Logging emits nanosecond fractions, which are truncated to
    microseconds. Timestamps without a zone designator are ambiguous and, like
    anything unparseable, return ``0.0``.
    """
    if isinstance(raw, bool):
        return 0.0
    if isinstance(raw, (int, float)):
        value = float(raw)
        return value if math.isfinite(value) and value > 0 else 0.0
    if not isinstance(raw, str):
        return 0.0
    match = _RFC3339_RE.match(raw.strip())
    if match is None:
        return 0.0
    fraction = (match.group("fraction") or "").ljust(6, "0")[:6]
    zone = match.group("zone")
    offset = "+00:00" if zone in ("Z", "z") else zone
    base = match.group("base").replace("t", "T").replace(" ", "T")
    try:
        return datetime.fromisoformat(f"{base}.{fraction}{offset}").timestamp()
    except ValueError:
        return 0.0


def _kms_key_family(resource_name: str) -> str:
    """CryptoKey name from a Cloud KMS key or key-version resource name."""
    match = _KMS_RESOURCE_RE.search(resource_name or "")
    return match.group("key") if match else ""


def _normalize_principal(raw: str) -> str:
    cleaned = (raw or "").strip()
    for prefix in ("serviceAccount:", "user:"):
        if cleaned.startswith(prefix):
            return cleaned[len(prefix) :].strip()
    return cleaned


def _normalize_kms_digest_b64(raw: Any) -> str:
    """Canonical RFC 4648 base64 of a 32-byte SHA-256 digest, else ``""``.

    Accepts base64 or base64url, padded or not. Anything that does not decode
    to exactly 32 bytes normalizes to ``""`` and can never match.
    """
    if not isinstance(raw, str) or not raw.strip():
        return ""
    cleaned = raw.strip()
    padded = cleaned + "=" * (-len(cleaned) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded.encode("ascii"))
        except (ValueError, binascii.Error, UnicodeEncodeError):
            continue
        if len(decoded) == 32:
            return base64.b64encode(decoded).decode("ascii")
    return ""


def _sha256_b64(preimage: bytes) -> str:
    return base64.b64encode(hashlib.sha256(preimage).digest()).decode("ascii")


def _b64url_json_object(segment: str) -> dict[str, Any] | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        parsed = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _compact_jws(
    item: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], bytes] | None:
    """``(header, claims, signing_input)`` of a compact JWS routing seal."""
    for field_name in _SEAL_FIELDS:
        candidate = item.get(field_name)
        if not isinstance(candidate, str):
            continue
        parts = candidate.strip().split(".")
        if len(parts) != 3 or not all(parts):
            continue
        header = _b64url_json_object(parts[0])
        claims = _b64url_json_object(parts[1])
        if header is None or claims is None or "alg" not in header:
            continue
        try:
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        except UnicodeEncodeError:
            continue
        return header, claims, signing_input
    return None


# ---------------------------------------------------------------------------
# Signing preimages
# ---------------------------------------------------------------------------


def _evidence_batch_preimage(item: Mapping[str, Any]) -> bytes | None:
    if item.get("schema") != EVIDENCE_BATCH_SCHEMA:
        return None
    body = {k: v for k, v in item.items() if k not in _EVIDENCE_SIGNATURE_FIELDS}
    return jcs_bytes(body)


def _gateway_preimage(item: Mapping[str, Any]) -> bytes | None:
    jws = _compact_jws(item)
    if jws is not None:
        return jws[2]
    payload = item.get("payload")
    if isinstance(payload, Mapping) and item.get("signature"):
        return jcs_bytes(dict(payload))
    return None


def _reconciler_preimage(item: Mapping[str, Any]) -> bytes | None:
    if item.get("type") == DISCREPANCY_FENCE_TYPE:
        body = {k: v for k, v in item.items() if k not in _FENCE_SIGNATURE_FIELDS}
        return jcs_bytes(body)
    if all(field_name in item for field_name in _SNAPSHOT_FIELDS):
        # Mirrors src.gateway.governance.reconciliation.trust.snapshot_signing_payload.
        return jcs_bytes(
            {
                "source": item["source"],
                "state_scalar": float(item["state_scalar"]),
                "verified_at": item["verified_at"],
                "sequence": item["sequence"],
                "settled_through": item.get("settled_through"),
            }
        )
    return None


_PREIMAGE_BUILDERS: Mapping[str, Callable[[Mapping[str, Any]], bytes | None]] = {
    COMPLIANCE_EVIDENCE_KEY: _evidence_batch_preimage,
    GATEWAY_SEAL_KEY: _gateway_preimage,
    RECONCILER_SNAPSHOT_KEY: _reconciler_preimage,
}


def compute_kms_preimage_digest_b64(item: Mapping[str, Any], key_family: str) -> str:
    """Base64 SHA-256 of ``item``'s exact signing preimage under ``key_family``.

    This is the value Cloud KMS records as ``protoPayload.request.digest.sha256``
    for the ``AsymmetricSign`` call that produced ``item``'s signature. It is
    never the hex ``content_sha256`` of an ``.ndjson`` batch or a stream
    ``record_hash``. Returns ``""`` when no preimage can be reconstructed.
    """
    builder = _PREIMAGE_BUILDERS.get(key_family)
    if builder is None:
        return ""
    try:
        preimage = builder(item)
    except (TypeError, ValueError):
        return ""
    return _sha256_b64(preimage) if preimage is not None else ""


# ---------------------------------------------------------------------------
# Signed artifact extraction
# ---------------------------------------------------------------------------


def _evidence_batch_ref(
    item: Mapping[str, Any], index: int
) -> SignedArtifactRef | None:
    signature = item.get("signature")
    if (
        item.get("signature_status") == "UNSIGNED"
        or item.get("evidentiary") is False
        or not isinstance(signature, Mapping)
    ):
        # Unsigned, non-evidentiary attestations never reach Cloud KMS.
        return None
    return SignedArtifactRef(
        artifact_type=EVIDENCE_BATCH_ARTIFACT,
        artifact_id=str(item.get("data_key") or f"evidence-batch[{index}]"),
        key_family=COMPLIANCE_EVIDENCE_KEY,
        key_version_id=str(signature.get("key_id") or ""),
        digest_sha256=compute_kms_preimage_digest_b64(item, COMPLIANCE_EVIDENCE_KEY),
        timestamp_epoch=_parse_timestamp_epoch(item.get("created_at_utc")),
    )


def _gateway_ref(item: Mapping[str, Any], index: int) -> SignedArtifactRef:
    digest = compute_kms_preimage_digest_b64(item, GATEWAY_SEAL_KEY)
    jws = _compact_jws(item)
    if jws is not None:
        header, claims, _ = jws
        return SignedArtifactRef(
            artifact_type=ROUTING_SEAL_ARTIFACT,
            artifact_id=str(claims.get("nonce") or f"routing-seal[{index}]"),
            key_family=GATEWAY_SEAL_KEY,
            key_version_id=str(header.get("kid") or ""),
            digest_sha256=digest,
            timestamp_epoch=_parse_timestamp_epoch(claims.get("iat")),
        )
    payload = item.get("payload")
    payload_map = payload if isinstance(payload, Mapping) else {}
    return SignedArtifactRef(
        artifact_type=GOVERNANCE_RECORD_ARTIFACT,
        artifact_id=str(
            payload_map.get("decision_id")
            or payload_map.get("evidence_id")
            or f"governance-record[{index}]"
        ),
        key_family=GATEWAY_SEAL_KEY,
        key_version_id=str(item.get("kid") or ""),
        digest_sha256=digest,
        timestamp_epoch=_parse_timestamp_epoch(item.get("signed_at")),
    )


def _reconciler_ref(item: Mapping[str, Any], index: int) -> SignedArtifactRef | None:
    signature = item.get("signature")
    if not (isinstance(signature, str) and signature):
        # Unsigned (non-enforcing) snapshots never reach Cloud KMS.
        return None
    if item.get("type") == DISCREPANCY_FENCE_TYPE:
        artifact_type = DISCREPANCY_FENCE_ARTIFACT
        artifact_id = str(item.get("fence_id") or f"discrepancy-fence[{index}]")
        timestamp = item.get("signed_at")
    else:
        artifact_type = RECONCILER_SNAPSHOT_ARTIFACT
        artifact_id = (
            f"{item.get('invariant_id') or item.get('source') or 'snapshot'}:"
            f"{item.get('sequence', index)}"
        )
        timestamp = item.get("verified_at")
    return SignedArtifactRef(
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        key_family=RECONCILER_SNAPSHOT_KEY,
        key_version_id=str(item.get("kms_key_id") or ""),
        digest_sha256=compute_kms_preimage_digest_b64(item, RECONCILER_SNAPSHOT_KEY),
        timestamp_epoch=_parse_timestamp_epoch(timestamp),
    )


_ARTIFACT_EXTRACTORS: Mapping[
    str, Callable[[Mapping[str, Any], int], SignedArtifactRef | None]
] = {
    COMPLIANCE_EVIDENCE_KEY: _evidence_batch_ref,
    GATEWAY_SEAL_KEY: _gateway_ref,
    RECONCILER_SNAPSHOT_KEY: _reconciler_ref,
}


def extract_signed_artifacts(
    items: Iterable[Mapping[str, Any]],
    key_family: str,
) -> list[SignedArtifactRef]:
    """Reduce signed CAGE documents produced under ``key_family`` to artifacts.

    ``key_family`` names the key the caller expects signed the documents:
    ``compliance-evidence`` for ``cage-evidence-batch/1`` attestations,
    ``gateway-seal`` for routing seals and governance decision records, and
    ``reconciler-snapshot`` for snapshots and discrepancy fences. Unsigned
    documents are skipped; documents the family cannot interpret are kept with
    an empty digest so they fail closed.
    """
    extractor = _ARTIFACT_EXTRACTORS.get(key_family)
    if extractor is None:
        raise ValueError(
            f"unknown key family {key_family!r}; expected one of "
            f"{sorted(KNOWN_SIGNING_KEYS)}"
        )
    refs: list[SignedArtifactRef] = []
    for index, item in enumerate(items):
        ref = extractor(item, index)
        if ref is not None:
            refs.append(ref)
    return refs


# ---------------------------------------------------------------------------
# Cloud Audit Log parsing and control-plane classification
# ---------------------------------------------------------------------------


def _is_k8s_system_principal(principal: str) -> bool:
    return principal in _K8S_SYSTEM_PRINCIPALS or principal.startswith(
        _K8S_SYSTEM_PRINCIPAL_PREFIXES
    )


def _k8s_target(resource_name: str) -> tuple[str | None, str, str | None]:
    """``(namespace, resource, subresource)`` of a GKE ``k8s.io`` resource name.

    ``apps/v1/namespaces/governance-stack/deployments/gateway/scale`` yields
    ``("governance-stack", "deployments", "scale")``;
    ``rbac.authorization.k8s.io/v1/clusterrolebindings/x`` yields
    ``(None, "clusterrolebindings", None)``.
    """
    segments = [segment for segment in resource_name.lower().split("/") if segment]
    if "namespaces" in segments:
        position = segments.index("namespaces")
        namespace = segments[position + 1] if position + 1 < len(segments) else None
        rest = segments[position + 2 :]
        if not rest:
            return namespace, "namespaces", None
        return namespace, rest[0], rest[2] if len(rest) > 2 else None
    for position, segment in enumerate(segments):
        if _K8S_VERSION_RE.fullmatch(segment):
            rest = segments[position + 1 :]
            if rest:
                return None, rest[0], rest[2] if len(rest) > 2 else None
    return None, "", None


def _classify_k8s_mutation(
    method_name: str,
    resource_name: str,
    principal: str,
) -> str | None:
    """Describe a Kubernetes API write that changes governance posture.

    Flags writes to any object in ``governance-stack`` (workloads, RBAC,
    ConfigMaps, Secrets, NetworkPolicies, the namespace itself, and
    subresources such as ``pods/exec`` or ``deployments/scale``) and to
    cluster-scoped RBAC and admission webhooks (``POAM-2026-192``). Status
    updates, coordination noise, and Kubernetes system controllers are not
    posture changes.
    """
    if _is_k8s_system_principal(principal):
        return None
    method_lower = method_name.lower()
    if method_lower.rsplit(".", 1)[-1] not in _K8S_MUTATING_VERBS:
        return None
    namespace, resource, subresource = _k8s_target(resource_name)
    if subresource == "status" or ".status." in method_lower:
        return None
    if resource in _K8S_NOISE_RESOURCES:
        return None
    category = _K8S_RESOURCE_CATEGORIES.get(resource, "object")
    if namespace == GOVERNANCE_NAMESPACE:
        return f"Kubernetes {GOVERNANCE_NAMESPACE} {category} mutation ({method_name})"
    if namespace is None and resource in _K8S_CLUSTER_SENSITIVE_RESOURCES:
        return f"Kubernetes cluster-scoped {category} mutation ({method_name})"
    return None


def _classify_control_plane_mutation(
    service_name: str,
    method_name: str,
    resource_name: str,
    principal: str = "",
) -> str | None:
    """Describe an Admin Activity record that changes CAGE posture, else ``None``.

    Kubernetes API writes (``io.k8s.*`` methods, logged under ``k8s.io`` or
    ``container.googleapis.com``) go through :func:`_classify_k8s_mutation`;
    every other GKE ``ClusterManager`` write is a cluster control-plane
    mutation.
    """
    service = (service_name or "").lower()
    method_lower = (method_name or "").lower()
    if service == "k8s.io" or (
        service == "container.googleapis.com" and method_lower.startswith("io.k8s.")
    ):
        return _classify_k8s_mutation(method_name, resource_name, principal)
    if service == "container.googleapis.com":
        operation = method_lower.rsplit(".", 1)[-1]
        if operation.startswith(_CLUSTER_MANAGER_MUTATIONS):
            return f"GKE cluster control-plane mutation ({method_name})"
        return None
    rule = _GCP_POSTURE_MUTATIONS.get(service)
    if rule is not None:
        reason, fragments = rule
        if any(fragment in method_lower for fragment in fragments):
            return f"{reason} ({method_name})"
    return None


def parse_cloud_audit_log_entry(
    entry: Mapping[str, Any],
) -> KmsSignLogEvent | ControlPlaneMutationEvent | None:
    """Parse one Cloud Audit Log ``LogEntry`` into a typed event, else ``None``."""
    proto = entry.get("protoPayload")
    if not isinstance(proto, Mapping):
        return None
    if proto.get("@type") and "AuditLog" not in str(proto.get("@type")):
        return None

    service_name = str(proto.get("serviceName", "")).strip()
    method_name = str(proto.get("methodName", "")).strip()
    resource_name = str(proto.get("resourceName", "")).strip()
    insert_id = str(entry.get("insertId", "") or "").strip()
    timestamp_epoch = _parse_timestamp_epoch(entry.get("timestamp"))

    auth_info = proto.get("authenticationInfo")
    principal = ""
    if isinstance(auth_info, Mapping):
        principal = _normalize_principal(str(auth_info.get("principalEmail", "")))

    status = proto.get("status")
    status_code = 0
    if isinstance(status, Mapping) and isinstance(status.get("code"), int):
        status_code = int(status["code"])

    if service_name == "cloudkms.googleapis.com" and method_name.endswith(
        "AsymmetricSign"
    ):
        request = proto.get("request")
        digest = request.get("digest") if isinstance(request, Mapping) else None
        return KmsSignLogEvent(
            insert_id=insert_id or f"kms@{timestamp_epoch}",
            resource_name=resource_name,
            key_family=_kms_key_family(resource_name),
            principal_email=principal,
            digest_sha256=_normalize_kms_digest_b64(
                digest.get("sha256") if isinstance(digest, Mapping) else None
            ),
            timestamp_epoch=timestamp_epoch,
            status_code=status_code,
        )

    log_name = str(entry.get("logName", ""))
    is_admin_activity = not log_name or (
        "cloudaudit.googleapis.com%2Factivity" in log_name
        or "cloudaudit.googleapis.com/activity" in log_name
    )
    if not is_admin_activity:
        return None
    reason = _classify_control_plane_mutation(
        service_name, method_name, resource_name, principal
    )
    if reason is None:
        return None
    return ControlPlaneMutationEvent(
        insert_id=insert_id or f"admin@{timestamp_epoch}",
        service_name=service_name,
        method_name=method_name,
        resource_name=resource_name,
        principal_email=principal,
        timestamp_epoch=timestamp_epoch,
        reason=reason,
    )


def iter_json_lines(
    stream: TextIO, source: str = "<input>"
) -> Iterator[dict[str, Any]]:
    """Yield one JSON object per non-blank line of ``stream``."""
    for lineno, line in enumerate(stream, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{lineno}: invalid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(
                f"{source}:{lineno}: expected a JSON object, got {type(obj).__name__}"
            )
        yield obj


def parse_json_documents(text: str, source: str = "<input>") -> list[dict[str, Any]]:
    """Parse a JSON object, a JSON array of objects, or JSON Lines."""
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return list(iter_json_lines(io.StringIO(stripped), source))
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
        return list(parsed)
    raise ValueError(
        f"{source}: expected a JSON object, an array of objects, or JSON Lines"
    )


def expected_key_callers_for_project(project_id: str) -> dict[str, str]:
    """Exact workload service-account email per signing key in ``project_id``."""
    project = project_id.strip()
    if not project:
        raise ValueError("project_id must be non-empty")
    return {
        key_family: f"{prefix}{project}.iam.gserviceaccount.com"
        for key_family, prefix in DEFAULT_EXPECTED_KEY_CALLERS.items()
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _artifact_matches_kms_event(
    artifact: SignedArtifactRef,
    event: KmsSignLogEvent,
    *,
    max_skew_seconds: float,
) -> bool:
    """True only if every corroborating attribute is present and agrees."""
    if event.status_code != 0 or event.key_family != artifact.key_family:
        return False
    if (
        "/cryptoKeyVersions/" in artifact.key_version_id
        and artifact.key_version_id != event.resource_name
    ):
        return False
    if not artifact.digest_sha256 or artifact.digest_sha256 != event.digest_sha256:
        return False
    if artifact.timestamp_epoch <= 0.0 or event.timestamp_epoch <= 0.0:
        return False
    return abs(artifact.timestamp_epoch - event.timestamp_epoch) <= max_skew_seconds


def _check_kms_event_policy(
    event: KmsSignLogEvent,
    caller_map: Mapping[str, str],
) -> AuditFinding | None:
    if event.status_code != 0:
        return AuditFinding(
            code="FAILED_KMS_SIGN_EVENT",
            subject=event.insert_id,
            detail=(
                f"Cloud KMS AsymmetricSign failed with status.code={event.status_code} "
                f"on {event.resource_name} by {event.principal_email or '<unknown>'}"
            ),
        )
    expected = caller_map.get(event.key_family, "")
    if not expected:
        return None
    allowed = (
        event.principal_email.startswith(expected)
        if expected.endswith("@")
        else event.principal_email == expected
    )
    if allowed:
        return None
    return AuditFinding(
        code="UNEXPECTED_SIGNER_PRINCIPAL",
        subject=event.insert_id,
        detail=(
            f"Key {event.key_family!r} ({event.resource_name}) called by "
            f"{event.principal_email!r}; expected {expected!r}"
        ),
    )


def _unique_entries(
    entries: Iterable[Mapping[str, Any]],
) -> Iterator[Mapping[str, Any]]:
    """Drop exact redeliveries of the same ``LogEntry`` (same log, id, time)."""
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        insert_id = str(entry.get("insertId", "") or "")
        if insert_id:
            identity = (
                str(entry.get("logName", "")),
                insert_id,
                str(entry.get("timestamp", "")),
            )
            if identity in seen:
                continue
            seen.add(identity)
        yield entry


def verify_audit_corroboration(
    audit_log_entries: Iterable[Mapping[str, Any]],
    *,
    signed_artifacts: Collection[SignedArtifactRef] = (),
    expected_key_callers: Mapping[str, str] | None = None,
    trusted_deployer_principals: Collection[str] = (),
    corroborated_key_families: Collection[str] | None = None,
    max_skew_seconds: float = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    verification_window: tuple[float, float] | None = None,
) -> AuditCorroborationReport:
    """Bidirectionally corroborate CAGE HSM-signed artifacts with Cloud Audit Logs.

    ``corroborated_key_families`` selects the key families checked in both
    directions (default: all three); caller isolation and control-plane checks
    always cover every supplied record.

    ``verification_window`` ``(start_epoch, end_epoch)`` scopes the two
    matching findings to artifacts and ``AsymmetricSign`` records timestamped
    inside it, while still matching against everything supplied. Callers fetch
    ``max_skew_seconds`` of margin around the window and end it after a settle
    delay, so records near an edge are never reported only because their
    counterpart fell outside the fetch.
    """
    if max_skew_seconds < 0:
        raise ValueError("max_skew_seconds must be non-negative")
    if verification_window is not None and not (
        verification_window[0] < verification_window[1]
    ):
        raise ValueError("verification_window start must precede its end")

    caller_map = dict(DEFAULT_EXPECTED_KEY_CALLERS)
    if expected_key_callers:
        caller_map.update(expected_key_callers)
    active_families = (
        frozenset(corroborated_key_families)
        if corroborated_key_families is not None
        else KNOWN_SIGNING_KEYS
    )
    unknown_families = active_families - KNOWN_SIGNING_KEYS
    if unknown_families:
        raise ValueError(f"unknown key families: {sorted(unknown_families)}")
    trusted_deployers = {
        _normalize_principal(principal)
        for principal in trusted_deployer_principals
        if principal
    }

    def in_window(epoch: float) -> bool:
        if verification_window is None:
            return True
        return verification_window[0] <= epoch <= verification_window[1]

    kms_events: list[KmsSignLogEvent] = []
    admin_events: list[ControlPlaneMutationEvent] = []
    for entry in _unique_entries(audit_log_entries):
        parsed = parse_cloud_audit_log_entry(entry)
        if isinstance(parsed, KmsSignLogEvent):
            if parsed.key_family in KNOWN_SIGNING_KEYS:
                kms_events.append(parsed)
        elif isinstance(parsed, ControlPlaneMutationEvent):
            admin_events.append(parsed)

    findings: list[AuditFinding] = []
    candidate_indices: list[int] = []
    for index, event in enumerate(kms_events):
        violation = _check_kms_event_policy(event, caller_map)
        if violation is not None:
            findings.append(violation)
        elif event.key_family in active_families:
            candidate_indices.append(index)

    consumed: set[int] = set()
    checked_artifacts = 0
    matched_pairs = 0
    for artifact in signed_artifacts:
        if artifact.key_family not in active_families:
            continue
        if not artifact.digest_sha256 or artifact.timestamp_epoch <= 0.0:
            # No window can place an artifact without a timestamp, so it is
            # always reported.
            checked_artifacts += 1
            missing = [
                name
                for name, present in (
                    ("signing-preimage digest", bool(artifact.digest_sha256)),
                    ("timestamp", artifact.timestamp_epoch > 0.0),
                )
                if not present
            ]
            findings.append(
                AuditFinding(
                    code="UNVERIFIABLE_ARTIFACT",
                    subject=artifact.artifact_id,
                    detail=(
                        f"{artifact.artifact_type} {artifact.artifact_id!r} "
                        f"(key={artifact.key_family}) has no reconstructable "
                        f"{' or '.join(missing)}"
                    ),
                )
            )
            continue
        reportable = in_window(artifact.timestamp_epoch)
        if reportable:
            checked_artifacts += 1
        matches = [
            index
            for index in candidate_indices
            if index not in consumed
            and _artifact_matches_kms_event(
                artifact, kms_events[index], max_skew_seconds=max_skew_seconds
            )
        ]
        if matches:
            best = min(
                matches,
                key=lambda index: abs(
                    kms_events[index].timestamp_epoch - artifact.timestamp_epoch
                ),
            )
            consumed.add(best)
            if reportable:
                matched_pairs += 1
        elif reportable:
            findings.append(
                AuditFinding(
                    code="MISSING_KMS_SIGN_EVENT",
                    subject=artifact.artifact_id,
                    detail=(
                        f"No Cloud KMS AsymmetricSign record corroborates "
                        f"{artifact.artifact_type} {artifact.artifact_id!r} "
                        f"(key={artifact.key_family}, "
                        f"kid={artifact.key_version_id or '<unspecified>'}, "
                        f"digest={artifact.digest_sha256}, "
                        f"at={_format_utc(artifact.timestamp_epoch)})"
                    ),
                )
            )

    for index in candidate_indices:
        event = kms_events[index]
        if index in consumed or not in_window(event.timestamp_epoch):
            continue
        findings.append(
            AuditFinding(
                code="UNMATCHED_KMS_SIGN_EVENT",
                subject=event.insert_id,
                detail=(
                    f"Cloud KMS AsymmetricSign {event.insert_id!r} on "
                    f"{event.resource_name} by {event.principal_email!r} "
                    f"(digest={event.digest_sha256 or '<missing>'}) matches no "
                    "supplied CAGE artifact"
                ),
            )
        )

    for mutation in admin_events:
        if mutation.principal_email in trusted_deployers:
            continue
        findings.append(
            AuditFinding(
                code="UNAUTHORIZED_CONTROL_PLANE_MUTATION",
                subject=mutation.insert_id,
                detail=(
                    f"{mutation.reason} on {mutation.resource_name!r} by untrusted "
                    f"principal {mutation.principal_email or '<unknown>'!r}"
                ),
            )
        )

    return AuditCorroborationReport(
        schema_version=AUDIT_CORROBORATION_SCHEMA_VERSION,
        corroborated=not findings,
        checked_artifacts=checked_artifacts,
        checked_kms_events=len(kms_events),
        checked_admin_events=len(admin_events),
        matched_pairs=matched_pairs,
        findings=tuple(findings),
        verification_window=verification_window,
    )
