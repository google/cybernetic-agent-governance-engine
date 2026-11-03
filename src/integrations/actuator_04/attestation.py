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

"""Actuator04AttestationProvider verifying host discrete TPM 2.0 PCR quotes and Ring-0 posture."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.seams.actuation import ReceiptVerification
from src.gateway.governance.seams.attestation import (
    AttestationStatus,
    ExternalAttestation,
)
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    ACTUATOR_04_ID,
    ATTESTATION_RECEIPT_DOMAIN_TAG,
    ENV_EXPECTED_TPM_PCR_QUOTE,
    ENV_RECEIPT_KEY_MANIFEST_URL,
)
from src.integrations.trust.key_manifest import (
    Ed25519KeyManifestClient,
    Ed25519KeyResolver,
)


class Actuator04AttestationProvider(AttestationProvider):
    """Polls host substrate for discrete TPM 2.0 PCR quotes and Ring-0 firewall postures."""

    def __init__(
        self,
        *,
        transport: Actuator04Transport,
        expected_pcr_quote: str | None = None,
        receipt_key_resolver: Ed25519KeyResolver | None = None,
    ) -> None:
        self._transport = transport
        self._expected_pcr_quote = expected_pcr_quote
        self._receipt_key_resolver = receipt_key_resolver

    @classmethod
    def from_env(cls) -> Actuator04AttestationProvider:
        """Construct Actuator04AttestationProvider from environment configuration."""
        transport = Actuator04Transport.from_env()
        expected = os.environ.get(ENV_EXPECTED_TPM_PCR_QUOTE, "").strip() or None
        manifest_url = os.environ.get(ENV_RECEIPT_KEY_MANIFEST_URL, "").strip()
        resolver: Ed25519KeyResolver | None = (
            Ed25519KeyManifestClient(manifest_url) if manifest_url else None
        )
        return cls(transport=transport, expected_pcr_quote=expected, receipt_key_resolver=resolver)

    @property
    def provider_name(self) -> str:
        return ACTUATOR_04_ID

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch and verify TPM 2.0 PCR quotes and Ring-0 postures across host endpoints."""
        attestations: list[ExternalAttestation] = []
        try:
            endpoints = self._transport.resolve_target_endpoints()
            responses = await self._transport.get_from_endpoints("/v1/cage/attest", endpoints=endpoints)
        except Exception as exc:
            return [
                ExternalAttestation(
                    attestation_type="HOST_TPM_PCR",
                    status=AttestationStatus.ERROR.value,
                    receipt_id="err-substrate-unreachable",
                    attested_at="",
                    provider_name=self.provider_name,
                    metadata={"error": str(exc)},
                )
            ]

        from src.integrations.actuator_04.adapter import (
            verify_substrate_receipt_signature,
        )

        expected_quote = (
            context.get("expected_tpm_pcr_quote") or self._expected_pcr_quote
        )

        MAX_ATTESTATION_SKEW_SECONDS = 300.0

        for resp in responses:
            body = resp.json()
            tpm_quote = body.get("tpm_pcr_quote", "")
            ts_str = body.get("timestamp_utc", "")

            # Freshness check: reject stale or expired quotes (> 300s skew)
            is_stale = False
            if not ts_str:
                is_stale = True
            else:
                try:
                    ts_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    age_seconds = abs((now - ts_dt).total_seconds())
                    if age_seconds > MAX_ATTESTATION_SKEW_SECONDS:
                        is_stale = True
                except Exception:
                    is_stale = True

            if is_stale:
                attestations.append(
                    ExternalAttestation(
                        attestation_type="HOST_TPM_PCR",
                        status=AttestationStatus.ERROR.value,
                        receipt_id=body.get("kid", "err-stale-timestamp"),
                        attested_at=ts_str,
                        provider_name=self.provider_name,
                        metadata={
                            "code": "ATTESTATION_TIMESTAMP_STALE",
                            "severity": "TERMINAL",
                            "detail": f"Attestation timestamp {ts_str!r} is expired or invalid (> {MAX_ATTESTATION_SKEW_SECONDS}s skew)",
                        },
                    )
                )
                continue

            envelope_digest = context.get("expected_envelope_digest") or body.get("envelope_digest", tpm_quote)

            v_status, finding = await verify_substrate_receipt_signature(
                body,
                domain_tag=ATTESTATION_RECEIPT_DOMAIN_TAG,
                expected_envelope_digest=envelope_digest,
                key_resolver=self._receipt_key_resolver,
            )

            if v_status != ReceiptVerification.VERIFIED or finding:
                meta = finding if finding else {"code": "RECEIPT_NOT_VERIFIED", "detail": "Receipt signature not verified"}
                attestations.append(
                    ExternalAttestation(
                        attestation_type="HOST_TPM_PCR",
                        status=AttestationStatus.ERROR.value,
                        receipt_id=body.get("kid", "err-unknown-kid"),
                        attested_at=body.get("timestamp_utc", ""),
                        provider_name=self.provider_name,
                        metadata=meta,
                    )
                )
                continue

            # Check TPM PCR measurement against baseline
            if expected_quote and tpm_quote != expected_quote:
                status = AttestationStatus.DRIFT_DETECTED
            else:
                status = AttestationStatus.VERIFIED

            attestations.append(
                ExternalAttestation(
                    attestation_type=body.get("attestation_type", "HOST_TPM_PCR"),
                    status=status.value,
                    receipt_id=body.get("kid", "tpm-verified"),
                    attested_at=body.get("timestamp_utc", ""),
                    provider_name=self.provider_name,
                    metadata={
                        "ring0_posture": body.get("ring0_posture", "ACTIVE_RING0_ENFORCED"),
                        "tpm_pcr_quote": tpm_quote,
                        "pcr_values": body.get("pcr_values", {}),
                        "epoch_map": body.get("epoch_map", {}),
                    },
                )
            )

        return attestations
