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

"""
verify_flowsignal_wire_and_hostile.py
======================================
Executes:
1. Live wire roundtrip against FlowSignal Cloud Run staging service.
2. Live wire hostile malformed-body attack against Cloud Run DRS ingress.
3. LIVE-P3-004 hostile response interception suite (Vectors A, B, C)
   evaluating CAGE fail-closed admission and ConsequenceToken gating.

Configuration
-------------
This script talks to a live partner staging environment, so all
deployment-specific identifiers are supplied by the operator. There are
deliberately no hardcoded fallbacks (AGENTS.md secret hygiene); a missing
value exits with actionable guidance rather than silently targeting someone
else's project.

Required:
    FLOWSIGNAL_STAGING_ENDPOINT — Cloud Run base URL of the staging service.
    CAGE_GCP_PROJECT            — GCP project ID or number holding the secret.
    CAGE_GCP_IMPERSONATE_SA     — service account to impersonate.

Optional:
    FLOWSIGNAL_BEARER_SECRET    — Secret Manager secret name
                                  (default: "flowsignal-cage-phase3-bearer").

Example:
    export FLOWSIGNAL_STAGING_ENDPOINT="https://<service>.a.run.app"
    export CAGE_GCP_PROJECT="my-project"
    export CAGE_GCP_IMPERSONATE_SA="cage-gateway@my-project.iam.gserviceaccount.com"
    uv run python scripts/verify_flowsignal_wire_and_hostile.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import httpx

from src.gateway.governance.seams.normative import ValidationResult
from src.integrations.provider_01.provider import (
    FlowSignalNormativeProvider,
    _build_cage_authority_request,
    _map_flowsignal_decision,
)


def _require_env(name: str, description: str) -> str:
    """Return a required environment variable, or exit with actionable guidance.

    Fail-closed by design: this script authenticates against a live partner
    staging endpoint, so deployment-specific identifiers must be supplied by
    the operator. Per AGENTS.md secret hygiene, there are deliberately no
    hardcoded fallbacks — a missing value is an error, not a default.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(
            f"ERROR: {name} is not set.\n"
            f"  {name} must contain {description}.\n"
            f"  This script targets a live partner staging environment and has\n"
            f"  no default — export the variable for your own GCP project:\n"
            f"    export {name}=...\n"
        )
    return value


def get_gcp_credentials() -> tuple[str, str, str]:
    """Resolve the staging endpoint and credentials from the environment.

    Required environment variables:
        FLOWSIGNAL_STAGING_ENDPOINT — Cloud Run base URL of the staging service.
        CAGE_GCP_PROJECT            — GCP project ID or number holding the secret.
        CAGE_GCP_IMPERSONATE_SA     — service account to impersonate.
    """
    endpoint = _require_env(
        "FLOWSIGNAL_STAGING_ENDPOINT",
        "the Cloud Run base URL of the FlowSignal staging service",
    )
    project = _require_env(
        "CAGE_GCP_PROJECT",
        "the GCP project ID or number holding the FlowSignal bearer secret",
    )
    impersonate_sa = _require_env(
        "CAGE_GCP_IMPERSONATE_SA",
        "the service account to impersonate (e.g. cage-gateway@<project>.iam.gserviceaccount.com)",
    )
    secret_name = os.environ.get(
        "FLOWSIGNAL_BEARER_SECRET", "flowsignal-cage-phase3-bearer"
    )

    bearer = subprocess.check_output(
        [
            "gcloud",
            "secrets",
            "versions",
            "access",
            "latest",
            f"--secret={secret_name}",
            f"--project={project}",
            f"--impersonate-service-account={impersonate_sa}",
        ],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()

    id_token = subprocess.check_output(
        [
            "gcloud",
            "auth",
            "print-identity-token",
            f"--audiences={endpoint}",
            f"--impersonate-service-account={impersonate_sa}",
        ],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()

    return endpoint, bearer, id_token


async def main() -> None:
    print("=" * 80)
    print("FLOWSIGNAL LIVE WIRE & HOSTILE VALIDATION SUITE (LIVE-P3-004)")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 80)

    # 1. Fetch live credentials
    endpoint, bearer, id_token = get_gcp_credentials()
    masked_bearer = f"{bearer[:6]}...{bearer[-4:]}"
    masked_id = f"{id_token[:10]}...{id_token[-6:]}"
    print(f"\n[1] Live Cloud Run Target: {endpoint}")
    print(f"    Secret Manager Bearer: {masked_bearer} (length {len(bearer)})")
    print(f"    Google IAM OIDC Token: {masked_id} (length {len(id_token)})")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer}",
        "X-Serverless-Authorization": f"Bearer {id_token}",
    }

    # 2. Live Wire Positive Execution (ALLOW Mandate Profile)
    print("\n[2] Live Wire Positive Execution (Authoritative ALLOW Profile)")
    allow_payload = {
        "thread_id": "thread-live-wire-allow-001",
        "correlation_id": "exec-live-wire-allow-001",
        "approval_id": "APPROVAL-TREASURY-001",
        "action": "payment.release",
        "target": "TREASURY_GATEWAY",
        "operator_urn": "agent-treasury-01",
        "actor_id": "agent-treasury-01",
        "params": {
            "purpose": "Invoice 78431",
            "actor_role": "treasury_agent",
            "principal_id": "institution-001",
            "principal_name": "Example Financial Institution",
            "mandate_id": "MANDATE-TREASURY-001",
            "mandate_max_amount": 1000000.0,
            "currency": "GBP",
            "permitted_source_accounts": ["TREASURY-001"],
            "permitted_counterparty_class": "APPROVED_SUPPLIERS",
            "mandate_valid_until": "2026-12-31T23:59:59Z",
            "amount": 500000.0,
            "source_account": "TREASURY-001",
            "beneficiary": "SUPPLIER-X",
            "counterparty_status": "APPROVED",
            "account_status": "ACTIVE",
            "risk_state": "NORMAL",
            "approval_required": False,
            "screening_status": "CLEAR",
            "screening_max_age_seconds": 3600,
            "screening_source": "SCREENING-SERVICE-01",
        },
    }

    wire_request_body = _build_cage_authority_request(allow_payload)
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp_allow = await client.post(
            f"{endpoint}/cage/validate",
            json=wire_request_body,
            headers=headers,
        )
        print(
            f"    Wire HTTP Status: {resp_allow.status_code} {resp_allow.reason_phrase}"
        )
        print(
            f"    Wire Trace Context: {resp_allow.headers.get('x-cloud-trace-context')}"
        )
        print(f"    Wire Response Date: {resp_allow.headers.get('date')}")
        resp_allow_data = resp_allow.json()
        print(f"    FlowSignal Decision: {resp_allow_data.get('decision')}")
        print(f"    Authority Record ID: {resp_allow_data.get('authority_record_id')}")
        print(
            f"    Receipt ID: {resp_allow_data.get('authority_receipt', {}).get('id')}"
        )

    # 3. Live Wire Hostile Malformed Request to Cloud Run
    print("\n[3] Live Wire Hostile Request (Malformed Request Ingress to Cloud Run)")
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp_malformed = await client.post(
            f"{endpoint}/cage/validate",
            json={"malformed_attack_vector": True},
            headers=headers,
        )
        print(
            f"    Wire HTTP Status: {resp_malformed.status_code} {resp_malformed.reason_phrase}"
        )
        print(
            f"    Wire Trace Context: {resp_malformed.headers.get('x-cloud-trace-context')}"
        )
        print(f"    Cloud Run Response Preview: {resp_malformed.text[:160]}...")

    # 4. LIVE-P3-004: Hostile Malformed FlowSignal Responses vs CAGE Fail-Closed Gate
    print("\n" + "=" * 80)
    print("LIVE-P3-004: MALFORMED FLOWSIGNAL RESPONSE / FAIL-CLOSED ADMISSION SUITE")
    print(
        "Safe Property: INVALID_FLOWSIGNAL_RESPONSE ⇒ admitted=False ∧ no ConsequenceToken"
    )
    print("=" * 80)

    # Setup mock signer for hermetic ConsequenceToken verification
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from src.gateway.governance.consequence_token import ConsequenceToken

    private_key = ec.generate_private_key(ec.SECP256R1())

    mock_signer = MagicMock()
    mock_signer.key_id = (
        "projects/test/locations/us/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"
    )
    mock_signer.sign.side_effect = lambda data: private_key.sign(
        data, ec.ECDSA(hashes.SHA256())
    )

    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=mock_signer,
    ):
        provider = FlowSignalNormativeProvider(
            endpoint=endpoint,
            api_key=bearer,
            gcp_id_token=id_token,
            timeout=10.0,
        )

        vectors = [
            (
                "A. Missing decision field",
                {
                    "authority_record_id": "MANDATE-TREASURY-001",
                    "message": "Authority evaluation complete",
                },
            ),
            (
                "B. Unknown decision value ('MAYBE')",
                {
                    "decision": "MAYBE",
                    "authority_record_id": "MANDATE-TREASURY-001",
                    "message": "Undetermined",
                },
            ),
            (
                "C. ALLOW with missing/empty authority_record_id",
                {
                    "decision": "ALLOW",
                    "authority_record_id": "",
                    "message": "Authorized without record reference",
                },
            ),
        ]

        for name, injected_response in vectors:
            print(f"\n--- Vector: {name} ---")
            print(f"Injected FlowSignal Response: {json.dumps(injected_response)}")

            # Mock wire transport to return the injected hostile response from FlowSignal
            mock_response = httpx.Response(
                status_code=200,
                json=injected_response,
                request=httpx.Request("POST", f"{endpoint}/cage/validate"),
            )

            with patch("httpx.AsyncClient.post", return_value=mock_response):
                val_result: ValidationResult = await provider.validate_fria(
                    allow_payload
                )

            token_minted = any(
                f.get("code") == "CONSEQUENCE_TOKEN" and "token" in f
                for f in val_result.findings
            )
            token_mint_failed = any(
                f.get("code") == "CONSEQUENCE_TOKEN_MINT_FAILED"
                for f in val_result.findings
            )

            print(f"Provider Result: {val_result}")
            print(f"Admission State: admitted = {val_result.admitted}")
            print(f"Reason / Error Code: {val_result.error}")
            print(f"Findings Count: {len(val_result.findings)}")
            for idx, f in enumerate(val_result.findings):
                print(
                    f"  [{idx}] code={f.get('code')}, severity={f.get('severity')}, message={f.get('message')}"
                )
            print(f"ConsequenceToken Minted: {token_minted}")
            if token_mint_failed:
                print(
                    "ConsequenceToken Mint Failed finding recorded: True (Fail-Closed)"
                )

            # Invariant assertion
            safe_property_satisfied = (val_result.admitted is False) and (
                not token_minted
            )
            print(
                f"Safe Invariant Satisfied (admitted=False ∧ no Token): {safe_property_satisfied}"
            )
            assert safe_property_satisfied, f"VIOLATION OF SAFE PROPERTY ON {name}"

    print("\n" + "=" * 80)
    print("ALL LIVE-P3-004 HOSTILE VECTORS VERIFIED FAIL-CLOSED: 100% SUCCESS")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
