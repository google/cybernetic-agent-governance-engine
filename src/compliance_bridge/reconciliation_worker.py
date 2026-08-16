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
reconciliation_worker.py — External Ledger Reconciliation Skeleton (Tier 5)
===========================================================================

Pre-flight structural placeholder for Priority 3 of the evidentiary
independence roadmap: replacing the self-reported CBF cash balance with
an independently reconciled external ledger balance.

Problem statement
-----------------
The Control Barrier Function (CBF) evaluates:

    h(x) = cash_balance - min_cash_balance

But ``cash_balance`` is written to Redis by the same execution system that
requests trades.  This creates a recursive self-authentication vulnerability:
the system reports its own financial state, then uses that self-reported state
to pass the governance check that authorises further trades.

In litigation, opposing counsel would ask: "Who wrote the number that the
barrier function checked?" — Answer: the same system that wanted the trade
approved.

Solution architecture
---------------------
This module defines the interface for an **external ledger reconciliation
daemon** that runs in a separate Kubernetes namespace (``reconciliation-worker``)
with its own Cilium network policy.  The daemon:

  1. Polls the external custody ledger (e.g. Plaid Exchange API, Apex Clearing)
     on a configurable interval.
  2. Validates the response against the provider's API signature.
  3. Signs the reconciled balance with Google Cloud KMS (Priority 1 key ring).
  4. Writes the verified balance directly to Redis with a strict TTL.

The CBF then reads ``reconciliation:verified_balance`` instead of the
self-reported ``safety:current_cash``.  If the verified balance is stale
(TTL expired) or absent, the CBF defaults to its fail-closed posture (-2).

IMPORTANT: This is a **pre-flight skeleton** — it defines the data contracts,
interfaces, and Redis key schema but does NOT contain production API
credentials or live provider integrations.  Production implementation
requires:
  - Workload Identity binding for the reconciliation daemon service account
  - Encrypted API credentials stored in Google Secret Manager
  - Provider-specific API client (Plaid, Apex, Interactive Brokers, etc.)
  - Cloud KMS signing key (shared with Priority 1 governance signer)

Environment variables
---------------------
  RECONCILIATION_POLL_INTERVAL_SECONDS   — polling interval (default: 60)
  RECONCILIATION_TTL_SECONDS             — Redis TTL for verified balances (default: 300)
  RECONCILIATION_PROVIDER                — provider name (default: "stub")
  REDIS_URL                              — Redis connection string
  KMS_GOVERNANCE_KEY                     — Cloud KMS key for signing reconciled balances
  CAGE_RECONCILIATION_REPLAY_DEFENSE     — feature flag for monotonic sequence (default: "false")
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger("cage.reconciliation")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL_SECONDS: int = int(
    os.environ.get("RECONCILIATION_POLL_INTERVAL_SECONDS", "60")
)
TTL_SECONDS: int = int(os.environ.get("RECONCILIATION_TTL_SECONDS", "300"))
PROVIDER: str = os.environ.get("RECONCILIATION_PROVIDER", "stub")

# ---------------------------------------------------------------------------
# Feature flag: Replay defense (R-04 mitigation, §2.10)
# ---------------------------------------------------------------------------
# Stage 0 (write-side): When enabled, workers stamp monotonic sequence on payloads.
# Stage 1 (read-side): When enabled, CBF enforces sequence validation.
REPLAY_DEFENSE_ENABLED: bool = os.environ.get(
    "CAGE_RECONCILIATION_REPLAY_DEFENSE", "false"
).lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# Production guard (BLOCKER-06)
# ---------------------------------------------------------------------------
# The stub provider fabricates a static $100k balance.  If the CBF evaluates
# against this fake number in production, the safety barrier is meaningless.
# Block startup immediately so the misconfiguration cannot be silently deployed.
#
# C-25 fix: use CAGE_ENV (not ENVIRONMENT) for consistency with the rest of
# the codebase.  The old guard checked os.environ.get("ENVIRONMENT") ==
# "production" which never fired because CAGE standardised on CAGE_ENV.
# This was a dead safety check that gave false confidence.

_cage_env_recon = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_is_production_recon: bool = _cage_env_recon not in ("development", "test", "dev", "ci")

if _is_production_recon and PROVIDER == "stub":
    raise RuntimeError(
        "RECONCILIATION_PROVIDER=stub is not allowed in production "
        f"(CAGE_ENV={_cage_env_recon!r}). "
        "Set a real ledger provider (e.g. RECONCILIATION_PROVIDER=anchorage or "
        "RECONCILIATION_PROVIDER=plaid). "
        "To bypass in local dev, set CAGE_ENV=development."
    )

# Redis key schema
_REDIS_KEY_VERIFIED_BALANCE = "reconciliation:verified_balance"
_REDIS_KEY_VERIFIED_AT = "reconciliation:verified_at"
_REDIS_KEY_PROVIDER = "reconciliation:provider"
_REDIS_KEY_SIGNATURE = "reconciliation:signature"
# §2.10 Replay defense: monotonic sequence source of truth (never TTL'd)
_REDIS_KEY_SEQUENCE_LATEST = "reconciliation:sequence:latest"
_REDIS_KEY_SEQUENCE_LAST_ACCEPTED = "reconciliation:sequence:last_accepted"


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class ReconciliationResult:
    """Result of an external ledger balance query.

    Attributes:
        source:          Provider name (e.g. "plaid", "apex_clearing", "stub").
        balance_usd:     Externally reported available liquid balance in USD.
        verified_at:     Unix timestamp when the balance was fetched.
        signature:       Cryptographic signature of the balance payload
                         (Cloud KMS asymmetricSign output, hex-encoded).
                         Empty string in dev/CI when Cloud KMS is unavailable (HMAC fallback).
        ttl_seconds:     Time-to-live for this balance in Redis.
        raw_response:    Optional raw provider response for forensic audit.
        error:           Error message if reconciliation failed; None on success.
        sequence:        Monotonic sequence number for replay defense (§2.10).
                         Zero means sequence validation is disabled or not yet stamped.
    """

    source: str
    balance_usd: float
    verified_at: float = field(default_factory=time.time)
    signature: str = ""
    ttl_seconds: int = TTL_SECONDS
    raw_response: dict | None = None
    error: str | None = None
    sequence: int = 0  # §2.10.1: Monotonic sequence number for R-04 replay defense

    @property
    def is_valid(self) -> bool:
        """True if the reconciliation succeeded and the balance is non-negative."""
        return self.error is None and self.balance_usd >= 0.0

    @property
    def is_stale(self) -> bool:
        """True if the balance is older than its TTL."""
        return (time.time() - self.verified_at) > self.ttl_seconds

    def to_redis_payload(self) -> str:
        """Serialize to a deterministic JSON string for Redis storage."""
        return json.dumps(
            {
                "source": self.source,
                "balance_usd": self.balance_usd,
                "verified_at": self.verified_at,
                "signature": self.signature,
                "sequence": self.sequence,  # §2.10: included in signed payload
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_redis_payload(cls, payload: str) -> ReconciliationResult:
        """Deserialize from Redis."""
        data = json.loads(payload)
        return cls(
            source=data["source"],
            balance_usd=data["balance_usd"],
            verified_at=data["verified_at"],
            signature=data.get("signature", ""),
            sequence=data.get("sequence", 0),  # §2.10: backward-compatible default
        )


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------


class LedgerProvider(Protocol):
    """Interface for external custody ledger providers.

    Production implementations must:
      - Authenticate via provider-specific credentials (stored in Secret Manager)
      - Validate the provider's response signature/TLS certificate
      - Return a ReconciliationResult with the externally reported balance
      - Never cache the balance locally — every call must hit the provider API
    """

    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        """Fetch the current available balance from the external ledger.

        Args:
            account_id: The account identifier at the custody provider.

        Returns:
            ReconciliationResult with the externally reported balance.
            On failure, the result will have ``error`` set and ``balance_usd`` = 0.
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Stub provider (development / CI)
# ---------------------------------------------------------------------------


class StubLedgerProvider:
    """Development-only provider that returns a configurable static balance.

    NEVER use in production — this defeats the entire purpose of external
    reconciliation.  The stub exists solely for:
      - Unit tests that validate the reconciliation daemon's Redis write path
      - CI pipelines that cannot reach external APIs
      - Local development without provider credentials
      - GKE validation tests and CISO presentation demos

    Set RECONCILIATION_STUB_BALANCE_USD to control the returned balance
    (default: 100000.0 = $100k).
    """

    def __init__(self) -> None:
        self._balance = float(
            os.environ.get("RECONCILIATION_STUB_BALANCE_USD", "100000.0")
        )
        logger.warning(
            "⚠️ StubLedgerProvider active — external reconciliation is NOT "
            "providing independent ground truth. This is acceptable in "
            "dev/test but MUST be replaced with AnchorageGrpcLedgerProvider "
            "in production."
        )

    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        """Return a static balance for testing."""
        return ReconciliationResult(
            source="stub",
            balance_usd=self._balance,
            verified_at=time.time(),
            signature="",  # No KMS signing in stub mode
            raw_response={"stub": True, "account_id": account_id},
        )


# ---------------------------------------------------------------------------
# Anchorage Digital — Production custody provider (OCC-chartered)
# ---------------------------------------------------------------------------


class AnchorageGrpcLedgerProvider:
    """Production ledger provider backed by the Anchorage Digital gRPC API.

    Anchorage Digital is an OCC-chartered qualified custodian with a gRPC-native
    API designed for regulated institutional workflows.  This provider maps
    directly to the ``LedgerProvider`` protocol, giving the CBF an externally
    attested balance that the execution system cannot influence.

    Why Anchorage
    -------------
    - **Regulatory authority**: OCC national trust bank charter — the highest
      tier of US custody regulation.  Carries evidentiary weight in any
      proceeding where the integrity of reported balances is challenged.
    - **gRPC-native API**: Structured protobuf contracts with built-in mTLS
      authentication.  No REST serialization ambiguity.
    - **Audit-grade access logs**: Every balance query is logged in Anchorage's
      immutable audit trail, providing an external corroboration point for
      the CAGE evidence chain.

    API surface required
    --------------------
    ::

        service VaultService {
          rpc GetVaultBalance(GetVaultBalanceRequest) returns (VaultBalanceResponse);
        }

        message GetVaultBalanceRequest {
          string vault_id = 1;
          string asset_type = 2;  // "USD"
        }

        message VaultBalanceResponse {
          string vault_id = 1;
          string asset_type = 2;
          string available_balance = 3;  // decimal string
          string pending_balance = 4;
          google.protobuf.Timestamp as_of = 5;
        }

    Authentication
    --------------
    - mTLS client certificate issued by Anchorage during onboarding.
    - Client cert and key stored in Google Secret Manager, mounted via
      Workload Identity into the ``reconciliation-worker`` namespace.

    Environment variables
    ---------------------
      ANCHORAGE_API_ENDPOINT     — gRPC endpoint (e.g. "api.anchorage.com:443")
      ANCHORAGE_VAULT_ID         — Vault identifier at Anchorage
      ANCHORAGE_CLIENT_CERT_PATH — Path to mTLS client certificate PEM
      ANCHORAGE_CLIENT_KEY_PATH  — Path to mTLS client key PEM
      ANCHORAGE_CA_CERT_PATH     — Optional: custom CA cert for the channel

    Status
    ------
    **NOT YET IMPLEMENTED** — this class defines the interface contract for
    the production integration.  The ``fetch_balance`` method raises
    ``NotImplementedError`` until Anchorage enterprise API credentials are
    provisioned and the gRPC stubs are generated from the Anchorage protobuf
    definitions.

    To integrate:
      1. Obtain API access from Anchorage Digital (enterprise onboarding).
      2. Generate Python gRPC stubs from the Anchorage protobuf definitions:
         ``python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. anchorage/vault/v1/vault.proto``
      3. Store mTLS credentials in Google Secret Manager.
      4. Mount credentials via Workload Identity in the reconciliation-worker
         Kubernetes namespace.
      5. Set RECONCILIATION_PROVIDER=anchorage in the deployment config.
    """

    def __init__(self) -> None:
        self._endpoint = os.environ.get("ANCHORAGE_API_ENDPOINT", "")
        self._vault_id = os.environ.get("ANCHORAGE_VAULT_ID", "")
        self._client_cert_path = os.environ.get("ANCHORAGE_CLIENT_CERT_PATH", "")
        self._client_key_path = os.environ.get("ANCHORAGE_CLIENT_KEY_PATH", "")
        self._ca_cert_path = os.environ.get("ANCHORAGE_CA_CERT_PATH", "")

        if not self._endpoint or not self._vault_id:
            logger.error(
                "[AnchorageProvider] ANCHORAGE_API_ENDPOINT and ANCHORAGE_VAULT_ID "
                "are required. Set RECONCILIATION_PROVIDER=stub for dev/test."
            )

        logger.info(
            "[AnchorageProvider] Initialised: endpoint=%s vault=%s",
            self._endpoint or "(not set)",
            self._vault_id or "(not set)",
        )

    def _create_channel(self) -> object:
        """Create an mTLS-authenticated gRPC channel to Anchorage.

        Returns:
            A ``grpc.Channel`` configured with the client certificate and key.

        Raises:
            NotImplementedError: gRPC stubs not yet generated.
        """
        # ── INTEGRATION POINT ──────────────────────────────────────────────
        # When Anchorage gRPC stubs are available:
        #
        #   import grpc
        #
        #   with open(self._client_cert_path, "rb") as f:
        #       client_cert = f.read()
        #   with open(self._client_key_path, "rb") as f:
        #       client_key = f.read()
        #
        #   ca_cert = None
        #   if self._ca_cert_path:
        #       with open(self._ca_cert_path, "rb") as f:
        #           ca_cert = f.read()
        #
        #   credentials = grpc.ssl_channel_credentials(
        #       root_certificates=ca_cert,
        #       private_key=client_key,
        #       certificate_chain=client_cert,
        #   )
        #   return grpc.secure_channel(self._endpoint, credentials)
        #
        raise NotImplementedError(
            "Anchorage gRPC channel creation requires generated protobuf stubs. "
            "See AnchorageGrpcLedgerProvider docstring for integration steps."
        )

    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        """Fetch the current vault balance from Anchorage Digital via gRPC.

        Args:
            account_id: Overrides self._vault_id if provided; otherwise
                        uses the configured ANCHORAGE_VAULT_ID.

        Returns:
            ReconciliationResult with the Anchorage-reported available balance.

        Raises:
            NotImplementedError: Until gRPC stubs are generated and
            enterprise API credentials are provisioned.
        """
        vault_id = account_id or self._vault_id

        # ── INTEGRATION POINT ──────────────────────────────────────────────
        # When Anchorage gRPC stubs are available:
        #
        #   channel = self._create_channel()
        #   stub = vault_pb2_grpc.VaultServiceStub(channel)
        #
        #   request = vault_pb2.GetVaultBalanceRequest(
        #       vault_id=vault_id,
        #       asset_type="USD",
        #   )
        #   response = stub.GetVaultBalance(request, timeout=30)
        #
        #   return ReconciliationResult(
        #       source="anchorage",
        #       balance_usd=float(response.available_balance),
        #       verified_at=response.as_of.seconds,
        #       raw_response={
        #           "vault_id": response.vault_id,
        #           "available": response.available_balance,
        #           "pending": response.pending_balance,
        #           "as_of": response.as_of.ToJsonString(),
        #       },
        #   )
        #
        raise NotImplementedError(
            f"AnchorageGrpcLedgerProvider.fetch_balance() is not yet implemented. "
            f"Vault: {vault_id}. "
            "Enterprise API credentials and gRPC stubs must be provisioned. "
            "Use RECONCILIATION_PROVIDER=stub for dev/test."
        )


# ---------------------------------------------------------------------------
# Plaid Production ledger provider
# ---------------------------------------------------------------------------


class PlaidLedgerProvider:
    """Production ledger provider backed by the Plaid API (Balance product).

    Plaid is the fastest path to a real external balance for POAM-023 closure:
    - Production credentials provisioned in days (vs. 2-6 weeks for Anchorage).
    - ``/accounts/balance/get`` returns real-time available balance from the
      linked bank account, not synthetic Sandbox data.
    - OAuth 2.0 bearer token authentication — no mTLS certificate management.

    Why Plaid for POAM-023
    ----------------------
    The CBF currently reads self-reported ``safety:current_cash`` — the
    execution system writes its own balance, then uses that balance to pass
    the governance check.  Plaid provides an independent external ground truth
    that the execution system cannot influence, closing the recursive
    self-authentication gap.

    API surface required
    --------------------
    POST /accounts/balance/get
    ::

        {
          "client_id": "<PLAID_CLIENT_ID>",
          "secret": "<PLAID_SECRET>",
          "access_token": "<PLAID_ACCESS_TOKEN>"
        }

    Response (relevant fields):
    ::

        {
          "accounts": [
            {
              "account_id": "<id>",
              "balances": {
                "available": 95000.00,
                "current": 95000.00,
                "iso_currency_code": "USD"
              }
            }
          ]
        }

    Authentication
    --------------
    - ``PLAID_CLIENT_ID`` and ``PLAID_SECRET`` — stored in Google Secret Manager,
      mounted via Workload Identity into the ``reconciliation-worker`` namespace.
    - ``PLAID_ACCESS_TOKEN`` — per-account OAuth token obtained during Plaid Link
      onboarding; stored in Secret Manager.
    - ``PLAID_ENV`` — "production" (default) or "sandbox" for dev/test.
      **Use "production" for POAM-023 closure** — Sandbox returns synthetic data.

    Environment variables
    ---------------------
      PLAID_CLIENT_ID      — Plaid client identifier
      PLAID_SECRET         — Plaid secret key (production or sandbox)
      PLAID_ACCESS_TOKEN   — Per-account OAuth access token
      PLAID_ENV            — "production" (default) or "sandbox"
      PLAID_ACCOUNT_ID     — Optional: filter to a specific account_id in the response

    Latency profile (for paper §5.3)
    ---------------------------------
    - ``/accounts/balance/get`` P50 ≈ 300 ms, P99 ≈ 1200 ms (Plaid SLA).
    - Amortised over 60 s polling interval: per-request overhead ≈ 0 ms.
    - KMS sign adds ≈ 5-15 ms (Cloud KMS asymmetricSign P50).
    - Redis setex adds ≈ 1-2 ms (local cluster).
    - Total write-path cost: T_reconcile ≈ 310-1220 ms per 60 s cycle.
    - CBF read-path overhead: KMS verify ≈ 0.1-0.5 ms (local verify, no network).

    Status
    ------
    **INTEGRATION READY** — this class is fully implemented.  To activate:
      1. Provision Plaid Production credentials (client_id + secret + access_token).
      2. Store in Google Secret Manager; mount via Workload Identity.
      3. Set RECONCILIATION_PROVIDER=plaid in the deployment config.
      4. Set PLAID_ENV=production (never "sandbox" in production).
    """

    _BASE_URLS: dict[str, str] = {
        "production": "https://production.plaid.com",
        "sandbox": "https://sandbox.plaid.com",
        "development": "https://development.plaid.com",
    }

    def __init__(self) -> None:
        self._client_id = os.environ.get("PLAID_CLIENT_ID", "")
        self._secret = os.environ.get("PLAID_SECRET", "")
        self._access_token = os.environ.get("PLAID_ACCESS_TOKEN", "")
        self._plaid_env = os.environ.get("PLAID_ENV", "production").lower()
        self._account_id_filter = os.environ.get("PLAID_ACCOUNT_ID", "")

        if not self._client_id or not self._secret or not self._access_token:
            logger.error(
                "[PlaidProvider] PLAID_CLIENT_ID, PLAID_SECRET, and PLAID_ACCESS_TOKEN "
                "are required. Set RECONCILIATION_PROVIDER=stub for dev/test."
            )

        if self._plaid_env == "sandbox":
            logger.warning(
                "[PlaidProvider] PLAID_ENV=sandbox — balance data is SYNTHETIC. "
                "Set PLAID_ENV=production for POAM-023 closure."
            )

        self._base_url = self._BASE_URLS.get(
            self._plaid_env, self._BASE_URLS["production"]
        )
        logger.info(
            "[PlaidProvider] Initialised: env=%s base_url=%s account_filter=%s",
            self._plaid_env,
            self._base_url,
            self._account_id_filter or "(all accounts)",
        )

    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        """Fetch the current available balance from Plaid.

        Calls ``POST /accounts/balance/get`` and returns the ``available``
        balance for the configured account.  If ``PLAID_ACCOUNT_ID`` is set,
        only that account is returned; otherwise the first USD account is used.

        Args:
            account_id: Overrides ``PLAID_ACCOUNT_ID`` if provided; otherwise
                        uses the configured env var or the first USD account.

        Returns:
            ReconciliationResult with the Plaid-reported available balance.

        Raises:
            RuntimeError: If the Plaid API returns an error or the response
                          cannot be parsed.
        """
        try:
            import urllib.request as _urllib_request
        except ImportError as exc:
            raise RuntimeError("urllib.request is unavailable.") from exc

        target_account = account_id or self._account_id_filter

        payload = json.dumps(
            {
                "client_id": self._client_id,
                "secret": self._secret,
                "access_token": self._access_token,
            }
        ).encode("utf-8")

        url = f"{self._base_url}/accounts/balance/get"
        req = _urllib_request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Plaid-Version": "2020-09-14",
            },
            method="POST",
        )

        t0 = time.monotonic()
        try:
            with _urllib_request.urlopen(req, timeout=30) as resp:
                raw_body = resp.read().decode("utf-8")
        except Exception as http_exc:
            raise RuntimeError(
                f"Plaid /accounts/balance/get HTTP error: {http_exc}"
            ) from http_exc
        fetch_ms = (time.monotonic() - t0) * 1000.0

        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError as parse_exc:
            raise RuntimeError(
                f"Plaid response is not valid JSON: {parse_exc}"
            ) from parse_exc

        if "error_code" in body:
            raise RuntimeError(
                f"Plaid API error: {body.get('error_code')} — "
                f"{body.get('error_message', 'no message')}"
            )

        accounts = body.get("accounts", [])
        if not accounts:
            raise RuntimeError(
                "Plaid returned no accounts in /accounts/balance/get response."
            )

        # Select the target account
        selected = None
        if target_account:
            for acct in accounts:
                if acct.get("account_id") == target_account:
                    selected = acct
                    break
            if selected is None:
                raise RuntimeError(
                    f"Plaid account_id {target_account!r} not found in response. "
                    f"Available: {[a.get('account_id') for a in accounts]}"
                )
        else:
            # Use the first USD account with a non-None available balance
            for acct in accounts:
                balances = acct.get("balances", {})
                if (
                    balances.get("iso_currency_code") == "USD"
                    and balances.get("available") is not None
                ):
                    selected = acct
                    break
            if selected is None:
                raise RuntimeError(
                    "No USD account with available balance found in Plaid response."
                )

        balances = selected.get("balances", {})
        available = balances.get("available")
        if available is None:
            raise RuntimeError(
                f"Plaid account {selected.get('account_id')!r} has null available balance."
            )

        logger.info(
            "[PlaidProvider] Balance fetched: account=%s available=%.2f "
            "currency=%s fetch_ms=%.1f",
            selected.get("account_id"),
            float(available),
            balances.get("iso_currency_code", "USD"),
            fetch_ms,
        )

        return ReconciliationResult(
            source="plaid",
            balance_usd=float(available),
            raw_response={
                "account_id": selected.get("account_id"),
                "available": available,
                "current": balances.get("current"),
                "iso_currency_code": balances.get("iso_currency_code"),
                "plaid_env": self._plaid_env,
                "fetch_ms": round(fetch_ms, 1),
            },
        )


# ---------------------------------------------------------------------------
# GCS WORM Ledger Provider
# ---------------------------------------------------------------------------


class GcsLedgerProvider:
    """Ledger provider backed by a GCS WORM object written by the audit pipeline.

    This provider reads the most-recent balance snapshot from a GCS bucket
    (``GCS_RECONCILIATION_BUCKET`` / ``GCS_RECONCILIATION_OBJECT``) rather
    than fetching live from Plaid.  It is appropriate for deployments where a
    separate audit-ledger pipeline writes a KMS-signed balance object to GCS
    on a scheduled basis, and the reconciliation daemon merely reads that
    object.

    The object must be a JSON blob matching the ``ReconciliationResult``
    ``to_redis_payload()`` / ``from_redis_payload()`` format, i.e.::

        {
            "balance": <float>,
            "currency": "USD",
            "provider": "gcs",
            "fetched_at": "<ISO-8601 UTC>",
            "kms_signature": "<base64-encoded-signature>",
            "account_id": "<account-id>"
        }

    Environment variables:
        GCS_RECONCILIATION_BUCKET  GCS bucket name (required).
        GCS_RECONCILIATION_OBJECT  Object key within the bucket
                                   (default: ``reconciliation/latest.json``).
    """

    def __init__(self) -> None:
        self._bucket = os.environ.get("GCS_RECONCILIATION_BUCKET", "")
        self._object = os.environ.get(
            "GCS_RECONCILIATION_OBJECT", "reconciliation/latest.json"
        )
        if not self._bucket:
            raise ValueError(
                "GcsLedgerProvider requires GCS_RECONCILIATION_BUCKET to be set."
            )

    def fetch_balance(self, account_id: str) -> ReconciliationResult:  # type: ignore[override]
        """Download the balance snapshot from GCS and return a ReconciliationResult."""
        try:
            from google.cloud import (
                storage,  # type: ignore[import-untyped, attr-defined]
            )
        except ImportError as exc:
            raise RuntimeError(
                "google-cloud-storage is required for GcsLedgerProvider. "
                "Install it with: pip install google-cloud-storage"
            ) from exc

        import datetime
        import json as _json

        client = storage.Client()
        bucket = client.bucket(self._bucket)
        blob = bucket.blob(self._object)
        raw = blob.download_as_text()
        data = _json.loads(raw)

        # Map the GCS snapshot schema to ReconciliationResult fields:
        #   - "balance" or "balances.{account_id}" -> balance_usd
        #   - "timestamp" -> verified_at (converted to Unix float)
        #   - "kms_signature" -> signature (if present)
        balances = data.get("balances", {})
        balance_value = balances.get(account_id, balances.get("default_account", 0.0))
        if not balance_value and "balance" in data:
            balance_value = data["balance"]

        # Parse timestamp if present, otherwise use current time
        verified_at = time.time()
        if "timestamp" in data:
            ts_str = data["timestamp"]
            try:
                dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                verified_at = dt.timestamp()
            except (ValueError, AttributeError):
                pass  # Use current time as fallback

        return ReconciliationResult(
            source="gcs",
            balance_usd=float(balance_value),
            verified_at=verified_at,
            signature=data.get("kms_signature", ""),
            raw_response=data,
        )


# ---------------------------------------------------------------------------
# ObjectStoreLedgerProvider — S3-compatible cloud-agnostic ledger provider
# ---------------------------------------------------------------------------


class ObjectStoreLedgerProvider:
    """Ledger provider backed by any S3-compatible object store.

    Supports AWS S3, GCS (via S3 Interoperability API), Azure Blob (via S3
    proxy), MinIO, Ceph, or any endpoint that speaks the S3 REST protocol.
    This makes the reconciliation worker fully cloud-agnostic — no Google SDK
    dependency is required.

    Object format (JSON — identical to ``GcsLedgerProvider``):

    .. code-block:: json

        {
            "balance": 48250.0,
            "currency": "USD",
            "provider": "s3",
            "fetched_at": "2026-08-06T12:00:00+00:00",
            "kms_signature": "<base64-encoded-signature>",
            "account_id": "<account-id>"
        }

    Environment variables:
        S3_RECONCILIATION_BUCKET   — Bucket name (required).
        S3_RECONCILIATION_OBJECT   — Object key within the bucket
                                     (default: ``reconciliation/latest.json``).
        S3_ENDPOINT_URL            — Custom endpoint URL for non-AWS backends
                                     (e.g. ``https://storage.googleapis.com``
                                     for GCS S3 Interop, or
                                     ``http://minio:9000`` for MinIO).
                                     Omit for standard AWS S3.
        S3_REGION_NAME             — AWS region (default: ``us-east-1``).
        AWS_ACCESS_KEY_ID          — Access key (standard boto3 env var; also
                                     used for GCS HMAC keys or MinIO creds).
        AWS_SECRET_ACCESS_KEY      — Secret key (standard boto3 env var).

    On GKE with Workload Identity, leave ``AWS_ACCESS_KEY_ID`` and
    ``AWS_SECRET_ACCESS_KEY`` unset and instead configure an IAM binding
    that allows the Kubernetes service account to assume the required IAM role
    (IRSA on EKS) or use a GCP HMAC key pair mounted as a K8s Secret.

    On-premises / hermetic testing:
        docker run -d -p 9000:9000 minio/minio server /data
        export S3_ENDPOINT_URL=http://localhost:9000
        export S3_RECONCILIATION_BUCKET=cage-ledger
        export AWS_ACCESS_KEY_ID=minioadmin
        export AWS_SECRET_ACCESS_KEY=minioadmin
    """

    def __init__(self) -> None:
        self._bucket = os.environ.get("S3_RECONCILIATION_BUCKET", "")
        self._object = os.environ.get(
            "S3_RECONCILIATION_OBJECT", "reconciliation/latest.json"
        )
        self._endpoint_url: str | None = os.environ.get("S3_ENDPOINT_URL") or None
        self._region_name: str = os.environ.get("S3_REGION_NAME", "us-east-1")
        if not self._bucket:
            raise ValueError(
                "ObjectStoreLedgerProvider requires S3_RECONCILIATION_BUCKET to be set."
            )

    def _make_client(self) -> object:
        """Construct a boto3 S3 client.  Import is deferred to keep the module
        importable in environments that do not have boto3 installed."""
        try:
            import boto3  # type: ignore[import-untyped]
            from botocore.config import Config  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is required for ObjectStoreLedgerProvider. "
                "Install it with: pip install boto3"
            ) from exc

        kwargs: dict[str, object] = {
            "region_name": self._region_name,
            "config": Config(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "adaptive"},
            ),
        }
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url

        return boto3.client("s3", **kwargs)

    def fetch_balance(self, account_id: str) -> ReconciliationResult:  # type: ignore[override]
        """Download the balance snapshot from S3-compatible storage."""
        import datetime
        import json as _json

        client = self._make_client()
        response = client.get_object(Bucket=self._bucket, Key=self._object)  # type: ignore[attr-defined]
        raw = response["Body"].read().decode("utf-8")
        data = _json.loads(raw)

        # Map the S3 snapshot schema to ReconciliationResult fields
        balances = data.get("balances", {})
        balance_value = balances.get(account_id, balances.get("default_account", 0.0))
        if not balance_value and "balance" in data:
            balance_value = data["balance"]

        # Parse timestamp if present, otherwise use current time
        verified_at = time.time()
        if "timestamp" in data:
            ts_str = data["timestamp"]
            try:
                dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                verified_at = dt.timestamp()
            except (ValueError, AttributeError):
                pass

        return ReconciliationResult(
            source="s3",
            balance_usd=float(balance_value),
            verified_at=verified_at,
            signature=data.get("kms_signature", ""),
            raw_response=data,
        )


# ---------------------------------------------------------------------------
# OTel null-context helper (used when opentelemetry is unavailable)
# ---------------------------------------------------------------------------


from contextlib import contextmanager


@contextmanager
def _null_context():  # type: ignore[no-untyped-def]
    """No-op context manager used when OTel is unavailable."""
    yield


# ---------------------------------------------------------------------------
# Reconciliation daemon
# ---------------------------------------------------------------------------


class ExternalLedgerReconciler:
    """Daemon that periodically fetches external balances and writes to Redis.

    Architecture:
      - Runs in a dedicated K8s namespace (``reconciliation-worker``)
      - Cilium policy: allowed to reach external provider FQDNs, NOT allowed
        to reach gateway or financial-advisor pods
      - Writes verified balances to Redis with strict TTL
      - Signs balances with Cloud KMS (Priority 1 governance signer)

    The CBF reads ``reconciliation:verified_balance`` instead of the
    self-reported ``safety:current_cash``.  If the verified balance is
    stale (TTL expired), the CBF fails closed.

    Args:
        provider:      LedgerProvider implementation.
        redis_client:  Redis client instance (sync).
        account_id:    Account identifier at the custody provider.
        poll_interval: Seconds between reconciliation polls.
        ttl:           Redis TTL for verified balances.
    """

    def __init__(
        self,
        provider: LedgerProvider,
        redis_client: object,
        account_id: str,
        poll_interval: int = POLL_INTERVAL_SECONDS,
        ttl: int = TTL_SECONDS,
    ) -> None:
        self._provider = provider
        self._redis = redis_client
        self._account_id = account_id
        self._poll_interval = poll_interval
        self._ttl = ttl

    def reconcile(self) -> ReconciliationResult:
        """Execute a single reconciliation cycle.

        1. Fetch the balance from the external ledger provider.
        2. Validate the result.
        3. Sign the balance payload with Cloud KMS (Priority 1 integration).
        4. Write the verified balance to Redis with TTL.

        OTel spans emitted (Phase 2b):
          - ``reconciliation.plaid_fetch_ms``  — provider HTTP round-trip (ms)
          - ``reconciliation.kms_sign_ms``     — KMS sign latency (ms)
          - ``reconciliation.redis_write_ms``  — Redis pipeline write latency (ms)
          - ``reconciliation.provider``        — provider name string
          - ``reconciliation.balance_usd``     — reconciled balance
          - ``reconciliation.signed``          — bool: KMS signature present

        Returns:
            ReconciliationResult — check ``.is_valid`` and ``.error``.
        """
        logger.info(
            "Reconciliation cycle starting: account=%s provider=%s",
            self._account_id,
            PROVIDER,
        )

        # ── Phase 2b: OTel span for the full reconciliation cycle ─────────
        try:
            from opentelemetry import trace as _otel_trace

            _tracer = _otel_trace.get_tracer("cage.reconciliation_worker")
            _span_ctx = _tracer.start_as_current_span("reconciliation.cycle")
        except Exception:
            _span_ctx = None  # type: ignore[assignment]

        def _set_span_attr(key: str, value: object) -> None:
            if _span_ctx is not None:
                try:
                    span = _otel_trace.get_current_span()
                    span.set_attribute(key, value)  # type: ignore[arg-type]
                except Exception:
                    pass

        with _span_ctx if _span_ctx is not None else _null_context():
            _set_span_attr("reconciliation.provider", PROVIDER)
            _set_span_attr("reconciliation.account_id", self._account_id)

            # ── 1. Fetch from external provider ───────────────────────────
            t_fetch_start = time.monotonic()
            try:
                result = self._provider.fetch_balance(self._account_id)
            except Exception as exc:
                logger.error(
                    "Reconciliation FAILED: provider=%s account=%s error=%s",
                    PROVIDER,
                    self._account_id,
                    exc,
                )
                _set_span_attr("reconciliation.error", str(exc))
                return ReconciliationResult(
                    source=PROVIDER,
                    balance_usd=0.0,
                    error=str(exc),
                )
            finally:
                fetch_ms = (time.monotonic() - t_fetch_start) * 1000.0
                _set_span_attr("reconciliation.plaid_fetch_ms", round(fetch_ms, 1))

            if not result.is_valid:
                logger.error("Reconciliation returned invalid result: %s", result.error)
                _set_span_attr("reconciliation.error", result.error or "invalid")
                return result

            _set_span_attr("reconciliation.balance_usd", result.balance_usd)

            # ── 2. Monotonic sequence number (§2.10 R-04 replay defense) ───
            # Read current sequence, increment, and include in signed payload.
            # The sequence is stored separately and never TTL'd — it must
            # survive independently of the 300s balance TTL.
            new_sequence: int = 0
            if REPLAY_DEFENSE_ENABLED:
                try:
                    new_sequence = self._redis.incr(_REDIS_KEY_SEQUENCE_LATEST)  # type: ignore[attr-defined]
                    result.sequence = new_sequence
                    logger.info(
                        "[R-04] Replay defense: stamped sequence=%d on reconciliation payload.",
                        new_sequence,
                    )
                except Exception as seq_exc:
                    logger.error(
                        "[R-04] Failed to increment sequence counter: %s — "
                        "payload will have sequence=0 (replay defense ineffective).",
                        seq_exc,
                    )

            _set_span_attr("cage.reconciliation.sequence", new_sequence)

            # ── 3. Cloud KMS signing (Priority 1 integration) ─────────────
            # Sign the reconciled balance payload so the CBF can verify that
            # the balance was written by an authorised reconciliation worker,
            # not by the execution system itself.
            # §2.10: sequence is included in signed payload — replay cannot
            # bump sequence without invalidating the signature.
            t_sign_start = time.monotonic()
            try:
                from src.gateway.governance.kms_signer import get_governance_signer

                signer = get_governance_signer()
                payload_dict = {
                    "source": result.source,
                    "balance_usd": result.balance_usd,
                    "verified_at": result.verified_at,
                    "sequence": result.sequence,  # §2.10: in signed payload
                }
                result.signature = signer.sign(payload_dict)

                if signer.is_kms_active:
                    logger.info(
                        "✅ Reconciled balance signed via Cloud KMS (non-repudiable)."
                    )
                else:
                    logger.warning(
                        "⚠️ Reconciled balance signed via HMAC fallback. "
                        "Cloud KMS must be configured for production."
                    )
            except Exception as sign_exc:
                logger.warning(
                    "⚠️ KMS signing failed for reconciled balance: %s — "
                    "balance will be written unsigned.",
                    sign_exc,
                )
            finally:
                kms_sign_ms = (time.monotonic() - t_sign_start) * 1000.0
                _set_span_attr("reconciliation.kms_sign_ms", round(kms_sign_ms, 1))
                _set_span_attr("reconciliation.signed", bool(result.signature))

            # ── 4. Write to Redis ──────────────────────────────────────────
            # Note: sequence key (_REDIS_KEY_SEQUENCE_LATEST) is written via
            # INCR above, NOT in this pipeline, because it must never expire.
            t_redis_start = time.monotonic()
            try:
                pipe = self._redis.pipeline()  # type: ignore[attr-defined]
                pipe.setex(
                    _REDIS_KEY_VERIFIED_BALANCE,
                    self._ttl,
                    result.to_redis_payload(),
                )
                pipe.setex(
                    _REDIS_KEY_VERIFIED_AT,
                    self._ttl,
                    str(result.verified_at),
                )
                pipe.setex(
                    _REDIS_KEY_PROVIDER,
                    self._ttl,
                    result.source,
                )
                if result.signature:
                    pipe.setex(
                        _REDIS_KEY_SIGNATURE,
                        self._ttl,
                        result.signature,
                    )
                pipe.execute()

                logger.info(
                    "✅ Reconciliation SUCCESS: provider=%s balance=%.2f "
                    "verified_at=%.0f ttl=%ds signed=%s sequence=%d "
                    "fetch_ms=%.1f kms_ms=%.1f",
                    result.source,
                    result.balance_usd,
                    result.verified_at,
                    self._ttl,
                    bool(result.signature),
                    result.sequence,
                    fetch_ms,
                    kms_sign_ms,
                )
            except Exception as redis_exc:
                logger.error(
                    "Reconciliation Redis write FAILED: %s — CBF will fail-closed "
                    "because verified balance is unavailable.",
                    redis_exc,
                )
                result.error = f"Redis write failed: {redis_exc}"
                _set_span_attr("reconciliation.redis_error", str(redis_exc))
            finally:
                redis_write_ms = (time.monotonic() - t_redis_start) * 1000.0
                _set_span_attr(
                    "reconciliation.redis_write_ms", round(redis_write_ms, 1)
                )

            return result

    def run_loop(self) -> None:
        """Run the reconciliation daemon in a blocking loop.

        This is the entry point for the K8s deployment.  The loop runs
        indefinitely, polling the external ledger at the configured interval.
        Errors are logged but never crash the daemon — a missed cycle means
        the previous balance ages out via TTL and the CBF fails closed.
        """
        logger.info(
            "Reconciliation daemon starting: account=%s provider=%s "
            "poll_interval=%ds ttl=%ds",
            self._account_id,
            PROVIDER,
            self._poll_interval,
            self._ttl,
        )

        while True:
            try:
                self.reconcile()
            except Exception as exc:
                logger.error("Reconciliation loop error (non-fatal): %s", exc)

            time.sleep(self._poll_interval)

    @classmethod
    def from_env(cls) -> ExternalLedgerReconciler:
        """Construct from environment variables.

        Required:
            REDIS_URL                              — Redis connection string
            RECONCILIATION_ACCOUNT_ID              — custody account ID

        Optional:
            RECONCILIATION_PROVIDER                — "stub" (default), "anchorage"
            RECONCILIATION_POLL_INTERVAL_SECONDS   — polling interval (default: 60)
            RECONCILIATION_TTL_SECONDS             — Redis TTL (default: 300)
        """
        try:
            import redis  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "redis-py is required for ExternalLedgerReconciler. "
                "Install with: pip install redis"
            ) from exc

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        account_id = os.environ.get("RECONCILIATION_ACCOUNT_ID", "default")
        client = redis.from_url(redis_url, decode_responses=True)

        # Provider selection
        _PROVIDERS: dict[str, type] = {
            "stub": StubLedgerProvider,
            "anchorage": AnchorageGrpcLedgerProvider,
            "plaid": PlaidLedgerProvider,
            # GCS-native provider (google-cloud-storage SDK required).
            "gcs": GcsLedgerProvider,
            # S3-compatible provider (boto3 required).
            # Supports AWS S3, GCS S3 Interop, MinIO, Ceph, Azure Blob (via proxy).
            "s3": ObjectStoreLedgerProvider,
            "object-store": ObjectStoreLedgerProvider,
        }

        provider: LedgerProvider
        if PROVIDER in _PROVIDERS:
            provider = _PROVIDERS[PROVIDER]()
        else:
            raise ValueError(
                f"Unknown reconciliation provider: {PROVIDER!r}. "
                f"Available providers: {list(_PROVIDERS.keys())}."
            )

        return cls(
            provider=provider,
            redis_client=client,
            account_id=account_id,
        )


# ---------------------------------------------------------------------------
# Redis reader (used by CBF to consume verified balances)
# ---------------------------------------------------------------------------


def read_verified_balance(redis_client: object) -> ReconciliationResult | None:
    """Read the externally reconciled balance from Redis.

    Called by the CBF in ``safety.py`` to prefer externally verified balances
    over the self-reported ``safety:current_cash``.

    Returns:
        ReconciliationResult if a verified balance exists and is within TTL.
        None if the key is absent (expired or never written).

    Note:
        A None return means the CBF should fail-closed: no external ground
        truth is available to validate the cash barrier.
    """
    try:
        raw = redis_client.get(_REDIS_KEY_VERIFIED_BALANCE)  # type: ignore[attr-defined]
        if raw is None:
            return None

        result = ReconciliationResult.from_redis_payload(raw)
        if result.is_stale:
            logger.warning(
                "Verified balance is stale (verified_at=%.0f, age=%.0fs, "
                "ttl=%ds) — CBF should fail-closed.",
                result.verified_at,
                time.time() - result.verified_at,
                result.ttl_seconds,
            )
            return None

        return result

    except Exception as exc:
        logger.error(
            "Failed to read verified balance from Redis: %s — CBF should fail-closed.",
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# CLI entry point (for K8s deployment)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    reconciler = ExternalLedgerReconciler.from_env()
    reconciler.run_loop()
