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
# Production guard (BLOCKER-06)
# ---------------------------------------------------------------------------
# The stub provider fabricates a static $100k balance.  If the CBF evaluates
# against this fake number in production, the safety barrier is meaningless.
# Block startup immediately so the misconfiguration cannot be silently deployed.

if os.environ.get("ENVIRONMENT") == "production" and PROVIDER == "stub":
    raise RuntimeError(
        "RECONCILIATION_PROVIDER=stub is not allowed in production. "
        "Set a real ledger provider (e.g. RECONCILIATION_PROVIDER=anchorage)."
    )

# Redis key schema
_REDIS_KEY_VERIFIED_BALANCE = "reconciliation:verified_balance"
_REDIS_KEY_VERIFIED_AT = "reconciliation:verified_at"
_REDIS_KEY_PROVIDER = "reconciliation:provider"
_REDIS_KEY_SIGNATURE = "reconciliation:signature"


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
    """

    source: str
    balance_usd: float
    verified_at: float = field(default_factory=time.time)
    signature: str = ""
    ttl_seconds: int = TTL_SECONDS
    raw_response: dict | None = None
    error: str | None = None

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

        Returns:
            ReconciliationResult — check ``.is_valid`` and ``.error``.
        """
        logger.info(
            "Reconciliation cycle starting: account=%s provider=%s",
            self._account_id,
            PROVIDER,
        )

        try:
            result = self._provider.fetch_balance(self._account_id)
        except Exception as exc:
            logger.error(
                "Reconciliation FAILED: provider=%s account=%s error=%s",
                PROVIDER,
                self._account_id,
                exc,
            )
            return ReconciliationResult(
                source=PROVIDER,
                balance_usd=0.0,
                error=str(exc),
            )

        if not result.is_valid:
            logger.error("Reconciliation returned invalid result: %s", result.error)
            return result

        # ── Cloud KMS signing (Priority 1 integration) ────────────────────
        # Sign the reconciled balance payload so the CBF can verify that the
        # balance was written by an authorised reconciliation worker, not by
        # the execution system itself.
        try:
            from src.gateway.governance.kms_signer import get_governance_signer

            signer = get_governance_signer()
            payload_dict = {
                "source": result.source,
                "balance_usd": result.balance_usd,
                "verified_at": result.verified_at,
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

        # ── Write to Redis ─────────────────────────────────────────────────
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
                "verified_at=%.0f ttl=%ds signed=%s",
                result.source,
                result.balance_usd,
                result.verified_at,
                self._ttl,
                bool(result.signature),
            )
        except Exception as redis_exc:
            logger.error(
                "Reconciliation Redis write FAILED: %s — CBF will fail-closed "
                "because verified balance is unavailable.",
                redis_exc,
            )
            result.error = f"Redis write failed: {redis_exc}"

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
