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
Config — Connection and service configuration (environment variables).

This class manages LLM endpoint URLs, API keys, and service addresses.
It does NOT manage governance thresholds — those are in GovernanceThresholds.

Future consolidation (R-14): This class will be merged into a unified
Pydantic BaseSettings class combining Config + ConfigManager.
"""

import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    # --- MODEL IDENTIFIERS ---
    # These MUST be provided by the .env configuration.
    MODEL_REASONING = os.getenv("MODEL_REASONING")
    DEFAULT_REASONING_MODEL = MODEL_REASONING  # For backward compatibility
    MODEL_FAST = os.getenv("MODEL_FAST")
    MODEL_CONSENSUS = os.getenv("MODEL_CONSENSUS", MODEL_REASONING)

    # Optional model overrides for specific subsystems.
    # If unset, each subsystem falls back to MODEL_FAST or MODEL_REASONING.
    TRANSPILER_MODEL = os.getenv(
        "TRANSPILER_MODEL"
    )  # Policy Transpiler; falls back to MODEL_FAST
    VLLM_FAST_MODEL = os.getenv(
        "VLLM_FAST_MODEL"
    )  # StructuredLLMClient; falls back to MODEL_FAST
    REMEDIATION_MODEL = os.getenv(
        "REMEDIATION_MODEL"
    )  # Compliance remediation; falls back to MODEL_REASONING

    # Node A: The Brain (Reasoning/Planner)
    VLLM_REASONING_API_BASE = os.getenv("VLLM_REASONING_API_BASE")

    # Node B: The Police (Governance/FSM)
    # vLLM / Model Serving
    VLLM_BASE_URL = os.getenv("VLLM_BASE_URL")
    VLLM_API_KEY = os.getenv("VLLM_API_KEY")

    # Gateway Configuration
    GATEWAY_URL = os.getenv("GATEWAY_URL")
    GATEWAY_API_BASE = f"{GATEWAY_URL}/v1" if GATEWAY_URL else None
    MCP_SERVER_SSE_URL = os.getenv(
        "MCP_SERVER_SSE_URL", f"{GATEWAY_URL}/mcp/sse" if GATEWAY_URL else None
    )
    VLLM_FAST_API_BASE = os.getenv("VLLM_FAST_API_BASE")

    MAX_TOKENS = int(os.getenv("MAX_TOKENS", 8192))

    # --- INFRASTRUCTURE ---
    GOOGLE_CLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")
    # GOOGLE_CLOUD_LOCATION: Required only when using GCP KMS or GCS.
    # Set explicitly (e.g., "us-central1", "europe-west1", "asia-southeast1").
    # Leave unset when using non-GCP storage/KMS backends.
    GOOGLE_CLOUD_LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "")
    PORT = int(os.getenv("PORT", 8080))
    REDIS_URL = os.getenv("REDIS_URL", "")
    GOVERNANCE_SALT = os.getenv(
        "GOVERNANCE_SALT"
    )  # Legacy fallback — see kms_signer.py

    # --- CLOUD KMS GOVERNANCE SIGNING (Priority 1) ---
    # Replaces GOVERNANCE_SALT with HSM-backed asymmetric signing.
    # In production: set KMS_GOVERNANCE_KEY to the full key version resource name.
    # The private key never leaves the KMS HSM; signatures are non-repudiable.
    # See: src/gateway/governance/kms_signer.py
    KMS_GOVERNANCE_KEY = os.getenv("KMS_GOVERNANCE_KEY")
    KMS_GOVERNANCE_PUBLIC_PEM = os.getenv("KMS_GOVERNANCE_PUBLIC_PEM", "")

    # Sidecars
    OPA_URL = os.getenv("OPA_URL")
    OPA_AUTH_TOKEN = os.getenv("OPA_AUTH_TOKEN")
    SANDBOX_URL = os.getenv("SANDBOX_URL")

    # --- KUBERNETES INFERENCE GATEWAY ---
    # If this is set, GatewayClient will route all requests here.
    # Supports any Kubernetes-hosted vLLM/inference server (GKE, EKS, AKS, on-prem, etc.)
    # Otherwise, it falls back to the split-brain URLs above.
    VLLM_GATEWAY_URL = os.getenv("VLLM_GATEWAY_URL")

    # --- LangSmith ---
    LANGCHAIN_TRACING_V2 = os.getenv("LANGCHAIN_TRACING_V2", "true")
    LANGCHAIN_PROJECT = os.getenv("LANGCHAIN_PROJECT", "financial-advisor")


import logging as _logging

_settings_logger = _logging.getLogger(__name__)

REQUIRED_ENV_VARS = [
    "VLLM_BASE_URL",
    "VLLM_REASONING_API_BASE",
    "VLLM_FAST_API_BASE",
    "OPA_URL",
    "GATEWAY_URL",
]


def validate_required_settings():
    """Call at application startup to fail fast if required env vars are missing."""
    missing = [
        var
        for var in REQUIRED_ENV_VARS
        if not globals().get(var.replace("-", "_"))
        and not __import__("os").environ.get(var)
    ]
    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "No localhost fallbacks are permitted in production."
        )
    _settings_logger.info(
        "Settings validated: all required environment variables are set."
    )


