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

"""Inference backend selection (``CAGE_INFERENCE_BACKEND``).

The inference backend is orthogonal to jurisdiction: the posture selects
policies, residency and compliance manifests, and this setting says whether a
model exists at all.

- ``none``: no model. OPA, CBF, STPA, the evidence chain and HITL run as
  usual. Every model-dependent check refuses with its own reason code instead
  of admitting or reaching for a default URL, and no NeMo rails are built.
- ``stub``: deterministic OpenAI-compatible test/staging stub backend
  (POAM-2026-191). The gateway inference proxy forwards ``/v1/chat/completions``
  to ``VLLM_BASE_URL`` (the ``inference-stub`` Service), while semantic LLM
  rails, LLM consensus critics, and LLM remediation narratives stay off just as
  under ``none``. Refused in ``PRODUCTION`` posture.
- ``external``: a model served outside the cluster.
- ``vllm``: in-cluster vLLM.

``stub``, ``external`` and ``vllm`` all need ``VLLM_BASE_URL`` and
``VLLM_API_KEY``.

Unset keeps the behaviour from before this setting existed: a backend is
required. ``none`` and ``stub`` are always explicit and never inferred from a
missing URL. An unknown value fails startup.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from enum import Enum
from typing import Final

ENV_VAR: Final[str] = "CAGE_INFERENCE_BACKEND"

# Reason codes for model-dependent paths that cannot run.
INFERENCE_BACKEND_NONE: Final[str] = "INFERENCE_BACKEND_NONE"
INFERENCE_BACKEND_STUB: Final[str] = "INFERENCE_BACKEND_STUB"
INFERENCE_BACKEND_URL_MISSING: Final[str] = "INFERENCE_BACKEND_URL_MISSING"


class InferenceBackend(str, Enum):
    """Where model inference comes from, if anywhere."""

    NONE = "none"
    STUB = "stub"
    EXTERNAL = "external"
    VLLM = "vllm"


class InferenceBackendConfigError(RuntimeError):
    """The inference backend configuration is invalid; startup must fail."""


class InferenceBackendUnavailable(RuntimeError):
    """A model-dependent path was reached with no usable backend.

    ``str()`` leads with the reason code, so a caller that records the error
    text records the code too.
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(f"{reason_code}: {message}")
        self.reason_code = reason_code


def resolve_inference_backend(
    environ: Mapping[str, str] | None = None,
) -> InferenceBackend | None:
    """Return the configured backend, or ``None`` when the setting is unset.

    Raises:
        InferenceBackendConfigError: for a value that is not ``none``,
            ``stub``, ``external`` or ``vllm``.
    """
    env = os.environ if environ is None else environ
    raw = env.get(ENV_VAR)
    if raw is None or not raw.strip():
        return None
    try:
        return InferenceBackend(raw.strip().lower())
    except ValueError:
        allowed = ", ".join(b.value for b in InferenceBackend)
        raise InferenceBackendConfigError(
            f"{ENV_VAR}={raw!r} is not one of: {allowed}"
        ) from None


def inference_disabled(environ: Mapping[str, str] | None = None) -> bool:
    """True when the process runs with no model endpoint (``CAGE_INFERENCE_BACKEND=none``)."""
    return resolve_inference_backend(environ) is InferenceBackend.NONE


def semantic_model_disabled(environ: Mapping[str, str] | None = None) -> bool:
    """True when no semantic LLM exists (``none`` or deterministic ``stub``)."""
    return resolve_inference_backend(environ) in (
        InferenceBackend.NONE,
        InferenceBackend.STUB,
    )


def semantic_model_reason_code(
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Return the reason code when semantic LLM features are off by backend, else ``None``."""
    backend = resolve_inference_backend(environ)
    if backend is InferenceBackend.NONE:
        return INFERENCE_BACKEND_NONE
    if backend is InferenceBackend.STUB:
        return INFERENCE_BACKEND_STUB
    return None


def require_backend_settings(get: Callable[[str], str | None]) -> None:
    """Fail startup when a model backend is required but not configured.

    Args:
        get: Setting reader, e.g. ``config_manager.get`` or ``os.environ.get``.

    Raises:
        InferenceBackendConfigError: when ``VLLM_BASE_URL`` or
            ``VLLM_API_KEY`` is missing.
    """
    if not get("VLLM_BASE_URL"):
        raise InferenceBackendConfigError(
            "VLLM_BASE_URL must be set — no localhost fallback in production."
        )
    if not get("VLLM_API_KEY"):
        raise InferenceBackendConfigError(
            "VLLM_API_KEY must be set — no 'EMPTY' fallback in production."
        )
