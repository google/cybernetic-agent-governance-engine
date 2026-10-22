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

"""Cached LLM client factory for the Governed Financial Advisor.

Constructs ``ChatOpenAI`` instances once per ``(role, model, base_url,
temperature, max_tokens, extra_body)`` configuration with bounded timeouts
(``httpx.Timeout(connect=3.0, read=60.0, write=10.0, pool=3.0)``) and
``max_retries=1`` so individual graph nodes never rebuild HTTP client pools on
every invocation.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Literal

import httpx
from langchain_openai import ChatOpenAI

LLMRole = Literal["reasoning", "fast"]

DEFAULT_LLM_TIMEOUT = httpx.Timeout(connect=3.0, read=60.0, write=10.0, pool=3.0)
DEFAULT_LLM_MAX_RETRIES = 1

_llm_cache: dict[tuple[Any, ...], ChatOpenAI] = {}
_llm_cache_lock = threading.Lock()


def clear_chat_model_cache() -> None:
    """Clear the cached ``ChatOpenAI`` instances (for test isolation)."""
    with _llm_cache_lock:
        _llm_cache.clear()


def chat_model(
    role: LLMRole = "fast",
    *,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    model_kwargs: dict[str, Any] | None = None,
    require_api_key: bool = False,
    api_key_error_cls: type[Exception] = RuntimeError,
) -> ChatOpenAI:
    """Return a cached ``ChatOpenAI`` instance for ``role`` and parameters.

    Args:
        role: ``"reasoning"`` (uses ``VLLM_REASONING_API_BASE`` / ``MODEL_REASONING``)
            or ``"fast"`` (uses ``VLLM_FAST_API_BASE`` / ``MODEL_FAST``).
        model: Explicit model override; defaults to ``MODEL_REASONING`` or ``MODEL_FAST``.
        base_url: Explicit endpoint override; defaults to ``VLLM_REASONING_API_BASE``
            or ``VLLM_FAST_API_BASE``.
        api_key: Explicit API key override; defaults to ``OPENAI_API_KEY``.
        temperature: Sampling temperature (defaults to ``0.6`` for ``"reasoning"``,
            ``0.0`` for ``"fast"``).
        max_tokens: Optional output token cap.
        model_kwargs: Optional extra kwargs (e.g. ``{"extra_body": {"guided_json": ...}}``).
        require_api_key: When ``True``, raises ``api_key_error_cls`` if no API key is set.
        api_key_error_cls: Exception class to raise when ``require_api_key=True`` and
            ``OPENAI_API_KEY`` is missing.
    """
    env_var_base = (
        "VLLM_REASONING_API_BASE" if role == "reasoning" else "VLLM_FAST_API_BASE"
    )
    env_var_model = "MODEL_REASONING" if role == "reasoning" else "MODEL_FAST"

    resolved_base = base_url if base_url is not None else os.environ.get(env_var_base)
    if not resolved_base:
        raise RuntimeError(
            f"{env_var_base} must be set — no localhost fallback in production"
        )

    resolved_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY")
    if require_api_key and not resolved_key:
        raise api_key_error_cls(
            "OPENAI_API_KEY must be set — no default is allowed in production"
        )

    resolved_model = model if model is not None else os.environ.get(env_var_model)
    resolved_temp = (
        temperature
        if temperature is not None
        else (0.6 if role == "reasoning" else 0.0)
    )
    kwargs_fingerprint = (
        json.dumps(model_kwargs, sort_keys=True, default=str) if model_kwargs else ""
    )

    cache_key = (
        role,
        resolved_model,
        resolved_base,
        resolved_key,
        resolved_temp,
        max_tokens,
        kwargs_fingerprint,
        ChatOpenAI,
    )

    with _llm_cache_lock:
        cached = _llm_cache.get(cache_key)
        if cached is not None:
            return cached

        init_kwargs: dict[str, Any] = {
            "model": resolved_model,
            "base_url": resolved_base,
            "temperature": resolved_temp,
            "timeout": DEFAULT_LLM_TIMEOUT,
            "max_retries": DEFAULT_LLM_MAX_RETRIES,
        }
        if resolved_key is not None:
            init_kwargs["api_key"] = resolved_key
        if max_tokens is not None:
            init_kwargs["max_tokens"] = max_tokens
        if model_kwargs is not None:
            init_kwargs["model_kwargs"] = model_kwargs

        instance = ChatOpenAI(**init_kwargs)
        _llm_cache[cache_key] = instance
        return instance
