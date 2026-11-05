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

"""Bind server-side inputs into an action's params before any stage reads them.

Some params describe measured state or server-verified authority, not caller
intent: a quote's age, a drawdown, a portfolio value, an approval token, or a
prompt-injection inspection score. Domains declare theirs by contributing a
:class:`~src.gateway.governance.contracts.ServerInputResolver` per action
(``PluginContribution.server_inputs``), and the kernel registers core STPA
resolvers via :func:`kernel_server_inputs`. :func:`bind_server_inputs` is the
one place they enter the params:

1. every kernel-owned security key (:data:`KERNEL_SERVER_INPUT_KEYS`) and every
   key the action's resolver owns is removed from the caller's params, whatever
   value it carried;
2. the resolver is asked for those keys, given the remaining params;
3. only owned keys from its answer are merged back;
4. if prompt-injection inspection detects an injection marker on any action's
   string parameters, ``semantic_score`` and ``prompt_injection_verified`` are
   stamped server-side so caller-spoofed scores or self-reported confidence can
   never bypass ``UCA-7`` or ``CTRL_AGT_001``.

Fail closed: if the resolver raises, times out, or omits a key, that key stays
absent and the governing rules refuse the missing value. The kernel never names
a domain key; it only applies its own core STPA resolvers and each contributed
resolver's ``owned_keys``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from typing import Any

from src.gateway.governance.contracts import ServerInputResolver
from src.gateway.governance.prompt_injection_detector import detect_prompt_injection
from src.gateway.governance.text_filter import ac_keyword_scan

logger = logging.getLogger(__name__)

#: Upper bound on one resolver call; a slower resolver resolves nothing.
RESOLVE_TIMEOUT_S: float = 5.0

#: Kernel-owned server-bound keys stripped unconditionally from caller params.
KERNEL_SERVER_INPUT_KEYS: frozenset[str] = frozenset(
    {"approval_token", "semantic_score", "prompt_injection_verified"}
)

#: Core STPA actions whose server-bound parameters are resolved by the kernel.
KERNEL_SERVER_INPUT_ACTIONS: frozenset[str] = frozenset(
    {"write_db", "prompt_injection_check"}
)

_INJECTION_DETECTED_SCORE: float = 1.0
_CLEAN_SEMANTIC_SCORE: float = 0.0
_SYSTEM_OVERRIDE_MARKER: str = "system override"

_verified_post_hitl_approval_id: ContextVar[str | None] = ContextVar(
    "verified_post_hitl_approval_id", default=None
)


@contextmanager
def verified_post_hitl_approval(approval_id: str) -> Iterator[None]:
    """Scope server-input resolution to a verified server-side HITL approval."""
    token = _verified_post_hitl_approval_id.set(approval_id)
    try:
        yield
    finally:
        _verified_post_hitl_approval_id.reset(token)


def _iter_scannable_strings(value: Any) -> Iterator[str]:
    """Yield string leaves from nested request parameter structures."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            if isinstance(k, str) and (
                k.startswith("_caller_") or k in KERNEL_SERVER_INPUT_KEYS
            ):
                continue
            yield from _iter_scannable_strings(v)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_scannable_strings(item)


def inspect_prompt_injection_params(params: Mapping[str, Any]) -> tuple[bool, float]:
    """Inspect ``params`` server-side for deterministic prompt-injection signals.

    Returns ``(True, 1.0)`` when any string parameter triggers structural
    prompt-injection detection, Tier-1 Aho-Corasick keyword scanning, or a
    system-override directive; otherwise returns ``(False, 0.0)``.
    """
    for text in _iter_scannable_strings(params):
        if not text:
            continue
        if (
            detect_prompt_injection(text).detected
            or ac_keyword_scan(text)
            or _SYSTEM_OVERRIDE_MARKER in text.lower()
        ):
            return True, _INJECTION_DETECTED_SCORE
    return False, _CLEAN_SEMANTIC_SCORE


class WriteDbApprovalInputResolver:
    """Kernel resolver for ``write_db``'s server-bound ``approval_token`` (UCA-1).

    Caller-supplied ``approval_token`` values are always stripped. An
    ``approval_token`` is stamped solely when executing inside a verified
    server-side :func:`verified_post_hitl_approval` context.
    """

    owned_keys: frozenset[str] = frozenset({"approval_token"})

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        del params
        approval_id = _verified_post_hitl_approval_id.get()
        if not isinstance(approval_id, str):
            return {}
        cleaned = approval_id.strip()
        if not cleaned or any(ch.isspace() for ch in cleaned):
            return {}
        return {"approval_token": f"apr-{cleaned}"}


class PromptInjectionInputResolver:
    """Kernel resolver for ``prompt_injection_check``'s ``semantic_score`` (UCA-7).

    Caller-supplied ``semantic_score`` and ``prompt_injection_verified`` values
    are stripped and recomputed from deterministic server-side inspection.
    """

    owned_keys: frozenset[str] = frozenset(
        {"semantic_score", "prompt_injection_verified"}
    )

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        detected, score = inspect_prompt_injection_params(params)
        return {
            "semantic_score": score,
            "prompt_injection_verified": not detected,
        }


_DEFAULT_KERNEL_RESOLVERS: Mapping[str, ServerInputResolver] = MappingProxyType(
    {
        "write_db": WriteDbApprovalInputResolver(),
        "prompt_injection_check": PromptInjectionInputResolver(),
    }
)


def kernel_server_inputs() -> dict[str, ServerInputResolver]:
    """Return fresh kernel-core STPA ``ServerInputResolver`` registrations."""
    return {
        "write_db": WriteDbApprovalInputResolver(),
        "prompt_injection_check": PromptInjectionInputResolver(),
    }


async def bind_server_inputs(
    resolvers: Mapping[str, ServerInputResolver],
    action: str,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a copy of ``params`` with ``action``'s owned keys server-resolved.

    Kernel-owned security keys (:data:`KERNEL_SERVER_INPUT_KEYS`) are always
    stripped from caller input regardless of ``action``. Clean actions without
    a resolver get an unchanged shallow copy.
    """
    bound = dict(params)
    stripped_kernel = sorted(k for k in KERNEL_SERVER_INPUT_KEYS if k in bound)
    for key in KERNEL_SERVER_INPUT_KEYS:
        bound.pop(key, None)

    resolver = resolvers.get(action) or _DEFAULT_KERNEL_RESOLVERS.get(action)
    if resolver is not None:
        owned = resolver.owned_keys
        ignored = sorted(set(stripped_kernel) | {k for k in owned if k in bound})
        for key in owned:
            bound.pop(key, None)
        if ignored:
            logger.warning(
                "server inputs: ignoring caller-supplied %s for %s", ignored, action
            )
        try:
            resolved = await asyncio.wait_for(
                resolver.resolve(MappingProxyType(dict(bound))), RESOLVE_TIMEOUT_S
            )
        except Exception as exc:
            logger.error(
                "server inputs: resolver for %s failed (%s: %s); owned keys stay unset",
                action,
                type(exc).__name__,
                exc,
            )
            return bound
        if not isinstance(resolved, Mapping):
            logger.error(
                "server inputs: resolver for %s returned %s, not a mapping; "
                "owned keys stay unset",
                action,
                type(resolved).__name__,
            )
            return bound
        for key, value in resolved.items():
            if key in owned:
                bound[key] = value
            else:
                logger.error(
                    "server inputs: resolver for %s returned unowned key %r; ignored",
                    action,
                    key,
                )
    elif stripped_kernel:
        logger.warning(
            "server inputs: ignoring caller-supplied %s for %s",
            stripped_kernel,
            action,
        )

    if "prompt_injection_verified" not in bound:
        detected, score = inspect_prompt_injection_params(bound)
        if detected:
            bound["semantic_score"] = score
            bound["prompt_injection_verified"] = False

    return bound


__all__ = [
    "KERNEL_SERVER_INPUT_ACTIONS",
    "KERNEL_SERVER_INPUT_KEYS",
    "RESOLVE_TIMEOUT_S",
    "PromptInjectionInputResolver",
    "WriteDbApprovalInputResolver",
    "bind_server_inputs",
    "inspect_prompt_injection_params",
    "kernel_server_inputs",
    "verified_post_hitl_approval",
]
