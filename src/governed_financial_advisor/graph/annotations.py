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
Side-Effect Node Annotation Utility — CAGE Architecture.

SIDE-EFFECT NODE REGISTRY
This registry is the canonical proof artifact for the July review.
All nodes that perform external I/O (database writes, API calls,
message queue publishes) MUST be registered here.

Usage
-----
Import ``side_effect_node`` and apply it as a decorator to any function
that performs external I/O:

    from src.governed_financial_advisor.graph.annotations import side_effect_node

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def my_node(state):
        ...

The decorator is annotation-only — it does NOT alter function behavior.
It registers the function in ``SIDE_EFFECT_REGISTRY`` so that
``get_side_effect_topology()`` (defined in ``graph.py``) can return the
complete side-effect surface as a machine-readable proof artifact.

Allowed ``kind`` values
-----------------------
- ``"db_write"``       — relational / document database write
- ``"api_call"``       — outbound HTTP / gRPC call to an external service
- ``"queue_publish"``  — message queue publish (Pub/Sub, BullMQ, etc.)
- ``"redis_write"``    — Redis SET / HSET / LPUSH / pipeline.execute
- ``"audit_log"``      — write to an audit / observability backend (Langfuse, etc.)
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Literal, TypeVar

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

SideEffectKind = Literal[
    "db_write",
    "api_call",
    "queue_publish",
    "redis_write",
    "audit_log",
]

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# SIDE-EFFECT NODE REGISTRY
# ---------------------------------------------------------------------------

SIDE_EFFECT_REGISTRY: dict[str, dict[str, Any]] = {}
"""
Module-level registry mapping function qualified name → side-effect metadata.

Schema per entry::

    {
        "kind":            str,       # one of SideEffectKind
        "external_system": str,       # e.g. "gateway_api", "redis_db1"
        "fn":              Callable,  # reference to the decorated function
    }

Consumers that need a serialisation-safe view (without the ``fn`` key)
should call ``get_side_effect_topology()`` in ``graph.py`` instead of
reading this dict directly.
"""


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def side_effect_node(
    kind: SideEffectKind,
    external_system: str,
) -> Callable[[F], F]:
    """Annotation decorator that registers a function in ``SIDE_EFFECT_REGISTRY``.

    This decorator is **annotation-only** — it does NOT wrap, alter, or
    intercept the decorated function in any way.  Both sync and async
    functions are supported.

    Args:
        kind:            Category of external I/O performed by this function.
                         Must be one of the ``SideEffectKind`` literals.
        external_system: Human-readable name of the external system contacted
                         (e.g. ``"gateway_api"``, ``"redis_db1"``,
                         ``"langfuse"``, ``"cloud_kms"``).

    Returns:
        The original function, unchanged.

    Raises:
        ValueError: If ``kind`` is not one of the allowed literals.

    Example::

        @side_effect_node(kind="api_call", external_system="gateway_api")
        async def tool_executor_node(state):
            ...
    """
    _allowed_kinds: tuple[str, ...] = (
        "db_write",
        "api_call",
        "queue_publish",
        "redis_write",
        "audit_log",
    )
    if kind not in _allowed_kinds:
        raise ValueError(
            f"side_effect_node: invalid kind={kind!r}. "
            f"Must be one of {_allowed_kinds}."
        )

    def decorator(fn: F) -> F:
        # Use the qualified name so registry keys are unique across modules.
        key: str = fn.__qualname__

        SIDE_EFFECT_REGISTRY[key] = {
            "kind": kind,
            "external_system": external_system,
            "fn": fn,
        }

        # Return the original function completely unmodified.
        # functools.wraps is not needed because we are not wrapping.
        return fn

    return decorator
