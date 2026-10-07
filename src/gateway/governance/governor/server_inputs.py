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

Some params describe measured state, not caller intent: a quote's age, a
drawdown, a portfolio value. A domain declares them by contributing a
:class:`~src.gateway.governance.contracts.ServerInputResolver` per action
(``PluginContribution.server_inputs``). :func:`bind_server_inputs` is the one
place they enter the params:

1. every key the resolver owns is removed from the caller's params, whatever
   value it carried;
2. the resolver is asked for those keys, given the remaining params;
3. only owned keys from its answer are merged back.

The preview entry points (``SymbolicGovernor.validate_action`` and
``verify``) bind before the pipeline runs. The committing path binds in the
domain's governed tool before it calls ``govern()``, so the seal names the
bound params the tool later executes. Both paths therefore evaluate the
same server-side values, and no caller value for an owned key is ever read.

Fail closed: if the resolver raises, times out, or omits a key, that key stays
absent and the domain's rules refuse the missing value. The kernel never names
a domain key; it only applies the resolver's ``owned_keys``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from src.gateway.governance.contracts import ServerInputResolver

logger = logging.getLogger(__name__)

#: Upper bound on one resolver call; a slower resolver resolves nothing.
RESOLVE_TIMEOUT_S: float = 5.0


async def bind_server_inputs(
    resolvers: Mapping[str, ServerInputResolver],
    action: str,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a copy of ``params`` with ``action``'s owned keys server-resolved.

    Actions without a resolver get an unchanged shallow copy.
    """
    bound = dict(params)
    resolver = resolvers.get(action)
    if resolver is None:
        return bound
    owned = resolver.owned_keys
    ignored = sorted(k for k in owned if k in bound)
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
    return bound


__all__ = ["RESOLVE_TIMEOUT_S", "bind_server_inputs"]
