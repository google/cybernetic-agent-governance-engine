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

"""Bind who is trading to the caller's verified workload identity.

``trade_governance.rego`` sets a trade's limits by ``trader_role`` (a junior
trader is allowed up to $5,000 without review, a senior one up to $500,000),
and the fiscal tier keys cumulative spend by ``trader_id``. Both say *who*
trades, so neither may come from the caller: an agent that could name its own
role could raise its own limits, for example after a prompt injection
(GHSA-w39v-5v7h-fxg9).

The gateway therefore binds both from the workload identity that
:class:`~src.gateway.server.workload_identity.WorkloadIdentityMiddleware`
verified for the request
(:func:`~src.gateway.server.workload_identity.current_client_identity`):

* ``CAGE_TRADER_ROLE_BINDINGS`` is a JSON object that maps a verified identity
  to a role, or to ``{"role": ..., "trader_id": ...}``::

      {
        "desk-a.trading.serviceaccount.identity.linkerd.cluster.local": "senior",
        "desk-b.trading.serviceaccount.identity.linkerd.cluster.local": {
          "role": "senior", "trader_id": "desk-b"
        }
      }

* a verified identity without a binding gets the least-privilege role
  :data:`LEAST_PRIVILEGE_ROLE` (``junior``);
* ``trader_id`` defaults to the verified identity itself;
* with no verified identity, an enforcing posture
  (:func:`~src.gateway.governance.env_posture.is_enforcing`) binds nothing and
  the trade policy refuses the trade (a missing role is an explicit DENY). A
  permissive posture (dev, test, CI) binds ``junior`` and
  :data:`UNVERIFIED_TRADER_ID`.

The kernel drops any caller value for both keys before the resolver runs
(:func:`~src.gateway.governance.governor.server_inputs.bind_server_inputs`), on
every path that evaluates a trade, so a preview and the committing run see the
same bound values.

The configuration fails closed: a value that is not a JSON object, a
duplicated identity, a key that is not a Linkerd workload identity, a role
outside the policy's allow-list (:data:`ALLOWED_TRADER_ROLES`), a malformed
``trader_id`` or an unknown field raises :class:`ValueError` while the finance
plugin assembles, so the gateway does not start.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from src.gateway.governance.env_posture import is_enforcing
from src.gateway.server.workload_identity import is_workload_identity

#: Environment variable holding the identity-to-role bindings (a JSON object).
TRADER_ROLE_BINDINGS_ENV = "CAGE_TRADER_ROLE_BINDINGS"

#: The roles ``trade_governance.rego`` admits (its ``allowed_roles``).
ALLOWED_TRADER_ROLES: frozenset[str] = frozenset({"junior", "senior"})

#: The role of a verified identity that has no binding.
LEAST_PRIVILEGE_ROLE = "junior"

#: The ``trader_id`` a permissive posture binds when no identity was verified.
UNVERIFIED_TRADER_ID = "unverified-caller"

#: The trade params this binding owns; a caller can never set them.
TRADER_KEYS: frozenset[str] = frozenset({"trader_role", "trader_id"})

_TRADER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")
_BINDING_FIELDS: frozenset[str] = frozenset({"role", "trader_id"})


class TraderIdentityUnavailable(RuntimeError):
    """No verified caller identity, and the posture requires one."""


@dataclass(frozen=True)
class TraderBinding:
    """The role, and optionally the trader id, bound to one workload identity."""

    role: str
    trader_id: str | None = None

    def __post_init__(self) -> None:
        if self.role not in ALLOWED_TRADER_ROLES:
            raise ValueError(
                f"trader role {self.role!r} is not one of "
                f"{sorted(ALLOWED_TRADER_ROLES)} (trade_governance.rego allowed_roles)"
            )
        if self.trader_id is not None and not (
            isinstance(self.trader_id, str) and _TRADER_ID.match(self.trader_id)
        ):
            raise ValueError(
                f"malformed trader_id {self.trader_id!r}: use 1-128 characters "
                "from letters, digits and ._:@/+- starting with a letter or digit"
            )


@dataclass(frozen=True)
class TraderRoleBindings:
    """Binds ``trader_role`` and ``trader_id`` from a verified workload identity.

    Attributes:
        bindings: Verified identity to :class:`TraderBinding`. Every key must
            be a Linkerd workload identity (the ``l5d-client-id`` form).
        require_identity: Bind nothing when no identity was verified. Defaults
            to the deployment posture: on in every enforcing posture.
    """

    # hash=False keeps the frozen value hashable (a mapping is not); equality
    # still compares the bindings.
    bindings: Mapping[str, TraderBinding] = field(default_factory=dict, hash=False)
    require_identity: bool = field(default_factory=is_enforcing)

    def __post_init__(self) -> None:
        malformed = sorted(
            repr(identity)
            for identity in self.bindings
            if not is_workload_identity(identity)
        )
        if malformed:
            raise ValueError(
                f"{TRADER_ROLE_BINDINGS_ENV} keys must be Linkerd workload "
                "identities ('<sa>.<namespace>.serviceaccount.identity.linkerd."
                f"<trust-domain>', the l5d-client-id form): {', '.join(malformed)}"
            )
        for identity, binding in self.bindings.items():
            if not isinstance(binding, TraderBinding):
                raise TypeError(
                    f"binding for {identity!r} is {type(binding).__name__}, "
                    "not TraderBinding"
                )
        object.__setattr__(self, "bindings", MappingProxyType(dict(self.bindings)))

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> TraderRoleBindings:
        """Build the bindings from ``CAGE_TRADER_ROLE_BINDINGS``.

        Unset or blank means no bindings: every verified identity is
        ``junior``.

        Raises:
            ValueError: the configuration is invalid (see the module docstring).
        """
        env = os.environ if environ is None else environ
        return cls(
            bindings=parse_trader_role_bindings(env.get(TRADER_ROLE_BINDINGS_ENV))
        )

    def bind(self, identity: str | None) -> dict[str, str]:
        """Return the ``trader_role`` and ``trader_id`` for a verified ``identity``.

        Raises:
            TraderIdentityUnavailable: ``identity`` is ``None`` and the
                posture requires one.
        """
        if identity is None:
            if self.require_identity:
                raise TraderIdentityUnavailable(
                    "no verified caller workload identity; an enforcing posture "
                    "binds no trader role"
                )
            return {
                "trader_role": LEAST_PRIVILEGE_ROLE,
                "trader_id": UNVERIFIED_TRADER_ID,
            }
        binding = self.bindings.get(identity)
        if binding is None:
            return {"trader_role": LEAST_PRIVILEGE_ROLE, "trader_id": identity}
        return {"trader_role": binding.role, "trader_id": binding.trader_id or identity}


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"{TRADER_ROLE_BINDINGS_ENV} lists {key!r} more than once")
        seen[key] = value
    return seen


def _binding(identity: str, value: Any) -> TraderBinding:
    if isinstance(value, str):
        return TraderBinding(role=value)
    if not isinstance(value, dict):
        raise ValueError(
            f"binding for {identity!r} must be a role or an object with 'role' "
            f"(and optionally 'trader_id'), not {type(value).__name__}"
        )
    unknown = sorted(set(value) - _BINDING_FIELDS)
    if unknown:
        raise ValueError(f"binding for {identity!r} has unknown fields {unknown}")
    role = value.get("role")
    if not isinstance(role, str):
        raise ValueError(f"binding for {identity!r} needs a string 'role'")
    trader_id = value.get("trader_id")
    if trader_id is not None and not isinstance(trader_id, str):
        raise ValueError(f"binding for {identity!r} has a non-string 'trader_id'")
    return TraderBinding(role=role, trader_id=trader_id)


def parse_trader_role_bindings(raw: str | None) -> dict[str, TraderBinding]:
    """Parse a ``CAGE_TRADER_ROLE_BINDINGS`` value; unset or blank is no bindings.

    Raises:
        ValueError: the value is not a JSON object, lists an identity twice, or
            holds an invalid binding.
    """
    if raw is None or not raw.strip():
        return {}
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{TRADER_ROLE_BINDINGS_ENV} is not valid JSON ({exc.msg} at "
            f"position {exc.pos})"
        ) from None
    if not isinstance(data, dict):
        raise ValueError(
            f"{TRADER_ROLE_BINDINGS_ENV} must be a JSON object mapping a verified "
            f"workload identity to a role, not {type(data).__name__}"
        )
    return {identity: _binding(identity, value) for identity, value in data.items()}


__all__ = [
    "ALLOWED_TRADER_ROLES",
    "LEAST_PRIVILEGE_ROLE",
    "TRADER_KEYS",
    "TRADER_ROLE_BINDINGS_ENV",
    "UNVERIFIED_TRADER_ID",
    "TraderBinding",
    "TraderIdentityUnavailable",
    "TraderRoleBindings",
    "parse_trader_role_bindings",
]
