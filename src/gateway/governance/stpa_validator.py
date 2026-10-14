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

"""Domain-agnostic STPA Unsafe Control Action (UCA) validator.

Evaluates kernel-core STPA rules alongside domain-contributed :class:`UcaRule`
predicates supplied via ``PluginContribution.uca_rules``. Fails closed into a
``Violation(tier="stpa", kind=ViolationKind.HARD)`` whenever a rule predicate
raises an unexpected exception.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.gateway.governance.contracts import Violation, ViolationKind

logger = logging.getLogger("Gateway.Governance.STPAValidator")


def _normalize_uca_code(uca_id: str) -> str:
    """Normalize a UCA identifier (e.g. ``'UCA-5'``) into a violation code."""
    sanitized = uca_id.strip().upper().replace("-", "_")
    if sanitized.startswith("STPA_"):
        return sanitized
    if sanitized.startswith("UCA_"):
        return f"STPA_{sanitized}"
    return f"STPA_UCA_{sanitized}"


def _normalize_action_name(action_name: object) -> str:
    """Canonicalize an action name for case-, whitespace-, and delimiter-safe matching."""
    if not isinstance(action_name, str):
        return ""
    normalized = action_name.strip().lower().replace("-", "_")
    return normalized


_STRUCTURED_TOKEN_PREFIXES: tuple[str, ...] = (
    "tok-",
    "tok_",
    "signed-",
    "signed_",
    "apr-",
    "apr_",
    "app-",
    "app_",
    "seal-",
    "seal_",
)
_MIN_OPAQUE_TOKEN_LEN: int = 16


def _is_valid_signed_approval_token(token: Any) -> bool:
    """Return True iff ``token`` is a structurally valid signed approval token string.

    Rejects ``None``, non-strings (``0``, ``False``, ``{}``, ``[]``), empty or
    whitespace-only strings, and arbitrary short unstructured strings (e.g.
    ``"garbage"``), while accepting structured token prefixes (``tok-*``,
    ``signed-*``, ``apr-*``, ``seal-*``), dot-segmented JWS/HMAC tokens, or
    high-entropy opaque token strings (>= 16 non-whitespace characters).
    """
    if not isinstance(token, str):
        return False
    stripped = token.strip()
    if not stripped or any(ch.isspace() for ch in stripped):
        return False
    lower = stripped.lower()
    if lower.startswith(_STRUCTURED_TOKEN_PREFIXES):
        prefix = next(p for p in _STRUCTURED_TOKEN_PREFIXES if lower.startswith(p))
        return len(stripped) > len(prefix)
    if "." in stripped:
        parts = stripped.split(".")
        return all(bool(part) for part in parts) and len(stripped) >= 8
    return len(stripped) >= _MIN_OPAQUE_TOKEN_LEN


@dataclass(frozen=True)
class UcaRule:
    """Compiled STPA Unsafe Control Action rule.

    Attributes:
        uca_id: Canonical STPA UCA identifier (e.g. ``"UCA-1"``).
        action: Governed action name this rule applies to, or ``"*"`` / ``"all"``
            for wildcard matching.
        description: Human-readable hazard / UCA description.
        predicate: Callable accepting ``(action_name, params)`` or ``(params,)``
            and returning a :class:`Violation`, sequence of violations, error
            string, boolean violation flag, or ``None`` when safe.
    """

    uca_id: str
    action: str = "*"
    description: str = ""
    predicate: Callable[..., Violation | Sequence[Violation] | str | bool | None] = (
        field(default=lambda *_args, **_kwargs: None)
    )
    action_name: str | None = None

    def __post_init__(self) -> None:
        if self.action_name is not None and self.action == "*":
            object.__setattr__(self, "action", self.action_name)
        elif self.action_name is None:
            object.__setattr__(self, "action_name", self.action)

    def evaluate(self, action_name: str, params: Mapping[str, Any]) -> list[Violation]:
        """Evaluate this UCA rule against ``(action_name, params)``, failing closed."""
        normalized_rule_action = _normalize_action_name(self.action)
        normalized_target_action = _normalize_action_name(action_name)
        if normalized_rule_action not in ("*", "all", normalized_target_action):
            return []

        code = _normalize_uca_code(self.uca_id)
        try:
            sig = inspect.signature(self.predicate)
            positional = [
                p
                for p in sig.parameters.values()
                if p.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            has_varargs = any(
                p.kind == inspect.Parameter.VAR_POSITIONAL
                for p in sig.parameters.values()
            )
            if not has_varargs and len(positional) == 1:
                result = self.predicate(params)
            else:
                result = self.predicate(normalized_target_action, params)
        except Exception as exc:
            logger.error(
                "STPAValidator: %s evaluation error — failing closed: %s",
                self.uca_id,
                exc,
            )
            return [
                Violation(
                    tier="stpa",
                    code=code,
                    message=(
                        f"{self.uca_id} ({action_name}): Evaluation error — "
                        f"failing closed ({exc})."
                    ),
                    kind=ViolationKind.HARD,
                )
            ]

        if result is None or result is False:
            return []
        if result is True:
            return [
                Violation(
                    tier="stpa",
                    code=code,
                    message=self.description
                    or f"{self.uca_id} ({action_name}): UCA triggered.",
                    kind=ViolationKind.HARD,
                )
            ]
        if isinstance(result, Violation):
            return [result]
        if isinstance(result, str):
            return [
                Violation(
                    tier="stpa",
                    code=code,
                    message=result,
                    kind=ViolationKind.HARD,
                )
            ]
        return list(result)


def _check_core_uca_1(action_name: str, params: Mapping[str, Any]) -> Violation | None:
    """UCA-1 [unsafe_action] on 'write_db': requires a signed approval_token."""
    if _normalize_action_name(action_name) != "write_db":
        return None
    token = params.get("approval_token") if isinstance(params, Mapping) else None
    if not _is_valid_signed_approval_token(token):
        reason = (
            "param 'approval_token' is None"
            if token is None
            else "param 'approval_token' is missing or not a valid signed token"
        )
        return Violation(
            tier="stpa",
            code="STPA_UCA_1",
            message=(
                f"UCA-1 (write_db): Agent executes write operation without a signed "
                f"approval token. [{reason}] (hazards: H-1)"
            ),
            kind=ViolationKind.HARD,
        )
    return None


CORE_UCA_RULES: tuple[UcaRule, ...] = (
    UcaRule(
        uca_id="UCA-1",
        action="write_db",
        description="Agent executes write operation without a signed approval token.",
        predicate=_check_core_uca_1,
    ),
)


class STPAValidator:
    """Domain-agnostic STPA validator over kernel core and plugin-contributed rules."""

    def __init__(
        self,
        rules: Sequence[UcaRule] = (),
        *,
        include_core: bool = True,
    ) -> None:
        contributed = tuple(rules)
        if include_core:
            core_ids = {r.uca_id for r in CORE_UCA_RULES}
            for r in contributed:
                if r.uca_id in core_ids and r not in CORE_UCA_RULES:
                    logger.warning(
                        "STPAValidator: contributed rule %r on action %r shares core "
                        "UCA identifier; retaining core rule alongside contributed rule.",
                        r.uca_id,
                        r.action,
                    )
            dedup_contributed = tuple(r for r in contributed if r not in CORE_UCA_RULES)
            self._rules: tuple[UcaRule, ...] = CORE_UCA_RULES + dedup_contributed
        else:
            self._rules = contributed

    @property
    def rules(self) -> tuple[UcaRule, ...]:
        """Return the immutable tuple of active UCA rules."""
        return self._rules

    @staticmethod
    def _v(
        code: str,
        message: str,
        kind: ViolationKind = ViolationKind.HARD,
    ) -> Violation:
        return Violation(
            tier="stpa",
            code=code,
            message=message,
            kind=kind,
        )

    def _validate_rules(
        self, action_name: str, params: dict[str, Any]
    ) -> list[Violation]:
        """Evaluate all registered ``self._rules`` against ``(action_name, params)``."""
        violations: list[Violation] = []
        safe_params: Mapping[str, Any] = params if isinstance(params, Mapping) else {}
        for rule in self._rules:
            violations.extend(rule.evaluate(action_name, safe_params))
        return violations

    def validate(self, action_name: str, params: dict[str, Any]) -> list[Violation]:
        """Validate ``(action_name, params)`` against all active STPA rules."""
        return self._validate_rules(action_name, params)

    def validate_generated(
        self, action_name: str, params: dict[str, Any]
    ) -> list[Violation]:
        """Run all registered UCA rules for ``action_name`` and return violations."""
        return self._validate_rules(action_name, params)


GeneratedSTPAValidator = STPAValidator

__all__ = [
    "CORE_UCA_RULES",
    "GeneratedSTPAValidator",
    "STPAValidator",
    "UcaRule",
]
