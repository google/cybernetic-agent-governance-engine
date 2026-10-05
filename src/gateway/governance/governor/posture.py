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

"""Explicit startup posture: every production guard, run once, never at import.

:func:`assert_production_posture` is called once by each entry point (the
gateway lifespan, the advisor lifespan, CLI scripts) after
:func:`~src.gateway.governance.governor.assembly.assemble_governor`. Posture
comes only from :func:`env_posture.resolve_posture`. Under an enforcing
posture (anything but DEV, TEST, CI) the first failed check is raised with
all failures listed; under a permissive posture every failure is logged at
CRITICAL and startup continues.

Checks:

* ``tier_runtime_requirements``: every module a tier (domain or
  jurisdiction) declares in ``runtime_requirements`` imports (e.g.
  ``dowhy`` for a causal tier).
* ``jurisdiction_requirements``: every ``PostureRequirement`` the region's
  ``JurisdictionContribution`` declares holds (e.g. the EU AI Act
  impact-assessment tier is not backed by the stub ``NormativeProvider``).
* ``kms_signing_mode`` (K3): the governance signer is KMS-backed, not the
  HMAC fallback. HMAC is allowed only in permissive postures.
* ``kms_ready``: the KMS key version is reachable and ENABLED.
* ``redis_ready``: Redis answers PING.
* ``reconciliation_provider`` (POAM-023): CBF ground truth is not the
  self-reported stub.
* ``reconciler_trust_anchor`` (G8): ``RECONCILER_KMS_KEY`` is set, is not
  the gateway key, and resolves to at least one reconciler public key, so
  the CBF can verify ground-truth snapshots by ``kid``.
* ``governance_salt`` (C-03/C-04): ``GOVERNANCE_SALT`` is not the
  well-known default, which would let anyone forge routing seals.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from src.gateway.governance.env_posture import DeploymentPosture, is_enforcing

if TYPE_CHECKING:
    from src.gateway.governance.governor.assembly import GovernorComponents

logger = logging.getLogger(__name__)


class PostureViolation(RuntimeError):
    """An enforcing posture failed one or more startup checks."""


def _signer() -> Any:
    from src.gateway.governance.kms_signer import get_governance_signer

    return get_governance_signer()


def _redis() -> Any:
    from src.gateway.infrastructure.redis_client import get_redis_client

    return get_redis_client()


def _reconciler_verifier() -> Any:
    from src.gateway.governance.reconciliation.trust import get_reconciler_verifier

    return get_reconciler_verifier()


def _check_tier_runtime_requirements(components: GovernorComponents) -> None:
    for tier in components.plugin_tiers:
        for module in getattr(tier, "runtime_requirements", ()):
            try:
                # Module names come from code-declared plugin tier attributes
                # (trusted composition-root input), never from request data.
                # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                importlib.import_module(module)
            # e.g. dowhy failing on numpy>=2 raises non-ImportError
            except Exception as exc:
                raise RuntimeError(
                    f"tier {tier.tier_name!r} requires {module!r}, which failed to import: {exc}"
                ) from exc


def _check_jurisdiction_requirements(components: GovernorComponents) -> None:
    jurisdiction = components.jurisdiction
    if jurisdiction is None:
        return
    unmet: list[str] = []
    for requirement in jurisdiction.runtime_requirements:
        try:
            requirement.check()
        except Exception as exc:
            unmet.append(f"{requirement.name}: {exc}")
    if unmet:
        raise RuntimeError(f"region {jurisdiction.region!r}: " + "; ".join(unmet))


def _check_kms_signing_mode(components: GovernorComponents) -> None:
    if not _signer().is_kms_active:
        raise RuntimeError(
            "governance signer is in HMAC fallback mode; set KMS_GOVERNANCE_KEY "
            "(CTRL_KMS_001). HMAC is permitted only in DEV/TEST/CI posture."
        )


def _check_kms_ready(components: GovernorComponents) -> None:
    signer = _signer()
    if signer.is_kms_active:  # an HMAC signer is reported by kms_signing_mode
        signer.validate_ready()


def _check_redis_ready(components: GovernorComponents) -> None:
    _redis().ping_ready()


def _check_reconciliation_provider(components: GovernorComponents) -> None:
    provider = os.environ.get("RECONCILIATION_PROVIDER", "stub").lower()
    if provider == "stub":
        raise RuntimeError(
            "RECONCILIATION_PROVIDER=stub: the CBF evaluates against self-reported "
            "balances with no external ground truth (POAM-023)"
        )
    gt_providers = getattr(components, "ground_truth_providers", {}) or {}
    missing = [
        inv.invariant_id
        for inv in getattr(components, "invariants", ())
        if getattr(inv, "requires_external_ground_truth", True)
        and inv.invariant_id not in gt_providers
    ]
    if missing:
        raise RuntimeError(
            f"invariants missing GroundTruthProvider registration: {missing}"
        )


def _check_reconciler_trust_anchor(components: GovernorComponents) -> None:
    from src.gateway.governance.reconciliation.trust import (
        RECONCILER_KMS_KEY_ENV,
        is_gateway_kid,
    )

    key = os.environ.get(RECONCILER_KMS_KEY_ENV, "").strip()
    if not key:
        raise RuntimeError(
            f"{RECONCILER_KMS_KEY_ENV} is unset: the CBF has no trust anchor for "
            "ground-truth snapshots and every reconciled balance would be rejected (G8)"
        )
    if is_gateway_kid(key):
        raise RuntimeError(
            f"{RECONCILER_KMS_KEY_ENV} references the gateway signing key; the "
            "reconciler must sign ground truth with a separate key (G8)"
        )
    if not _reconciler_verifier().trust_anchor_kids:
        raise RuntimeError(
            f"no reconciler public key resolved for {RECONCILER_KMS_KEY_ENV}; "
            "check the key exists and the gateway has publicKeyViewer on it (G8)"
        )


def _check_governance_salt(components: GovernorComponents) -> None:
    from src.gateway.governance.routing_seal import is_default_salt

    if is_default_salt():
        raise RuntimeError(
            "GOVERNANCE_SALT is the hardcoded default; routing seals can be forged. "
            "Set a strong, unique GOVERNANCE_SALT (>= 32 bytes)."
        )


CHECKS: tuple[tuple[str, Callable[[GovernorComponents], None]], ...] = (
    ("tier_runtime_requirements", _check_tier_runtime_requirements),
    ("jurisdiction_requirements", _check_jurisdiction_requirements),
    ("kms_signing_mode", _check_kms_signing_mode),
    ("kms_ready", _check_kms_ready),
    ("redis_ready", _check_redis_ready),
    ("reconciliation_provider", _check_reconciliation_provider),
    ("reconciler_trust_anchor", _check_reconciler_trust_anchor),
    ("governance_salt", _check_governance_salt),
)


def assert_production_posture(
    posture: DeploymentPosture, *, components: GovernorComponents
) -> None:
    """Run every startup check for ``posture`` against the assembled ``components``.

    Raises:
        PostureViolation: ``posture`` is enforcing and a check failed, or
            ``components`` were assembled for a different posture.
    """
    if components.posture is not posture:
        raise PostureViolation(
            f"governor was assembled for {components.posture.value!r} but startup posture is {posture.value!r}"
        )
    failures: list[tuple[str, str]] = []
    for name, check in CHECKS:
        try:
            check(components)
        except Exception as exc:
            failures.append((name, str(exc)))
    if not failures:
        logger.info(
            "startup posture %s: all %d checks passed", posture.value, len(CHECKS)
        )
        return
    if is_enforcing(posture):
        detail = "; ".join(f"{name}: {msg}" for name, msg in failures)
        raise PostureViolation(f"startup posture {posture.value!r} refused: {detail}")
    for name, msg in failures:
        logger.critical(
            json.dumps(
                {
                    "event": "CAGE_POSTURE_CHECK_FAILED",
                    "severity": "CRITICAL",
                    "check": name,
                    "posture": posture.value,
                    "detail": msg,
                    "note": "permitted only because the posture is not enforcing",
                }
            )
        )
