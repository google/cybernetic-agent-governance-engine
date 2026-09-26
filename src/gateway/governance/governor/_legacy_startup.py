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

import os
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# No-Direct-Bind startup assertions
# ---------------------------------------------------------------------------
# These checks run at module import time so the service fails fast rather than
# surfacing gaps on the first live request.

_ENVIRONMENT: str = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_IS_PRODUCTION: bool = _ENVIRONMENT not in ("development", "test", "dev", "ci")


# Gap 4 fix: DoWhy absence in production silently removes Tier 6 (causal
# gatekeeper).  Fail fast so the gap is surfaced at startup, not at runtime.
# Catches Exception (not just ImportError) because some dowhy versions import
# numpy.distutils at module level, which raises ModuleNotFoundError (a subclass
# of ImportError) when numpy>=2.0 is installed — that error propagates as a
# generic exception from within dowhy's own import chain.
if _IS_PRODUCTION:
    try:
        import dowhy as _dowhy_probe  # noqa: F401
    except Exception:
        raise RuntimeError(
            "CAGE STARTUP FAILURE (No-Direct-Bind Gap 4): 'dowhy' is not installed "
            "or failed to import (e.g. numpy>=2.0 incompatibility). "
            "The DoWhy causal gatekeeper (Tier 6) is a mandatory component of the "
            "No-Direct-Bind governance gate in production. Without it, an agent can "
            "reach EXECUTED without causal world-model validation. "
            "Install a numpy-2.x-compatible dowhy (>=0.12), or set CAGE_ENV=development "
            "to bypass (not for production use)."
        )

# Gap 5 fix (PERFORMANCE_REVIEW.md §3, CTRL_KMS_001): KMS_GOVERNANCE_KEY unset or
# pointing to a non-existent/disabled key version caused every signing call to return
# HTTP 500 in a prior production incident — not caught until a red-team measurement run.
# Verify the KMS key is reachable and ENABLED before the pod is marked ready.
if _IS_PRODUCTION:
    try:
        from src.gateway.governance.kms_signer import get_governance_signer

        get_governance_signer().validate_ready()
    except RuntimeError as _kms_ready_exc:
        raise RuntimeError(
            f"[STARTUP] KMS readiness probe failed — refusing to start: {_kms_ready_exc}"
        ) from _kms_ready_exc

# Gap 6 fix (PERFORMANCE_REVIEW.md §3): Redis unreachable at startup means every CBF
# call will fail-closed (or silently error). Verify Redis is reachable before the
# pod is marked ready so the misconfiguration is caught at startup, not at runtime.
if _IS_PRODUCTION:
    try:
        from src.gateway.infrastructure.redis_client import get_redis_client

        get_redis_client().ping_ready()
    except RuntimeError as _redis_ready_exc:
        raise RuntimeError(
            f"[STARTUP] Redis readiness probe failed — refusing to start: {_redis_ready_exc}"
        ) from _redis_ready_exc

# CAGE-SEC-007: RECONCILIATION_PROVIDER=stub guard (module-level, POAM-023)
# Raises at import time so the misconfiguration is caught before any request
# is served — not silently at the first CBF evaluation.
if (
    os.environ.get("RECONCILIATION_PROVIDER", "stub") == "stub"
    and os.environ.get("CAGE_ENV", "dev") == "production"
):
    raise RuntimeError(
        "CAGE-SEC-007: RECONCILIATION_PROVIDER=stub is not permitted in production. "
        "Set RECONCILIATION_PROVIDER=plaid or RECONCILIATION_PROVIDER=anchorage."
    )


def assert_safe_operational_state() -> None:
    """Refuse unsafe startup posture.

    Raises ``RuntimeError`` in production (logs CRITICAL elsewhere) when
    ``RECONCILIATION_PROVIDER=stub``: the CBF would evaluate against
    self-reported balances with no external ground truth (POAM-023).

    The former ``CBF_FAIL_OPEN`` + HMAC-fallback combined check was removed
    with the ``CBF_FAIL_OPEN`` flag itself; the CBF tier can no longer be
    bypassed. A standalone HMAC-fallback posture check is planned for the
    PR 4a composition root (``governor/posture.py``).

    Call this during application startup.
    """
    import json
    env = (
        os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
    ).lower()
    _is_production = env not in ("development", "test", "dev", "ci")

    # ── Gap 5 (POAM-023): CBF ground truth is self-reported ──────────────────
    _recon_provider = os.environ.get("RECONCILIATION_PROVIDER", "stub").lower()
    if _recon_provider == "stub":
        _poam023_msg = (
            "CAGE STARTUP WARNING (POAM-023): RECONCILIATION_PROVIDER=stub. "
            "The CBF is evaluating cash barrier conditions against self-reported "
            "balances written by the execution system itself — no external ground "
            "truth is available. This is a known open compliance gap. "
            "Resolve by setting RECONCILIATION_PROVIDER=plaid or =anchorage and "
            "provisioning the corresponding credentials."
        )
        if _is_production:
            raise RuntimeError(_poam023_msg)
        else:
            logger.critical(
                json.dumps(
                    {
                        "event": "POAM_023_STUB_PROVIDER_IN_USE",
                        "severity": "CRITICAL",
                        "reconciliation_provider": _recon_provider,
                        "environment": env,
                        "poam_id": "POAM-023",
                        "audit_note": _poam023_msg,
                    }
                )
            )

def is_cage_defer_enabled() -> bool:
    """Return whether DEFER decision path is enabled.

    Honors explicit environment variable override if present; otherwise
    falls back to the module-level CAGE_DEFER_ENABLED flag.
    """
    env = os.getenv("CAGE_DEFER_ENABLED")
    if env is not None:
        return env.lower() == "true"
    return True

def is_cage_narrow_enabled() -> bool:
    """Return whether NARROW decision path is enabled.

    Honors explicit environment variable override if present; otherwise
    falls back to the module-level CAGE_NARROW_ENABLED flag.
    """
    env = os.getenv("CAGE_NARROW_ENABLED")
    if env is not None:
        return env.lower() == "true"
    return True

def is_cage_pause_enabled() -> bool:
    """Return whether PAUSE decision path is enabled.

    Honors explicit environment variable override if present; otherwise
    falls back to the module-level CAGE_PAUSE_ENABLED flag.
    """
    env = os.getenv("CAGE_PAUSE_ENABLED")
    if env is not None:
        return env.lower() == "true"
    return True


def _env_flag(name: str, default: bool) -> bool:
    """Parse a boolean environment flag; unset falls back to ``default``.

    D4 fix: This replaces the class-constant ``ENABLE_LEGACY_TRADE_DISPATCH``
    with an env-driven flag so that Gate 3 can actually toggle between
    the legacy and pluggable dispatch paths.
    """
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in ("true", "1", "t", "y", "yes", "on")
