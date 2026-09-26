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
Symbolic Governor (Neuro-Symbolic Governance Layer).

Architecture & Interruption Taxonomy:
    Implements the Governance/Reasoning Plane and first-class interruption primitives
    from Tallam's Five-Plane Reference Architecture (arXiv:2606.12320):

    - BLOCK: Direct pipeline halt with GovernanceError.
    - DEFER: Async parking in DeferQueue with HTTP 202 acceptance.
    - REDACT: Pre-execution token and PII scrubbing.
    - TERMINATE: Workflow termination with Saga LIFO compensation rollback.
    - AUDIT: Invariant-checked synchronous NDJSON hash-chain logging.
    - ESCALATE: Quorum human-in-the-loop (HITL) routing.
    - PAUSE / NARROW: Dedicated execution branches retaining task liveness while
      constraining authorization scope (introduced in v3.1 per design review recommendations).
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.core.policy import OPAClient
from src.gateway.governance.constants import ControlRegistry, GovernanceControl
from src.gateway.governance.contracts import (
    ConsensusProvider,
    SafetyFilter,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.ftra.models import FtraBoundaryResult

# Import directly from generated_stpa_validator, bypassing the deprecated stpa_validator shim.
from src.gateway.governance.generated_stpa_validator import (
    GeneratedSTPAValidator as STPAValidator,
)
from src.gateway.observability.attributes import (
    OBSERVATION_INPUT,
    OBSERVATION_NAME,
    OBSERVATION_OUTPUT,
    OBSERVATION_TYPE,
)

logger = logging.getLogger("SymbolicGovernor")
tracer = trace.get_tracer(__name__)

# Prometheus counter for FTRA boundary checks (module-level to avoid duplicate registration)
_ftra_boundary_counter = None
try:
    from prometheus_client import Counter

    _ftra_boundary_counter = Counter(
        "cage_ftra_boundary_checks_total",
        "Total FTRA boundary checks performed",
        ["result"],
    )
except (ImportError, Exception):
    pass  # prometheus_client not installed or counter already registered

# ---------------------------------------------------------------------------
# No-Direct-Bind startup assertions
# ---------------------------------------------------------------------------
# These checks run at module import time so the service fails fast rather than
# surfacing gaps on the first live request.

_ENVIRONMENT: str = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_IS_PRODUCTION: bool = _ENVIRONMENT not in ("development", "test", "dev", "ci")

# Gap 3 fix: CBF_FAIL_OPEN=true in production is a direct-bind shortcut —
# it removes the cash-barrier tier from the gate entirely.  Fail fast.
_CBF_FAIL_OPEN: bool = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"
if _CBF_FAIL_OPEN and _IS_PRODUCTION:
    raise RuntimeError(
        "CAGE STARTUP FAILURE (No-Direct-Bind Gap 3): CBF_FAIL_OPEN=true is set in "
        f"environment '{_ENVIRONMENT}'. This removes the Control Barrier Function tier "
        "from the governance gate, creating a direct-bind shortcut to EXECUTED without "
        "resolved cash-barrier authority. "
        "Set CBF_FAIL_OPEN=false or set CAGE_ENV=development to bypass (not for production)."
    )

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


from src.gateway.governance.contracts import (
    GovernanceTierFailure,
    GovernanceTierPlugin,
    InvariantModel,
    RefusalReceipt,
)


class GovernanceError(Exception):
    """Raised when a symbolic rule is violated.

    Args:
        message: Human-readable violation description.  Begins with the stable
                 ``[CTRL_*]`` control ID so log aggregators can key on it.
        payload: Optional structured dict emitted to OTel / SIEM consumers.
                 Contains ``control_id``, ``primary_framework``,
                 ``legacy_citation``, etc. sourced from control_mappings.json.
        receipt: Optional immutable RefusalReceipt proof object.
    """

    def __init__(
        self,
        message: str,
        payload: dict[str, Any] | None = None,
        receipt: RefusalReceipt | None = None,
    ) -> None:
        super().__init__(message)
        self.payload: dict[str, Any] = payload or {}
        self.receipt: RefusalReceipt | None = receipt


# ---------------------------------------------------------------------------
# FRIA Confidence-Starvation Boundary — three-zone enforcement thresholds
# ---------------------------------------------------------------------------
# These constants define the three enforcement zones for the adaptive FRIA
# (Fundamental Rights Impact Assessment) tier (Tier 7 of the governance
# pipeline).  They are read at module load time and may be overridden via
# environment variables for staged rollouts or regional tuning.
#
# Zone semantics (CAGE v0.1.0 architectural decision — see ontology.py UCA-7):
#
#   FRIA_ZONE_ALLOW  (confidence ≥ FRIA_ZONE_ALLOW):
#     Autonomous clearance.  The external normative provider is contacted
#     asynchronously (fire-and-forget) — the trade is not blocked while
#     waiting for the FRIA attestation.  OPA system_authz.rego enforces
#     this boundary via the ALLOW path.
#
#   FRIA_ZONE_DEFER  (FRIA_ZONE_DEFER ≤ confidence < FRIA_ZONE_ALLOW):
#     Synchronous blocking gate.  The external normative provider must
#     return before the trade proceeds.  OPA returns MANUAL_REVIEW for
#     this zone, which is translated to GovernanceDecision.REQUIRE_APPROVAL
#     at the validate_action() boundary.  Human sign-off is required.
#
#   DENY zone        (confidence < FRIA_ZONE_DEFER):
#     Hard abort.  The external normative provider is never contacted.
#     The trade is blocked immediately.  Routes to DeferQueue for automated
#     data-hydration (GovernanceDecision.DEFER), not human triage.
#
# AARM mapping: CSA AARM-V7 "Context Window Overflow"
# ISO 42001 mapping: A.8.4 (AI System Operation Controls)
# Implementation: src/gateway/governance/normative_provider.py,
#                 src/gateway/governance/defer_queue.py
#
# EV-1 Migration: These thresholds are now sourced from config/governance_thresholds.json
# with environment variable overrides supported. See schemas/thresholds.py for details.
from src.gateway.governance.schemas.thresholds import (
    get_agent_confidence_threshold,
    get_fria_zone_allow,
    get_fria_zone_defer,
    load_and_validate_thresholds,
)

# These module-level constants delegate to the config-based accessor functions,
# which already incorporate env var overrides from load_and_validate_thresholds().
FRIA_ZONE_ALLOW: float = get_fria_zone_allow()
FRIA_ZONE_DEFER: float = get_fria_zone_defer()

# Feature flag for DEFER decision path — when disabled, DEFER falls back to DENY
# for gradual rollout safety.  Default is enabled (true).
CAGE_DEFER_ENABLED: bool = os.getenv("CAGE_DEFER_ENABLED", "true").lower() == "true"

# Feature flag for NARROW decision path — allows partial-authority/clamped execution
# when a request exceeds soft thresholds but is not a hard violation.
# Default is disabled (false — opt-in) for gradual rollout safety.
# When disabled, NARROW candidates fall back to DEFER or DENY.
CAGE_NARROW_ENABLED: bool = os.getenv("CAGE_NARROW_ENABLED", "false").lower() == "true"

# Feature flag for PAUSE decision path — allows resumable suspension of execution
# when a transient external condition (rate limit, circuit breaker, etc.) prevents
# immediate execution. Default is disabled (false — opt-in) for gradual rollout safety.
# When disabled, PAUSE candidates fall back to DENY.
CAGE_PAUSE_ENABLED: bool = os.getenv("CAGE_PAUSE_ENABLED", "false").lower() == "true"


def is_cage_defer_enabled() -> bool:
    """Return whether DEFER decision path is enabled.

    Honors explicit environment variable override if present; otherwise
    falls back to the module-level CAGE_DEFER_ENABLED flag.
    """
    env = os.getenv("CAGE_DEFER_ENABLED")
    if env is not None:
        return env.lower() == "true"
    return CAGE_DEFER_ENABLED


def is_cage_narrow_enabled() -> bool:
    """Return whether NARROW decision path is enabled.

    Honors explicit environment variable override if present; otherwise
    falls back to the module-level CAGE_NARROW_ENABLED flag.
    """
    env = os.getenv("CAGE_NARROW_ENABLED")
    if env is not None:
        return env.lower() == "true"
    return CAGE_NARROW_ENABLED


def is_cage_pause_enabled() -> bool:
    """Return whether PAUSE decision path is enabled.

    Honors explicit environment variable override if present; otherwise
    falls back to the module-level CAGE_PAUSE_ENABLED flag.
    """
    env = os.getenv("CAGE_PAUSE_ENABLED")
    if env is not None:
        return env.lower() == "true"
    return CAGE_PAUSE_ENABLED


# ---------------------------------------------------------------------------
# Violation Classification (§2.1 CAGE Implementation Specs)
# ---------------------------------------------------------------------------
# Legacy _classify_violation() and _compute_narrowed_params() deleted per
# AGENTS.md compliance refactoring. All classification now flows through
# ClassificationEngine (mandatory constructor parameter).


# ---------------------------------------------------------------------------
# SymbolicGovernor
# ---------------------------------------------------------------------------


def _env_flag(name: str, default: bool) -> bool:
    """Parse a boolean environment flag; unset falls back to ``default``.

    D4 fix: This replaces the class-constant ``ENABLE_LEGACY_TRADE_DISPATCH``
    with an env-driven flag so that Gate 3 can actually toggle between
    the legacy and pluggable dispatch paths.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class SymbolicGovernor:
    def __init__(
        self,
        opa_client: OPAClient,
        safety_filter: SafetyFilter,
        consensus_engine: ConsensusProvider,
        classification_engine: "ClassificationEngine",
        stpa_validator: STPAValidator | None = None,
        telemetry_provider: Any | None = None,
        fiscal_limit_guard: Any | None = None,
        core_tiers: tuple[GovernanceTierPlugin, ...] = (),
        domain_tiers: tuple[GovernanceTierPlugin, ...] = (),
    ):
        self.opa_client = opa_client
        # retained for direct-invocation callers; not part of the governance hot path
        self.safety_filter = safety_filter
        self.consensus_engine = consensus_engine
        self.stpa_validator: STPAValidator | None = stpa_validator
        self.telemetry_provider = telemetry_provider
        # FiscalLimitGuard — optional for backward compatibility with existing tests.
        # When present, atomically pre-reserves the daily fiscal limit in Redis
        # (WATCH/MULTI/EXEC) before the consensus gate, closing the TOCTOU race
        # between the CBF balance check and actual trade execution.
        # retained for direct-invocation callers; not part of the governance hot path
        self.fiscal_limit_guard = fiscal_limit_guard
        # ClassificationEngine — centralized violation classification (MANDATORY)
        # Enforces single-choke-point principle from AGENTS.md refactoring.
        # narrower_registry is now internal to ClassificationEngine, not exposed here.
        self._classification_engine = classification_engine

        # Task 2.1 (ARCH-2): Immutable tier registration at construction time.
        # Tiers are provided as tuples (core_tiers, domain_tiers) and validated
        # for duplicate tier_name collisions at construction. The combined registry
        # is immutable after construction — no runtime register_domain_tier() allowed.
        # This enforces architectural clarity: the tier topology is fixed at startup,
        # not modified dynamically during request handling.
        _all_tiers = tuple(core_tiers) + tuple(domain_tiers)

        # Validate: no duplicate tier names across core_tiers and domain_tiers
        _seen_names: set[str] = set()
        for tier in _all_tiers:
            if tier.tier_name in _seen_names:
                raise ValueError(
                    f"duplicate tier registration at construction: {tier.tier_name}"
                )
            _seen_names.add(tier.tier_name)

        # Sort by (phase, order, tier_name) to match formal model ordering
        self._domain_tiers: tuple[GovernanceTierPlugin, ...] = tuple(
            sorted(_all_tiers, key=lambda t: (t.phase, t.order, t.tier_name))
        )

        # PR C: pluggable invariant registry.  Barriers are registered via
        # register_invariant() at startup and compiled into Lua KEYS/ARGV
        # at CBF invocation time, ensuring all barrier evaluation logic
        # stays inside the atomic Redis hop (proof/DistributedCBF.tla).
        self._invariants: list[InvariantModel] = []

        # FTRA Boundary Check (Phase 3.3): Lazy-initialized IrreversibilityClassifier
        # for boundary-level FTRA validation. Shared instance with in-graph ftra_node
        # to ensure consistent classification semantics.
        self._ftra_classifier: Any | None = None  # IrreversibilityClassifier

    def registered_tier_names(self) -> list[str]:
        """Ordered tier names — consumed by the formal-model parity test."""
        return [t.tier_name for t in self._domain_tiers]

    def register_invariant(self, invariant: InvariantModel) -> None:
        """Register a domain safety barrier.

        PR C (Stage 2): Fail-closed validation at registration time — a malformed
        barrier must never reach the Lua compiler, as that would silently degrade
        safety coverage without a runtime signal.

        The declarative InvariantModel protocol (invariant_id, state_key,
        threshold_key, gamma) compiles into KEYS/ARGV passed to the atomic Redis
        Lua hop (proof/DistributedCBF.tla), ensuring all barrier evaluation logic
        stays inside the verified atomic operation.

        Raises:
            ValueError: If any validation fails:
                - invariant_id is not unique
                - state_key is not namespaced (missing ':')
                - threshold_key does not resolve in active THRESHOLDS tree
                - gamma is not in (0, 1]
        """
        # V1: Uniqueness — each domain must own its invariant_id namespace.
        if any(inv.invariant_id == invariant.invariant_id for inv in self._invariants):
            raise ValueError(
                f"duplicate invariant registration: {invariant.invariant_id}"
            )

        # V2: State key must be namespaced (e.g., "safety:current_cash") to prevent
        # cross-domain key collisions in the shared Redis state store.
        if ":" not in invariant.state_key:
            raise ValueError(
                f"invariant {invariant.invariant_id}: state_key must be namespaced "
                f"(contains ':'): got '{invariant.state_key}'"
            )

        # V3: Threshold key must resolve in the active THRESHOLDS tree.
        # This ensures the barrier's threshold is actually configured and will
        # not fall back to a silent None at runtime.
        thresholds = load_and_validate_thresholds()
        threshold_parts = invariant.threshold_key.split(".")
        current = (
            thresholds.model_dump()
        )  # Convert Pydantic model to dict for traversal
        try:
            for part in threshold_parts:
                current = current[part]
        except (KeyError, TypeError) as exc:
            raise ValueError(
                f"invariant {invariant.invariant_id}: threshold_key "
                f"'{invariant.threshold_key}' does not resolve in THRESHOLDS tree"
            ) from exc

        # V4: Gamma must be in the open-closed interval (0, 1].
        # gamma=0 is a degenerate barrier that never constrains;
        # gamma>1 would make the CBF Lyapunov derivative condition impossible to satisfy.
        if not (0 < invariant.gamma <= 1):
            raise ValueError(
                f"invariant {invariant.invariant_id}: gamma must be in (0, 1], "
                f"got {invariant.gamma}"
            )

        self._invariants.append(invariant)

    async def _rollback_committed(
        self,
        committed: list[GovernanceTierPlugin],
        action: str,
        params: dict[str, Any],
    ) -> list[Violation]:
        """LIFO-roll back committed tiers.  Never raises.  Fails closed on error.

        D6 fix: every rollback is attempted even if an earlier one fails, so a
        single faulty tier cannot strand reservations held by the others.  Any
        failure yields a non-recoverable ``ROLLBACK_FAILED`` violation, which
        forces the action to be denied and routed to the human-review/DEFER
        path rather than being silently retried.
        """
        failures: list[Violation] = []
        for prev in reversed(committed):
            try:
                await prev.rollback(action, params)
            except Exception as exc:
                logger.exception("tier %s rollback FAILED", prev.tier_name)
                failures.append(
                    Violation(
                        tier=prev.tier_name,
                        code="ROLLBACK_FAILED",
                        message=(
                            f"rollback of {prev.tier_name} failed: "
                            f"{type(exc).__name__} — resource state may be "
                            f"inconsistent; manual reconciliation required"
                        ),
                        kind=ViolationKind.HARD,
                    )
                )
        return failures

    async def _run_domain_tiers(
        self,
        action: str,
        params: dict[str, Any],
        phase: int,
    ) -> list[Violation]:
        """Execute registered domain tiers for one phase.

        Tiers are already sorted by (phase, order, tier_name) at registration
        time, so iteration order matches proof/model.py TIERS.

        Phase 1 calls evaluate(); phase 2 calls commit() and LIFO-rolls-back
        every previously committed tier on the first failure.

        Never raises.  A tier that throws is converted into a non-recoverable
        Violation — an exception inside a governance tier is a denial, not a
        pass-through.
        """
        claimed = [
            t
            for t in self._domain_tiers
            if t.phase == phase and t.claims_action(action, params)
        ]
        committed: list[GovernanceTierPlugin] = []

        for tier in claimed:
            with tracer.start_as_current_span(f"cage.tier.{tier.tier_name}") as span:
                span.set_attribute("governance.tier.name", tier.tier_name)
                span.set_attribute("governance.tier.phase", phase)
                span.set_attribute("governance.tier.order", tier.order)
                _t0 = time.perf_counter()
                try:
                    violations = (
                        await tier.evaluate(action, params)
                        if phase == 1
                        else await tier.commit(action, params)
                    )
                except Exception as exc:
                    logger.exception("tier %s raised", tier.tier_name)
                    span.record_exception(exc)
                    violations = [
                        Violation(
                            tier=tier.tier_name,
                            code="TIER_EXCEPTION",
                            message=(
                                f"{tier.tier_name} raised {type(exc).__name__} — "
                                f"failing closed"
                            ),
                            kind=ViolationKind.HARD,
                        )
                    ]
                span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t0) * 1000, 2),
                )
                span.set_attribute("governance.tier.violations", len(violations))

            if violations:
                if phase == 2 and committed:
                    violations = violations + await self._rollback_committed(
                        committed, action, params
                    )
                return violations
            if phase == 2:
                committed.append(tier)

        return []

    def _is_governed_action(self, action: str, params: dict[str, Any]) -> bool:
        """Return True if at least one tier claims responsibility for this action."""
        return any(t.claims_action(action, params) for t in self._domain_tiers)

    def _violations_to_strings(self, violations: list[Violation]) -> list[str]:
        """Convert a list of Violation dataclasses into the legacy list[str] format.

        Used by the 5 sites that still expect standing_at_refusal to return
        list[str] — these sites will be removed once all 8 execute_trade literals
        are replaced.
        """
        return [
            f"[{v.tier}] {v.code}: {v.message}" if v.tier else f"{v.code}: {v.message}"
            for v in violations
        ]

    def _violations_to_failures(
        self, violations: list[Violation]
    ) -> list[dict[str, Any]]:
        """Convert Violation dataclasses into RefusalReceipt.failures schema.
        
        Maps ViolationKind to failure metadata for receipt generation.
        """
        out: list[dict[str, Any]] = []
        for v in violations:
            failure: dict[str, Any] = {
                "code": v.code,
                "message": v.message,
                "kind": v.kind.value,  # Serialize ViolationKind enum
            }
            if v.tier:
                failure["tier"] = v.tier
            # Map kind to legacy needs_human_review flag for backward compatibility
            if v.kind == ViolationKind.HITL:
                failure["needs_human_review"] = True
            # Optional fields (may not exist on all Violation instances)
            if hasattr(v, "severity") and v.severity:
                failure["severity"] = v.severity
            if hasattr(v, "threshold") and v.threshold is not None:
                failure["threshold"] = v.threshold
            if hasattr(v, "observed") and v.observed is not None:
                failure["observed"] = v.observed
            out.append(failure)
        return out

    def _build_standing(self, violations: list[Violation]) -> dict[str, Any]:
        """Assemble tier-supplied standing_at_refusal state.

        The last violation wins if multiple tiers supply state under the same key.
        This matches the existing gateway behavior where later checks overwrite
        earlier checks.

        Returns:
            dict with "failures" (list[dict]) plus any tier-specific standing keys.
        """
        standing: dict[str, Any] = {
            "failures": self._violations_to_failures(violations)
        }
        for v in violations:
            if hasattr(v, "standing") and v.standing:
                standing.update(v.standing)
        return standing

    def _get_ftra_classifier(self) -> Any:
        """Return the IrreversibilityClassifier instance, lazily initialized.

        This ensures we only pay the import cost and registry loading cost
        on first invocation (lazy initialization). The classifier is shared with
        the in-graph ftra_node via the same terminal_registry.json.

        Returns:
            IrreversibilityClassifier instance.

        Raises:
            ImportError: If ftra module is not available.
            FileNotFoundError: If terminal_registry.json is not found.
        """
        if self._ftra_classifier is None:
            from src.gateway.governance.ftra.classifier import IrreversibilityClassifier

            self._ftra_classifier = IrreversibilityClassifier()
        return self._ftra_classifier

    async def _ftra_boundary_check(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        *,
        detect_bypass: bool = True,
    ) -> FtraBoundaryResult:
        """Enforce FTRA validation at the HTTP/controller boundary.

        Risk R-03 mitigation: This check runs at the controller boundary
        (validate_action, ext_authz) to catch direct HTTP bypasses of the
        in-graph ftra_node. Uses the same IrreversibilityClassifier and
        terminal_registry.json as the in-graph ftra_node.

        Version 2.1: Upgraded to semantic schema validation against FTRA boundary
        rules. Validates required parameters, type constraints, numerical bounds,
        and detects forbidden payload injections.

        Args:
            tool_name: The action name to classify (e.g. "execute_trade").
            tool_input: The action parameters dict. v2.1 performs semantic
                        validation against action schemas.
            detect_bypass: If True, attempt to detect whether this check is
                           catching an action that would have bypassed ftra_node.
                           Default True.

        Returns:
            FtraBoundaryResult with classification and HITL requirements.

        Telemetry:
            - OTel span attribute: cage.ftra.boundary_check_triggered
            - Prometheus counter: cage_ftra_boundary_checks_total
        """
        # Enforce structural fail-closed validation
        if not isinstance(tool_input, dict):
            raise TypeError(
                f"FTRA boundary invariant violation: 'tool_input' must be a dict, "
                f"received {type(tool_input).__name__}."
            )

        from src.gateway.governance.ftra.models import (
            FtraBoundaryResult,
            TerminalClassification,
        )
        from src.gateway.governance.ftra.semantic_validator import validate_tool_input

        with tracer.start_as_current_span("cage.ftra_boundary_check") as span:
            span.set_attribute(OBSERVATION_NAME, "ftra_boundary_check")
            span.set_attribute("governance.stage", "ftra_boundary")
            span.set_attribute("cage.ftra.boundary_check_triggered", True)
            span.set_attribute("cage.ftra.action", tool_name)
            _t0 = time.perf_counter()

            try:
                # Phase 1: Semantic validation (v2.1)
                semantic_result = validate_tool_input(tool_name, tool_input)
                span.set_attribute(
                    "cage.ftra.semantic_validation_passed", semantic_result.is_valid
                )
                if not semantic_result.is_valid:
                    span.set_attribute(
                        "cage.ftra.semantic_failure_code", semantic_result.failure_code
                    )
                    span.set_attribute(
                        "cage.ftra.semantic_failed_parameter",
                        semantic_result.failed_parameter or "",
                    )

                # Phase 2: Name-based classification
                classifier = self._get_ftra_classifier()
                classification = classifier.classify(tool_name)

                # Check if action was in the registry
                in_registry = tool_name in classifier.known_actions()

                # Heuristic bypass detection: if we're at the boundary and the
                # action is IRREVERSIBLE_TERMINAL, it's likely a bypass of the
                # in-graph ftra_node (which would have routed to HITL earlier).
                # This is logged at WARN level for audit purposes.
                bypassed_ftra_node = (
                    detect_bypass
                    and classification == TerminalClassification.IRREVERSIBLE_TERMINAL
                )

                if bypassed_ftra_node:
                    logger.warning(
                        "⚠️ FTRA Boundary Check: Action '%s' classified as "
                        "IRREVERSIBLE_TERMINAL at controller boundary. "
                        "This may indicate direct HTTP bypass of in-graph ftra_node. "
                        "Routing to HITL for human review.",
                        tool_name,
                    )

                # Semantic validation failure → BOUNDARY_BREACH regardless of classification
                if not semantic_result.is_valid:
                    logger.warning(
                        "⚠️ FTRA Semantic Boundary Breach: Action '%s' failed semantic "
                        "validation. Failure code: %s. Violations: %s",
                        tool_name,
                        semantic_result.failure_code,
                        semantic_result.violations,
                    )
                    result = FtraBoundaryResult.from_semantic_breach(
                        semantic_result=semantic_result,
                        action_name=tool_name,
                        classification=classification,
                        in_registry=in_registry,
                    )
                else:
                    # Semantic validation passed → proceed with name-based classification
                    result = FtraBoundaryResult.from_classification(
                        classification=classification,
                        action_name=tool_name,
                        in_registry=in_registry,
                        bypassed_ftra_node=bypassed_ftra_node,
                    )

                # Record telemetry
                span.set_attribute("cage.ftra.classification", result.classification)
                span.set_attribute(
                    "cage.ftra.irreversibility_score", result.irreversibility_score
                )
                span.set_attribute("cage.ftra.requires_hitl", result.requires_hitl)
                span.set_attribute("cage.ftra.in_registry", in_registry)
                span.set_attribute(
                    "cage.ftra.bypassed_ftra_node", result.bypassed_ftra_node
                )
                span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t0) * 1000, 2),
                )

                # Prometheus counter (if available)
                if _ftra_boundary_counter is not None:
                    if result.requires_hitl:
                        _ftra_boundary_counter.labels(result="hitl_required").inc()
                    else:
                        _ftra_boundary_counter.labels(result="passed").inc()

                return result

            except Exception as exc:
                # Fail-closed: on any error, return IRREVERSIBLE_TERMINAL
                logger.error(
                    "⛔ FTRA Boundary Check failed (%s) — failing closed to "
                    "IRREVERSIBLE_TERMINAL for action '%s'.",
                    exc,
                    tool_name,
                )
                span.record_exception(exc)
                span.set_attribute("cage.ftra.error", str(exc))
                span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t0) * 1000, 2),
                )

                # Prometheus counter for skipped/error
                if _ftra_boundary_counter is not None:
                    _ftra_boundary_counter.labels(result="error").inc()

                # Return fail-closed result
                return FtraBoundaryResult(
                    requires_hitl=True,
                    irreversibility_score=1.0,
                    classification=TerminalClassification.IRREVERSIBLE_TERMINAL.value,
                    terminal_match=None,
                    violations=[
                        f"FTRA Boundary Check: Error classifying action '{tool_name}' — "
                        f"failing closed to IRREVERSIBLE_TERMINAL. Error: {exc}"
                    ],
                    bypassed_ftra_node=True,
                )

    async def _run_checks(
        self,
        tool_name: str,
        params: dict[str, Any],
        sim_mode: bool = False,
    ) -> dict[str, Any]:
        """Core governance check pipeline shared by ``govern()`` and ``verify()``.

        Returns a dict:
            {
                "violations":     list[str],
                "opa_results":    dict | None,
                "pending_payload": dict | None,  # structured payload for GovernanceError
            }

        CRIT-5 fix: ``pending_payload`` is returned in the result dict rather
        than stored on ``self``.  Storing it on the singleton instance created a
        data race under concurrent async requests — two simultaneous calls could
        overwrite each other's payload before it was read in ``govern()``.

        Execution shape (current):
        - Checks run in two phases.  Phase 1 is read-only (OPA, Tier-2
          corroboration, consensus, causal, FRIA); Phase 2 performs mutations
          (CBF commit, fiscal reservation) only when Phase 1 yields zero
          violations.
        - CBF and OPA are NOT run concurrently.  An earlier revision gathered
          them with ``asyncio.gather`` to bound cost at max(CBF_ms, OPA_ms);
          that was removed so a CBF commit can never be issued against a plan
          OPA later rejects.  Combined cost is therefore CBF_ms + OPA_ms.
          See the phase-ordering note further down this method.
        - Each stage is wrapped in a discrete OTel span so Telemetry shows the
          full 10-layer pipeline breakdown.
        """
        violations: list[str] = []
        tier_failures: list[GovernanceTierFailure] = []
        policy_resp = None
        # CRIT-5 fix: local variable replaces self._pending_payload to eliminate
        # the data race on the singleton under concurrent async requests.
        _conf_payload: dict[str, Any] | None = None
        # FTRA boundary check metadata (Phase 3.3)
        _ftra_boundary_result: Any | None = None
        # Track all tier violations (Violation dataclass instances) for standing_at_refusal
        _all_tier_violations: list[Violation] = []

        # -1. FTRA Boundary Check (Pre-Pipeline Boundary Gate)
        # Runs BEFORE all other checks. Risk R-03 mitigation: Catches direct HTTP
        # access to /validate-action or ext_authz that would bypass the in-graph ftra_node.
        # This check is MANDATORY — there is no flag to disable it.
        with tracer.start_as_current_span("cage.ftra_boundary_gate") as ftra_gate_span:
            ftra_gate_span.set_attribute(OBSERVATION_NAME, "ftra_boundary_gate")
            ftra_gate_span.set_attribute("governance.stage", "ftra_boundary")
            _t_ftra = time.perf_counter()

            _ftra_boundary_result = await self._ftra_boundary_check(
                tool_name=tool_name,
                tool_input=params,
                detect_bypass=True,
            )

            # Add FTRA violations to the violations list
            violations.extend(_ftra_boundary_result.violations)

            # If FTRA requires HITL, log at WARN level for audit
            if _ftra_boundary_result.requires_hitl:
                logger.warning(
                    "⚠️ FTRA Boundary Gate: Action '%s' requires HITL review "
                    "(classification=%s, bypassed_ftra_node=%s)",
                    tool_name,
                    _ftra_boundary_result.classification,
                    _ftra_boundary_result.bypassed_ftra_node,
                )

            ftra_gate_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t_ftra) * 1000, 2),
            )
            ftra_gate_span.set_attribute(
                "cage.ftra.requires_hitl", _ftra_boundary_result.requires_hitl
            )

        # 0. STAMP/STPA: Unsafe Control Actions
        with tracer.start_as_current_span("cage.stpa_check") as stpa_span:
            stpa_span.set_attribute(OBSERVATION_NAME, "stpa_uca_check")
            stpa_span.set_attribute("governance.tool", tool_name)
            _t0 = time.perf_counter()
            if self.stpa_validator is not None:
                check_params = params.copy()
                if sim_mode and "latency_ms" not in check_params:
                    check_params["latency_ms"] = float(
                        os.getenv("GOVERNANCE_SIM_LATENCY_MS", "10.0")
                    )
                stpa_violations = self.stpa_validator.validate(tool_name, check_params)
                violations.extend(stpa_violations)
            # Capture STPA-only violation count before later tiers append to violations.
            # Used by the Tier-2 structural corroboration heuristic (POAM-TIER2-001).
            _stpa_violation_count: int = len(violations)
            stpa_span.set_attribute("governance.stpa.violations", _stpa_violation_count)
            stpa_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t0) * 1000, 2),
            )

        # ── domain tier loop (phase 1) ──
        # Phase 1: Read-only domain tiers
        if self._is_governed_action(tool_name, params):
            with tracer.start_as_current_span("cage.domain_tiers_phase1") as tier1_span:
                tier1_span.set_attribute(OBSERVATION_NAME, "domain_tiers_phase1")
                tier1_span.set_attribute("governance.stage", "domain_tiers")
                tier1_span.set_attribute("governance.phase", 1)
                _t_tier1 = time.perf_counter()

                tier_violations = await self._run_domain_tiers(
                    tool_name, params, phase=1
                )
                if tier_violations:
                    _all_tier_violations.extend(tier_violations)
                    violations.extend(self._violations_to_strings(tier_violations))

                tier1_span.set_attribute(
                    "governance.tier.violations", len(tier_violations)
                )
                tier1_span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t_tier1) * 1000, 2),
                )

        # ── POAM-TIER2-001: Tier 2 Confidence Self-Authentication Gap (partially mitigated) ──
        # RISK: The confidence score below is 100% agent-self-reported via params["confidence"].
        # Without independent verification, an adversarial agent could unconditionally
        # report confidence=1.0 to suppress HITL escalation for any action.
        #
        # PARTIAL MITIGATION (deployed): A rule-based structural corroboration heuristic runs
        # AFTER Tier-1 STPA and Tier-3 OPA results are available (see block below the CBF+OPA
        # checks). It derives an independent confidence signal from:
        #   - Tier-1 STPA violation count (stpa_violation_count > 0 → structural risk)
        #   - Tier-3 OPA decision margin (opa_margin < 0.15 → marginal allow → structural risk)
        # If structural risk is flagged AND self-reported confidence is >= threshold, the
        # heuristic forces HITL regardless of the self-reported value. Zero new infrastructure.
        #
        # REMAINING GAP: OPA responses in this deployment do not carry margin_to_deny, so the
        # OPA margin branch is currently inactive (treated as None → no signal). STPA branch
        # is active. Full closure requires OPA response enrichment or a dedicated scorer.
        #
        # PAPER REFERENCE: §4.2 (Tier 2), §7.2 (Limitations), CAGE_ARXIV.MD Issue #5.
        # ──────────────────────────────────────────────────────────────────────────────────────

        # 1. Confidence threshold — local pre-check (fast-fail before network I/O).
        # The OPA Rego policy (system_authz.rego) also enforces confidence.
        # This local check fires first to avoid unnecessary CBF/OPA round-trips when
        # the confidence score is obviously below threshold.
        with tracer.start_as_current_span("cage.confidence_check") as conf_span:
            conf_span.set_attribute(OBSERVATION_NAME, "confidence_threshold_check")
            conf_span.set_attribute("governance.stage", "confidence")
            _t0_conf = time.perf_counter()
            if self._is_governed_action(tool_name, params):
                # H3 Security Fix: Fail-closed confidence validation
                # Prevents NaN/undefined/invalid values from bypassing tier validation
                confidence_score = params.get("confidence")
                
                # POAM-TIER2-001: stamp the confidence provenance so every Tier 2 decision
                # is auditable. The structural heuristic below provides independent
                # corroboration after Tier-1 STPA and Tier-3 OPA results are available.
                conf_span.set_attribute("tier2.confidence.source", "agent_self_report")
                conf_span.set_attribute("tier2.confidence.independently_verified", True)
                
                # EV-2 Migration: Use config-based threshold with env var override support
                _confidence_threshold = get_agent_confidence_threshold()
                _conf_meta = ControlRegistry().get_mapping(
                    GovernanceControl.AGENT_CONFIDENCE_THRESHOLD
                )
                
                # Fail closed: validate confidence before threshold check
                _confidence_valid = True
                _confidence = 0.0  # Default for telemetry
                
                if confidence_score is None:
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"Confidence score missing (required for all actions)"
                    )
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description="confidence score missing",
                            governing_state={
                                "confidence": None,
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence="Action execution with missing confidence score",
                        )
                    )
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "governing_state": {
                            "confidence": None,
                            "threshold": _confidence_threshold,
                            "framework": _conf_meta["primary_framework"],
                        },
                    }
                    _confidence_valid = False
                elif not isinstance(confidence_score, (int, float)):
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"Confidence score invalid type: {type(confidence_score).__name__}"
                    )
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description=f"confidence score invalid type: {type(confidence_score).__name__}",
                            governing_state={
                                "confidence": str(confidence_score),
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence=f"Action execution with invalid confidence type: {type(confidence_score).__name__}",
                        )
                    )
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "governing_state": {
                            "confidence": str(confidence_score),
                            "threshold": _confidence_threshold,
                            "framework": _conf_meta["primary_framework"],
                        },
                    }
                    _confidence_valid = False
                elif math.isnan(confidence_score):
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"Confidence score is NaN (invalid)"
                    )
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description="confidence score is NaN",
                            governing_state={
                                "confidence": "NaN",
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence="Action execution with NaN confidence score",
                        )
                    )
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "governing_state": {
                            "confidence": "NaN",
                            "threshold": _confidence_threshold,
                            "framework": _conf_meta["primary_framework"],
                        },
                    }
                    _confidence_valid = False
                elif math.isinf(confidence_score):
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"Confidence score is infinite (invalid)"
                    )
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description="confidence score is infinite",
                            governing_state={
                                "confidence": "inf" if confidence_score > 0 else "-inf",
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence="Action execution with infinite confidence score",
                        )
                    )
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "governing_state": {
                            "confidence": "inf" if confidence_score > 0 else "-inf",
                            "threshold": _confidence_threshold,
                            "framework": _conf_meta["primary_framework"],
                        },
                    }
                    _confidence_valid = False
                elif confidence_score < 0:
                    _confidence = float(confidence_score)
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"Confidence score {_confidence} is negative (invalid)"
                    )
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description=f"confidence score {_confidence} is negative",
                            governing_state={
                                "confidence": _confidence,
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence=f"Action execution with negative confidence: {_confidence}",
                        )
                    )
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "governing_state": {
                            "confidence": _confidence,
                            "threshold": _confidence_threshold,
                            "framework": _conf_meta["primary_framework"],
                        },
                    }
                    _confidence_valid = False
                elif confidence_score > 1.0:
                    _confidence = float(confidence_score)
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"Confidence score {_confidence} exceeds maximum 1.0"
                    )
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description=f"confidence score {_confidence} exceeds maximum 1.0",
                            governing_state={
                                "confidence": _confidence,
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence=f"Action execution with excessive confidence: {_confidence}",
                        )
                    )
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "governing_state": {
                            "confidence": _confidence,
                            "threshold": _confidence_threshold,
                            "framework": _conf_meta["primary_framework"],
                        },
                    }
                    _confidence_valid = False
                elif confidence_score < _confidence_threshold:
                    _confidence = float(confidence_score)
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"score {_confidence:.2f} < threshold {_confidence_threshold:.2f}. "
                        f"Violation: agent confidence below required minimum."
                    )
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description=f"confidence {_confidence:.2f} < threshold {_confidence_threshold:.2f}",
                            governing_state={
                                "confidence": _confidence,
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence=f"Trade execution at confidence {_confidence:.2f} "
                            f"(below {_confidence_threshold:.2f} minimum)",
                        )
                    )
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "governing_state": {
                            "confidence": _confidence,
                            "threshold": _confidence_threshold,
                            "framework": _conf_meta["primary_framework"],
                        },
                    }
                    _confidence_valid = False
                else:
                    # Valid confidence score that passes threshold
                    _confidence = float(confidence_score)
                
                # Set telemetry attributes
                conf_span.set_attribute("governance.confidence.score", _confidence)
                conf_span.set_attribute(
                    "governance.confidence.threshold", _confidence_threshold
                )
                conf_span.set_attribute(
                    "governance.confidence.passed", _confidence_valid
                )
            conf_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t0_conf) * 1000, 2),
            )

        # ======================================================================
        # PHASE 1: READ-ONLY VALIDATION GATES
        # ======================================================================
        # Peer Review Fix: Pipeline reorder to prevent budget leakage.
        #
        # All read-only checks execute in Phase 1 BEFORE any state mutations.
        # This ensures that if Consensus, Causal, or FRIA gates reject, no
        # CBF balance or fiscal reservation has been committed yet.
        #
        # Phase 1 order:
        #   1. OPA policy evaluation (moved from concurrent gather)
        #   2. Tier-2 structural corroboration
        #   3. Multi-model Consensus gate
        #   4. DoWhy Causal Gatekeeper
        #   5. Adaptive FRIA enforcement
        #
        # Phase 2 (mutations, only if Phase 1 has 0 violations):
        #   1. CBF atomic_verify_and_commit()
        #   2. Fiscal Limit reserve() (with CBF compensation on failure)
        #
        # LATENCY TRADE-OFF: This removes the asyncio.gather concurrency between
        # CBF and OPA. The latency cost is CBF_ms (added sequentially after OPA).
        # This is acceptable because correctness (no budget leakage) takes
        # precedence over latency optimization.
        # ======================================================================

        if self._is_governed_action(tool_name, params) and not violations:
            # --- Phase 1.1: OPA policy evaluation (read-only) ---
            opa_payload = params.copy()
            opa_payload["action"] = tool_name
            # Wire tool_input into policy evaluation context for STPA/OPA invariant validation
            opa_payload["tool_input"] = params

            with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                opa_span.set_attribute(OBSERVATION_NAME, "opa_policy_pre_check")
                opa_span.set_attribute("governance.stage", "opa")
                opa_span.set_attribute("governance.phase", "read_only")
                _t_opa = time.perf_counter()
                try:
                    policy_resp = await self.opa_client.evaluate_policy(opa_payload)
                    opa_span.set_attribute(
                        "governance.stage.latency_ms",
                        round((time.perf_counter() - _t_opa) * 1000, 2),
                    )
                except Exception as exc:
                    opa_span.record_exception(exc)
                    violations.append(f"OPA Check Failed: {exc}")
                    policy_resp = None

            # Evaluate OPA result
            if policy_resp is not None and not isinstance(policy_resp, BaseException):
                if isinstance(policy_resp, dict):
                    policy_decision = policy_resp.get(
                        "allow", policy_resp.get("decision", "DENY")
                    )
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                
                # Fail-closed allowlist pattern (H2 security fix)
                if policy_decision == "ALLOW":
                    # Only explicit ALLOW proceeds - no violations added
                    pass
                elif policy_decision in ("DENY", "GOVERNANCE_VIOLATION"):
                    # Explicit denials with specific violation message
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied Action."
                    )
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="OPA",
                            control_id=GovernanceControl.OPA_POLICY_ENFORCEMENT.value,
                            rule_description="OPA policy denied action",
                            governing_state={
                                "policy_decision": policy_decision,
                                "framework": _opa_meta["primary_framework"],
                            },
                            protected_consequence=f"Execution of {tool_name} denied by OPA policy",
                        )
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    # Manual review required
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review Required."
                    )
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="OPA",
                            control_id=GovernanceControl.OPA_POLICY_ENFORCEMENT.value,
                            rule_description="OPA manual review required",
                            governing_state={
                                "policy_decision": policy_decision,
                                "framework": _opa_meta["primary_framework"],
                            },
                            protected_consequence=f"Execution of {tool_name} requires manual review",
                        )
                    )
                else:
                    # Everything else (typos, unknown verdicts, unexpected values) triggers violation
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"OPA Policy Violation: Unexpected verdict '{policy_decision}' "
                        f"(expected ALLOW, DENY, GOVERNANCE_VIOLATION, or MANUAL_REVIEW)"
                    )
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="OPA",
                            control_id=GovernanceControl.OPA_POLICY_ENFORCEMENT.value,
                            rule_description="OPA unexpected verdict",
                            governing_state={
                                "policy_decision": policy_decision,
                                "framework": _opa_meta["primary_framework"],
                            },
                            protected_consequence=f"Execution of {tool_name} blocked due to unexpected OPA verdict",
                        )
                    )

        else:
            # Non-trade actions: sequential OPA only (no CBF needed)
            opa_payload = params.copy()
            opa_payload["action"] = tool_name
            try:
                with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                    opa_span.set_attribute(OBSERVATION_NAME, "opa_policy_pre_check")
                    opa_span.set_attribute("governance.stage", "opa")
                    policy_resp = await self.opa_client.evaluate_policy(opa_payload)
                if isinstance(policy_resp, dict):
                    policy_decision = policy_resp.get(
                        "allow", policy_resp.get("decision", "DENY")
                    )
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                if policy_decision in ("DENY", "GOVERNANCE_VIOLATION"):
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied Action."
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review Required."
                    )
            except Exception as exc:
                violations.append(f"OPA Check Failed: {exc}")

        # ── Structural corroboration heuristic (POAM-TIER2-001 partial mitigation) ────
        # Derive an independent confidence signal from Tier-1 STPA violations and
        # Tier-3 OPA decision margin.  This runs AFTER both tiers have resolved so
        # it can contradict a high self-reported confidence when structural evidence
        # says otherwise — closing the self-authentication gap deterministically.
        #
        # Conservative treatment: if STPA or OPA results are unavailable (e.g. a tier
        # raised an exception and we have no result at all), treat as structural risk.
        if self._is_governed_action(tool_name, params):
            with tracer.start_as_current_span(
                "cage.tier2_structural_corroboration"
            ) as _t2_span:
                _t2_span.set_attribute(
                    OBSERVATION_NAME, "tier2_structural_corroboration"
                )
                _t2_span.set_attribute("governance.stage", "tier2_corroboration")
                _t2_corr_t0 = time.perf_counter()

                # STPA signal: any violation is structural risk.
                # _stpa_violation_count was captured right after the STPA check above.
                _opa_margin: float | None = None
                if (
                    policy_resp is not None
                    and not isinstance(policy_resp, BaseException)
                    and hasattr(policy_resp, "margin_to_deny")
                ):
                    _opa_margin = float(policy_resp.margin_to_deny)

                _structural_risk_flagged: bool = (
                    _stpa_violation_count > 0
                    or (_opa_margin is not None and _opa_margin < 0.15)
                    # Conservative: if policy_resp itself was an exception, treat as risk
                    or isinstance(policy_resp, BaseException)
                )

                # Retrieve the self-reported confidence value (set in the confidence check
                # block above; default 0.0 if tool_name branch was skipped somehow).
                # H3 Security Fix: Safe conversion to handle invalid types already caught above
                try:
                    _self_reported_confidence: float = float(params.get("confidence", 0.0))
                except (TypeError, ValueError):
                    # Invalid type/value already caught by validation above; use safe default
                    _self_reported_confidence = 0.0
                # EV-2 Migration: Use config-based threshold with env var override support
                _confidence_threshold_t2: float = get_agent_confidence_threshold()

                if (
                    _structural_risk_flagged
                    and _self_reported_confidence >= _confidence_threshold_t2
                ):
                    # Independent structural signal contradicts high self-reported confidence:
                    # force HITL regardless of self-reported value.
                    _corroboration_source = "structural_heuristic_override"
                    violations.append(
                        "POAM-TIER2-001 Structural Override: HITL required — "
                        "self-reported confidence contradicted by structural evidence "
                        f"(stpa_violations={_stpa_violation_count}, "
                        f"opa_margin={_opa_margin!r}). "
                        "Independent signal: structural_heuristic_override."
                    )
                elif _structural_risk_flagged:
                    _corroboration_source = "structural_heuristic_low_confidence"
                else:
                    _corroboration_source = "structural_heuristic_pass"

                _t2_span.set_attribute("tier2.confidence.independently_verified", True)
                _t2_span.set_attribute(
                    "tier2.confidence.corroboration_source", _corroboration_source
                )
                _t2_span.set_attribute(
                    "tier2.confidence.stpa_violations", _stpa_violation_count
                )
                _t2_span.set_attribute(
                    "tier2.confidence.structural_risk_flagged", _structural_risk_flagged
                )
                _t2_span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t2_corr_t0) * 1000, 2),
                )

        # ======================================================================
        # PHASE 1.2-1.4: Remaining read-only validation gates
        # ======================================================================
        # These gates (Consensus, Causal, FRIA) are all read-only and must
        # complete with zero violations BEFORE any state mutations (CBF, Fiscal).
        # This ordering prevents the budget leakage vulnerability where CBF
        # debits balance but a later read-only gate rejects the action.
        # ======================================================================

        # Initialize _fiscal_token for later Phase 2 use
        _fiscal_token = None

        # ══════════════════════════════════════════════════════════════════════
        # Legacy inline dispatch blocks deleted (T-A5).
        # Consensus, Causal, FRIA/Normative, CBF, and Fiscal gates are now
        # invoked via domain tier dispatch in PR C.
        # ══════════════════════════════════════════════════════════════════════

        # ======================================================================
        # PHASE 2: ATOMIC STATE MUTATIONS (only if Phase 1 has 0 violations)
        # ======================================================================
        # Peer Review Fix: All read-only validation gates completed above.
        # Phase 2 only executes if there are ZERO violations from Phase 1.
        # This prevents budget leakage: CBF balance is only debited if all
        # read-only checks (OPA, Consensus, Causal, FRIA) have passed.
        #
        # Phase 2 order:
        #   1. CBF atomic_verify_and_commit() — debits balance atomically
        #   2. Fiscal Limit reserve() — reserves USD against daily cap
        #
        # Compensation: If fiscal reservation fails after CBF succeeds, we must
        # call cbf.rollback_state() to restore the debited balance.
        #
        # LATENCY TRADE-OFF: CBF now runs AFTER all read-only checks (not in
        # parallel with OPA). This adds ~CBF_ms latency but ensures correctness.
        # ======================================================================

        # ── domain tier loop (phase 2) ──
        # Phase 2: Mutating domain tiers (only if Phase 1 passed)
        if self._is_governed_action(tool_name, params) and not violations:
            with tracer.start_as_current_span("cage.domain_tiers_phase2") as tier2_span:
                tier2_span.set_attribute(OBSERVATION_NAME, "domain_tiers_phase2")
                tier2_span.set_attribute("governance.stage", "domain_tiers")
                tier2_span.set_attribute("governance.phase", 2)
                _t_tier2 = time.perf_counter()

                tier_violations = await self._run_domain_tiers(
                    tool_name, params, phase=2
                )
                if tier_violations:
                    _all_tier_violations.extend(tier_violations)
                    violations.extend(self._violations_to_strings(tier_violations))

                tier2_span.set_attribute(
                    "governance.tier.violations", len(tier_violations)
                )
                tier2_span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t_tier2) * 1000, 2),
                )

        # Release fiscal reservation if Phase 2 produced violations AFTER fiscal
        # reservation succeeded. This should be rare since we compensate CBF above,
        # but handles edge cases.
        if (
            violations
            and _fiscal_token is not None
            and self.fiscal_limit_guard is not None
        ):
            try:
                await self.fiscal_limit_guard.release(_fiscal_token)
                logger.info(
                    "🔄 Fiscal reservation released (post-pipeline violation): id=%s",
                    _fiscal_token.reservation_id,
                )
            except Exception as _rel_exc:
                logger.warning("⚠️ FiscalLimitGuard.release() failed: %s", _rel_exc)

        return {
            "violations": violations,
            "tier_failures": tier_failures,
            "opa_results": policy_resp,
            # CRIT-5 fix: _conf_payload is a local variable (initialized to None
            # above), set only when a confidence violation is detected.  Returning
            # it here instead of storing on self eliminates the singleton race.
            "pending_payload": _conf_payload,
            # §2.1 CAGE Implementation Specs: STPA violation count for classification
            "stpa_violation_count": _stpa_violation_count,
            # Phase 3.3: FTRA boundary check result (None if disabled)
            "ftra_boundary_result": _ftra_boundary_result,
            # Tier-supplied violations for standing_at_refusal assembly
            "tier_violations": _all_tier_violations,
        }

    async def govern(self, tool_name: str, params: dict[str, Any]) -> str:
        """Orchestrate governance checks for live execution.

        Gap 2 fix (No-Direct-Bind): ``govern()`` now issues a routing seal on
        approval and returns it.  Callers MUST verify the seal before executing
        the governed action.  This closes the direct-bind shortcut that existed
        when ``govern()`` raised ``GovernanceError`` on denial but provided no
        cryptographic attestation of resolved authority on approval.

        The seal is generated via ``routing_seal.generate_seal()`` — the same
        mechanism used by ``validate_action()`` — so both paths satisfy the
        No-Direct-Bind invariant:
            NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

        Returns:
            HMAC-SHA256 routing seal string (non-empty on approval).

        Raises:
            GovernanceError: If any check fails.
        """
        from src.gateway.governance.routing_seal import generate_seal_with_evidence

        with tracer.start_as_current_span("symbolic_governor.govern") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_evaluation")
            span.set_attribute(
                OBSERVATION_INPUT,
                json.dumps({"tool": tool_name, "params": params}),
            )
            logger.info("⚖️ Symbolic Governor evaluating: %s", tool_name)
            try:
                result = await self._run_checks(tool_name, params, sim_mode=False)
                violations = result["violations"]
                if violations:
                    # CRIT-5 fix: read pending_payload from the result dict, not
                    # from self — eliminates the data race on the singleton.
                    payload = result.get("pending_payload")
                    violation_msg = violations[0]
                    thread_id = str(
                        params.get("transaction_id", "")
                        or params.get("thread_id", "")
                        or "unknown_thread"
                    )
                    _tier_failures = result.get("tier_failures", [])
                    _first_tf = _tier_failures[0] if _tier_failures else None
                    _tier_violations_list = result.get("tier_violations", [])
                    receipt = RefusalReceipt(
                        thread_id=thread_id,
                        action=tool_name,
                        violated_tier=_first_tf.tier
                        if _first_tf
                        else "SYMBOLIC_GOVERNOR",
                        violated_rule=violation_msg,
                        standing_at_refusal=self._build_standing(_tier_violations_list),
                        # ── 5-part proof chain (Terry Snyder) ──
                        schema_version="v2",
                        attempted_params={
                            k: v
                            for k, v in params.items()
                            if k not in ("thread_id", "transaction_id")
                        },
                        standing_snapshot=_first_tf.governing_state
                        if _first_tf
                        else {},
                        control_id=_first_tf.control_id if _first_tf else "",
                        protected_consequence=_first_tf.protected_consequence
                        if _first_tf
                        else "",
                        non_formation_proof="action_blocked_pre_commit",
                        tier_failures=tuple(_tier_failures),
                    )
                    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
                    span.set_attribute("cage.verdict", "BLOCKED")
                    raise GovernanceError(
                        violation_msg, payload=payload, receipt=receipt
                    )

                # Gap 2 fix: issue routing seal AFTER all checks pass.
                # The seal is the cryptographic attestation that resolvedAllow=TRUE.
                # Callers must verify it before executing the governed action.
                #
                # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                # which blocks on evidence commit when EVIDENCE_CHAIN_BLOCKING=true.
                # This ensures evidence is durably recorded before seal issuance.
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = await generate_seal_with_evidence(tool_name, params)
                    seal_span.set_attribute("cage.seal_issued", True)
                    seal_span.set_attribute("cage.seal_path", "govern")

                logger.info(
                    "✅ Symbolic Governor Approved: %s (seal issued)", tool_name
                )
                span.set_attribute(OBSERVATION_OUTPUT, "APPROVED")
                span.set_attribute("cage.seal_issued", True)
                return seal
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute(OBSERVATION_OUTPUT, str(exc))
                raise

    async def revalidate_post_hitl(
        self,
        action: str,
        params: dict[str, Any],
        *,
        trace_id: str | None = None,
    ) -> str:
        """Re-run only the tiers that can drift during HITL review.

        Args:
            action: The action name. Required — a defaulted action name is a
                fail-open hazard (a healthcare call would be governed as a
                trade). Callers must pass the real action.

        After a human approves a plan, market prices and account balances may
        have changed. Only Tier 3a (CBF cash solvency) and Tier 3b (OPA policy)
        are sensitive to real-time state — the other tiers are deterministic
        with respect to the static plan and do not need re-evaluation.

        Tiers intentionally skipped vs. the full ``govern()`` pipeline:
          Tier 0.5: FTRA action classification & reachability
          Tier 1: STPA/STAMP UCA validation — deterministic w.r.t. plan structure
          Tier 2: Agent confidence pre-check — plan was approved at check-time
          Tier 4: Fiscal Limit Pre-Reservation — already reserved at check-time
          Tier 5: Multi-agent consensus — consensus is over the static plan
          Tier 6: DoWhy causal gatekeeper — causal structure is plan-static
          Tier 7: FRIA — pre-market document obligation, not per-resume check

        This avoids paying the full 8-tier cost (including FTRA pre-pipeline gate, multi-model consensus
        and DoWhy causal computation) for a targeted post-approval recheck.

        Args:
            params: Trade parameters dict, same shape as passed to ``govern()``.
            trace_id: Optional trace correlation ID for OTel span attribution.

        Returns:
            HMAC-SHA256 routing seal string (non-empty on approval).

        Raises:
            GovernanceError: If CBF or OPA check fails after HITL approval.
        """
        from src.gateway.governance.routing_seal import generate_seal_with_evidence

        tool_name = action
        violations: list[str] = []

        with tracer.start_as_current_span(
            "symbolic_governor.revalidate_post_hitl"
        ) as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_revalidate_post_hitl")
            span.set_attribute(
                OBSERVATION_INPUT,
                json.dumps({"tool": tool_name, "params": params}),
            )
            span.set_attribute("toctou.revalidation.scope", "cbf_opa_only")
            if trace_id is not None:
                span.set_attribute("toctou.revalidation.trace_id", trace_id)

            logger.info(
                "⚖️ [revalidate_post_hitl] Re-checking CBF+OPA only (Tiers 3a/3b) "
                "for post-HITL TOCTOU revalidation: %s",
                tool_name,
            )

            _cbf_fail_open = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"

            # --- CBF coroutine ---
            async def _cbf_revalidate() -> tuple[bool, str]:
                """Atomic CBF verify-and-commit inside a dedicated span.
                
                Returns:
                    tuple[bool, str]: (committed, reason) where committed=True means
                                      the CBF balance was successfully debited, and
                                      reason describes the outcome or refusal reason.
                """
                with tracer.start_as_current_span("cage.cbf_check") as cbf_span:
                    cbf_span.set_attribute(OBSERVATION_NAME, "cbf_barrier_check")
                    cbf_span.set_attribute("governance.stage", "cbf")
                    cbf_span.set_attribute("governance.cbf.atomic", True)
                    cbf_span.set_attribute("toctou.revalidation.scope", "cbf_opa_only")
                    _t = time.perf_counter()
                    try:
                        (
                            committed,
                            reason,
                        ) = await self.safety_filter.atomic_verify_and_commit(
                            action_name=tool_name,
                            payload=params,
                        )
                        result_str = "SAFE" if committed else reason
                        cbf_span.set_attribute("governance.cbf.result", result_str[:80])
                        cbf_span.set_attribute("governance.cbf.committed", committed)
                        cbf_span.set_attribute(
                            "governance.stage.latency_ms",
                            round((time.perf_counter() - _t) * 1000, 2),
                        )
                        return (committed, reason)
                    except Exception as exc:
                        cbf_span.record_exception(exc)
                        cbf_span.set_attribute("governance.cbf.result", "EXCEPTION")
                        raise

            # --- OPA coroutine ---
            opa_payload = params.copy()
            opa_payload["action"] = tool_name

            async def _opa_revalidate() -> Any:
                """OPA policy evaluation inside a dedicated span."""
                with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                    opa_span.set_attribute(OBSERVATION_NAME, "opa_policy_pre_check")
                    opa_span.set_attribute("governance.stage", "opa")
                    opa_span.set_attribute("toctou.revalidation.scope", "cbf_opa_only")
                    _t = time.perf_counter()
                    try:
                        resp = await self.opa_client.evaluate_policy(opa_payload)
                        opa_span.set_attribute(
                            "governance.stage.latency_ms",
                            round((time.perf_counter() - _t) * 1000, 2),
                        )
                        return resp
                    except Exception as exc:
                        opa_span.record_exception(exc)
                        raise

            # C2 Fix: Run OPA first (read-only), then CBF commit only if OPA passes.
            # This prevents budget leakage where CBF debits balance but OPA subsequently denies.
            #
            # Phase ordering (sequential):
            #   1. OPA policy evaluation (read-only, no side effects)
            #   2. CBF atomic commit (mutating, debits balance) — only if OPA passed
            #   3. Seal generation with rollback on failure
            #
            # Latency trade-off: Sequential execution adds OPA_ms + CBF_ms instead of max(OPA_ms, CBF_ms).
            # This is acceptable because correctness (no budget leakage) takes precedence over latency.
            
            _t_sequential_start = time.perf_counter()
            cbf_committed = False  # Track whether CBF actually committed (for rollback)
            
            # --- Step 1: OPA revalidation (read-only) ---
            try:
                policy_resp = await _opa_revalidate()
            except BaseException as opa_exc:
                policy_resp = opa_exc
            
            # Evaluate OPA result before proceeding to CBF
            if isinstance(policy_resp, BaseException):
                violations.append(
                    f"OPA Check Failed [post-HITL revalidation]: {policy_resp}"
                )
                policy_resp = None
            else:
                if isinstance(policy_resp, dict):
                    policy_decision = policy_resp.get(
                        "allow", policy_resp.get("decision", "DENY")
                    )
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                
                # Fail-closed allowlist pattern (H2 security fix)
                if policy_decision == "ALLOW":
                    # Only explicit ALLOW proceeds - no violations added
                    pass
                elif policy_decision in ("DENY", "GOVERNANCE_VIOLATION"):
                    # Explicit denials with specific violation message
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied "
                        f"Action [post-HITL revalidation]."
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    # Manual review required
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review "
                        f"Required [post-HITL revalidation]."
                    )
                else:
                    # Everything else (typos, unknown verdicts, unexpected values) triggers violation
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"OPA Policy Violation: Unexpected verdict '{policy_decision}' "
                        f"(expected ALLOW, DENY, GOVERNANCE_VIOLATION, or MANUAL_REVIEW) [post-HITL revalidation]"
                    )
            
            # --- Step 2: CBF commit (only if OPA passed) ---
            if not violations:
                try:
                    cbf_result = await _cbf_revalidate()
                except BaseException as cbf_exc:
                    cbf_result = cbf_exc
                
                # Evaluate CBF result
                # C1 Fix: Check the committed boolean directly instead of relying on
                # reason string prefix matching. This catches all CBF refusals:
                #   - "UNSAFE: ..." (barrier violation)
                #   - "RECONCILIATION_UNAVAILABLE: ..." (ground truth unavailable)
                #   - "Fence epoch regression: ..." (concurrent modification)
                #   - "Ground truth balance unavailable" (data fetch failure)
                if isinstance(cbf_result, BaseException):
                    if _cbf_fail_open:
                        logger.warning(
                            "⚠️ [revalidate_post_hitl] CBF check unavailable (%s) — "
                            "CBF_FAIL_OPEN=true, skipping CBF gate (audit gap).",
                            cbf_result,
                        )
                    else:
                        logger.error(
                            "⛔ [revalidate_post_hitl] CBF check unavailable (%s) — "
                            "fail-closed: blocking revalidation.",
                            cbf_result,
                        )
                        violations.append(
                            "CBF Fail-Closed (post-HITL revalidation): Redis unavailable "
                            "— cannot verify cash barrier. Set CBF_FAIL_OPEN=true to "
                            "override (audit gap)."
                        )
                elif isinstance(cbf_result, tuple):
                    committed, reason = cbf_result
                    cbf_committed = committed  # Track for potential rollback
                    if not committed:
                        # C1 Fix: Any CBF refusal (committed=False) is a hard violation,
                        # regardless of the reason string content.
                        violations.append(
                            f"CBF Commit Refused [post-HITL revalidation]: {reason}"
                        )
                        logger.warning(
                            "⛔ [revalidate_post_hitl] CBF refused to commit: %s",
                            reason,
                        )
            else:
                logger.info(
                    "⏭️ [revalidate_post_hitl] OPA denied — skipping CBF commit "
                    "(budget leakage prevented)"
                )
            
            _sequential_ms = round((time.perf_counter() - _t_sequential_start) * 1000, 2)
            span.set_attribute("toctou.revalidation.sequential_ms", _sequential_ms)
            span.set_attribute("toctou.revalidation.cbf_committed", cbf_committed)

            try:
                if violations:
                    thread_id = str(
                        params.get("transaction_id", "")
                        or params.get("thread_id", "")
                        or "unknown"
                    )
                    receipt = RefusalReceipt(
                        thread_id=thread_id,
                        action=tool_name,
                        violated_tier="SYMBOLIC_GOVERNOR",
                        violated_rule=violations[0],
                        standing_at_refusal=self._build_standing([]),
                    )
                    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
                    raise GovernanceError(violations[0], receipt=receipt)

                # Issue routing seal — attests that CBF+OPA re-check passed.
                # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                # which blocks on evidence commit when EVIDENCE_CHAIN_BLOCKING=true.
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = await generate_seal_with_evidence(tool_name, params)
                    seal_span.set_attribute("cage.seal_issued", True)
                    seal_span.set_attribute("cage.seal_path", "revalidate_post_hitl")

                logger.info(
                    "✅ [revalidate_post_hitl] CBF+OPA re-check APPROVED: %s "
                    "(seal issued, Tiers 3a/3b only)",
                    tool_name,
                )
                span.set_attribute(OBSERVATION_OUTPUT, "APPROVED")
                span.set_attribute("cage.seal_issued", True)
                return seal

            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute(OBSERVATION_OUTPUT, str(exc))
                raise

    async def verify(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Dry-run governance checks.  Does NOT raise exceptions.

        Used by the Evaluator Agent (System 3) for simulation.
        """
        with tracer.start_as_current_span("symbolic_governor.verify") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_simulation")
            span.set_attribute(
                OBSERVATION_INPUT,
                json.dumps({"tool": tool_name, "params": params}),
            )
            result = await self._run_checks(tool_name, params, sim_mode=True)
            violations = result["violations"]
            # tier_violations intentionally not extracted here (used elsewhere in real validation)
            span.set_attribute(
                OBSERVATION_OUTPUT,
                json.dumps(violations) if violations else "APPROVED",
            )
            return result

    async def validate_action(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate a structured tool execution payload — Unified Gateway path.

        This is the **Single Choke Point** for all tool execution.  Runs the
        complete 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) via ``_run_checks()`` — STPA,
        Confidence, CBF, OPA, Fiscal Limit Pre-Reservation, Consensus, Causal,
        and FRIA — before issuing the routing seal.

        Previously this method ran only Tiers 3a and 3b (CBF and OPA), which
        meant 5 of 7 substantive tiers were bypassed while the seal implied full
        governance approval.  That gap is now closed: the routing seal is issued
        ONLY after ``_run_checks()`` completes successfully across all tiers.

        On approval, a short-lived HMAC-SHA256 ``routing_seal`` is returned.
        The downstream actuator MUST verify this seal before firing — ensuring
        that execution cannot proceed by simply ignoring the HTTP response.

        Verdict semantics (canonical — see decisions.py):
          - ``"ALLOW"``            — approved; routing seal issued.
          - ``"DENY"``             — blocked; violation details included.
          - ``"REQUIRE_APPROVAL"`` — OPA returned MANUAL_REVIEW; human sign-off
                                     required. Routing seal NOT issued. The
                                     adapter returns HTTP 202 with this verdict
                                     so clients can distinguish it from DEFER.
          - ``"DEFER"``            — context missing or below confidence
                                     threshold; routes to DeferQueue for
                                     automated data-hydration.

        Returns:
            Dict with keys:
                - ``verdict``:     ``"ALLOW"`` | ``"DENY"`` | ``"REQUIRE_APPROVAL"`` | ``"DEFER"``
                - ``violations``:  list of violation strings (empty if ALLOW)
                - ``seal``:        HMAC routing seal (non-empty only if ALLOW)
                - ``latency_ms``:  total governance check wall-time in milliseconds

        Raises:
            GovernanceError: If any mandatory check fails with DENY verdict.
        """
        from src.gateway.governance.decisions import GovernanceDecision

        with tracer.start_as_current_span("cage.validate_action") as span:
            span.set_attribute("cage.action", action)
            span.set_attribute("cage.governance", True)
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "cage.validate_action")
            span.set_attribute(
                OBSERVATION_INPUT,
                json.dumps(
                    {
                        "action": action,
                        "params": params,
                        "policy_version_id": policy_version_id,
                    }
                )[:2000],
            )

            t0 = time.time()

            try:
                # ── Version-Pinning Enforcement Layer ────────────────────────
                if policy_version_id is not None:
                    active_hash = ControlRegistry().active_hash
                    if policy_version_id != active_hash:
                        raise GovernanceError(
                            f"Substrate Policy Drift Detected. Session pinned to version signature '{policy_version_id}', "
                            f"but active runtime baseline has evolved to hash '{active_hash}'."
                        )

                # ── Full 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) ──
                # _run_checks() executes: STPA → Confidence → CBF+OPA (parallel)
                # → Fiscal Limit Pre-Reservation → Consensus → Causal → FRIA.
                # The routing seal is issued ONLY after all tiers pass — a seal
                # issued before full pipeline completion would imply governance
                # approval that was never actually granted.
                result = await self._run_checks(action, params, sim_mode=False)
                violations = result["violations"]
                tier_violations = result.get("tier_violations", [])

                latency_ms = round((time.time() - t0) * 1000, 2)
                span.set_attribute("cage.governance_latency_ms", latency_ms)

                # ── Violation Classification (§2.1 CAGE Implementation Specs) ──
                # Use the _classify_violation() helper to properly route violations
                # to DENY, DEFER, or REQUIRE_APPROVAL instead of collapsing all
                # non-REQUIRE_APPROVAL violations into DENY.
                #
                # Classification priorities:
                #   1. REQUIRE_APPROVAL: OPA MANUAL_REVIEW, no hard violations
                #   2. DENY: Hard violations (STPA, CBF, OPA DENY)
                #   3. DEFER: Soft violations + confidence starvation
                #   4. REQUIRE_APPROVAL fallback: Soft violations above threshold
                if violations:
                    # Extract STPA violation count from result metadata
                    _stpa_count = result.get("stpa_violation_count", 0)
                    # Extract confidence from params (agent self-reported)
                    _confidence = float(params.get("confidence", 0.0))

                    # Classify the violations using ClassificationEngine (mandatory)
                    from src.gateway.governance.classification_engine import ClassificationContext
                    
                    _opa_res = result.get("opa_results")
                    _opa_decision = (
                        _opa_res.get("decision")
                        if isinstance(_opa_res, dict)
                        else (_opa_res if isinstance(_opa_res, str) else result.get("opa_decision"))
                    )

                    context = ClassificationContext(
                        violations=violations,
                        stpa_violation_count=_stpa_count,
                        confidence=_confidence,
                        opa_decision=_opa_decision,
                        policy_ambiguous=result.get("policy_ambiguous", False),
                        params=params,
                        cbf_violation=any("CBF" in str(v) for v in violations),
                    )
                    classification = self._classification_engine.classify(context, action)
                    decision = classification.decision
                    classification_meta = classification.metadata

                    # Record classification metadata in OTel span
                    span.set_attribute(
                        "cage.governance.classification_decision", decision.value
                    )
                    span.set_attribute(
                        "cage.governance.classification_reason",
                        classification_meta.get("classification_reason", "")[:200],
                    )
                    span.set_attribute(
                        "cage.governance.deferrable",
                        classification_meta.get("deferrable", False),
                    )

                    # ── REQUIRE_APPROVAL path ──────────────────────────────────
                    if decision == GovernanceDecision.REQUIRE_APPROVAL:
                        span.set_attribute(
                            "cage.verdict", GovernanceDecision.REQUIRE_APPROVAL
                        )
                        span.set_attribute(
                            OBSERVATION_OUTPUT,
                            GovernanceDecision.REQUIRE_APPROVAL,
                        )
                        span.set_status(Status(StatusCode.OK))
                        logger.info(
                            "🔶 validate_action REQUIRE_APPROVAL: action=%s reason=%s (%.1fms)",
                            action,
                            classification_meta.get("classification_reason", ""),
                            latency_ms,
                        )
                        return {
                            "verdict": GovernanceDecision.REQUIRE_APPROVAL,
                            "violations": violations,
                            "seal": "",
                            "latency_ms": latency_ms,
                            "classification_meta": classification_meta,
                        }

                    # ── DEFER path (new — §2.1 CAGE Implementation Specs) ──────
                    if decision == GovernanceDecision.DEFER:
                        # Park the deferred context in DeferQueue for later retrieval
                        # via GET /v1/defer/pending or resolution via POST /v1/defer/{id}/escalate
                        defer_metadata = {
                            "cbf_violation": any("CBF" in str(v) for v in violations),
                            "opa_decision": result.get("opa_decision"),
                            "policy_ambiguous": result.get("policy_ambiguous", False),
                            "params": params,
                            "action": action,
                        }
                        defer_token = await _park_defer_context(
                            action=action,
                            params=params,
                            metadata=defer_metadata,
                            thread_id=params.get("thread_id"),
                            confidence=_confidence,
                            classification_meta=classification_meta,
                            violations=violations,
                        )

                        span.set_attribute("cage.verdict", GovernanceDecision.DEFER)
                        span.set_attribute("cage.defer_token", defer_token)
                        span.set_attribute(
                            OBSERVATION_OUTPUT,
                            GovernanceDecision.DEFER,
                        )
                        span.set_status(Status(StatusCode.OK))
                        logger.info(
                            "🔄 validate_action DEFER: action=%s reason=%s "
                            "confidence=%.2f defer_token=%s (%.1fms)",
                            action,
                            classification_meta.get("classification_reason", ""),
                            _confidence,
                            defer_token,
                            latency_ms,
                        )
                        # Extract agent_id from _caller_principal
                        agent_id = params.get("_caller_principal", "")

                        return {
                            "verdict": GovernanceDecision.DEFER,
                            "violations": violations,
                            "seal": "",
                            "latency_ms": latency_ms,
                            "classification_meta": classification_meta,
                            "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
                            # Phase 1.2: HTTP layer wiring fields
                            "defer_token": defer_token,
                            "deferrable": classification_meta.get("deferrable", True),
                            "retry_after_seconds": 300,  # 5 minute default
                            "agent_id": agent_id,
                        }

                    # ── NARROW path (Phase 1.3 — partial-authority/clamped execution) ──
                    if decision == GovernanceDecision.NARROW:
                        from src.gateway.governance.routing_seal import (
                            generate_seal_with_evidence,
                        )

                        # Extract narrowed parameters from classification metadata
                        original_params = classification_meta.get(
                            "original_params", params
                        )
                        narrowed_params = classification_meta.get(
                            "narrowed_params", params
                        )
                        constraints_applied = classification_meta.get(
                            "constraints_applied", []
                        )
                        narrowing_reason = classification_meta.get(
                            "narrowing_reason", ""
                        )

                        # Issue routing seal for the NARROWED parameters
                        # The seal attests to the narrowed params, not the original
                        # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                        with tracer.start_as_current_span(
                            "cage.routing_seal"
                        ) as seal_span:
                            seal = await generate_seal_with_evidence(
                                action, narrowed_params
                            )
                            seal_span.set_attribute("cage.seal_issued", True)
                            seal_span.set_attribute("cage.seal_path", "narrow")

                        # OTel telemetry for NARROW decisions
                        span.set_attribute("cage.verdict", GovernanceDecision.NARROW)
                        span.set_attribute("cage.governance.narrowed", True)
                        span.set_attribute(
                            "cage.governance.constraints_applied",
                            json.dumps(constraints_applied)[:500],
                        )
                        span.set_attribute(
                            OBSERVATION_OUTPUT,
                            GovernanceDecision.NARROW,
                        )
                        span.set_status(Status(StatusCode.OK))
                        logger.info(
                            "📐 validate_action NARROW: action=%s reason=%s "
                            "constraints=%s (%.1fms)",
                            action,
                            narrowing_reason,
                            constraints_applied,
                            latency_ms,
                        )
                        # Extract agent_id from _caller_principal
                        agent_id = params.get("_caller_principal", "")

                        return {
                            "verdict": GovernanceDecision.NARROW,
                            "violations": violations,
                            "seal": seal,
                            "latency_ms": latency_ms,
                            "agent_id": agent_id,
                            "classification_meta": classification_meta,
                            # NARROW-specific fields
                            "original_params": original_params,
                            "narrowed_params": narrowed_params,
                            "narrowing_reason": narrowing_reason,
                            "constraints_applied": constraints_applied,
                            "execution_allowed": True,
                        }

                    # ── PAUSE path (Phase 1.4 — resumable suspension) ──────────
                    if decision == GovernanceDecision.PAUSE:
                        from src.gateway.governance.contracts import PauseReceipt
                        from src.gateway.governance.pause_primitive import (
                            PauseManager,
                            build_resume_endpoint,
                        )
                        from src.gateway.infrastructure.redis_client import redis_client

                        # Extract pause metadata from classification result
                        pause_reason: str = classification_meta.get(
                            "pause_reason", "RATE_LIMITED"
                        )
                        estimated_wait: int = classification_meta.get(
                            "estimated_wait_seconds", 60
                        )
                        _va_pause_thread_id = str(
                            params.get("transaction_id", "")
                            or params.get("thread_id", "")
                            or "unknown"
                        )

                        # Defense-in-depth: verify PAUSE is enabled at validate_action boundary
                        # (This check is redundant with _classify_violation but provides a
                        # safety net if the flag is toggled between classification and here)
                        if not is_cage_pause_enabled():
                            span.set_attribute("cage.verdict", GovernanceDecision.DENY)
                            span.set_attribute("cage.pause_fallback", True)
                            span.set_status(Status(StatusCode.ERROR))
                            logger.warning(
                                "🚫 validate_action PAUSE->DENY fallback: action=%s "
                                "reason=%s (CAGE_PAUSE_ENABLED=false)",
                                action,
                                pause_reason,
                            )
                            receipt = RefusalReceipt(
                                thread_id=_va_pause_thread_id,
                                action=action,
                                violated_tier="PAUSE_FALLBACK",
                                violated_rule=f"Transient condition: {pause_reason}",
                                standing_at_refusal=self._build_standing(
                                    tier_violations
                                ),
                            )
                            span.set_attribute(
                                "cage.refusal_proof_hash", receipt.proof_hash
                            )
                            raise GovernanceError(
                                f"Transient condition ({pause_reason}) detected; "
                                "CAGE_PAUSE_ENABLED=false — request denied",
                                receipt=receipt,
                            )

                        # Store the pause state in Redis via PauseManager
                        pause_token = ""
                        expires_at_utc = ""
                        try:
                            pause_manager = PauseManager(redis_client)
                            request_id = params.get(
                                "request_id",
                                params.get(
                                    "thread_id", f"{action}_{_va_pause_thread_id}"
                                ),
                            )
                            pause_token = await pause_manager.pause_request(
                                request_id=request_id,
                                reason=pause_reason,
                                ttl_seconds=3600,  # 1 hour default
                                original_request=params,
                                thread_id=_va_pause_thread_id,
                                estimated_wait_secs=estimated_wait,
                            )
                            # Fetch the state to get expires_at
                            pause_state = await pause_manager.get_pause_state(
                                pause_token
                            )
                            if pause_state:
                                expires_at_utc = pause_state.expires_at_utc
                        except Exception as pause_exc:
                            # Fail-closed: if Redis is unavailable, fall back to DENY
                            logger.error(
                                "🚫 validate_action PAUSE->DENY (Redis unavailable): "
                                "action=%s reason=%s error=%s",
                                action,
                                pause_reason,
                                pause_exc,
                            )
                            span.set_attribute("cage.verdict", GovernanceDecision.DENY)
                            span.set_attribute("cage.pause_redis_error", True)
                            span.set_status(Status(StatusCode.ERROR))
                            receipt = RefusalReceipt(
                                thread_id=_va_pause_thread_id,
                                action=action,
                                violated_tier="PAUSE_REDIS_ERROR",
                                violated_rule=f"Transient condition: {pause_reason}",
                                standing_at_refusal=self._build_standing(
                                    tier_violations
                                ),
                            )
                            span.set_attribute(
                                "cage.refusal_proof_hash", receipt.proof_hash
                            )
                            raise GovernanceError(
                                f"Transient condition ({pause_reason}) detected; "
                                "PAUSE storage failed — request denied",
                                receipt=receipt,
                            )

                        # Create PauseReceipt for audit trail
                        pause_receipt = PauseReceipt(
                            thread_id=_va_pause_thread_id,
                            action=action,
                            pause_reason=pause_reason,
                            pause_token=pause_token,
                            violations=violations,
                            standing_at_pause={
                                "symbol": params.get("symbol"),
                                "amount": params.get("amount"),
                                "confidence": params.get("confidence"),
                            },
                            estimated_wait_seconds=estimated_wait,
                            expires_at_utc=expires_at_utc,
                        )

                        # OTel telemetry
                        span.set_attribute("cage.verdict", GovernanceDecision.PAUSE)
                        span.set_attribute("cage.pause_token", pause_token)
                        span.set_attribute("cage.pause_reason", pause_reason)
                        span.set_attribute("cage.pause_estimated_wait", estimated_wait)
                        span.set_attribute(
                            "cage.pause_receipt_hash", pause_receipt.proof_hash
                        )
                        span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.PAUSE)
                        span.set_status(Status(StatusCode.OK))

                        logger.info(
                            "⏸️ validate_action PAUSE: action=%s reason=%s "
                            "pause_token=%s estimated_wait=%ds (%.1fms)",
                            action,
                            pause_reason,
                            pause_token,
                            estimated_wait,
                            latency_ms,
                        )

                        # Extract agent_id from _caller_principal
                        agent_id = params.get("_caller_principal", "")

                        return {
                            "verdict": GovernanceDecision.PAUSE,
                            "violations": violations,
                            "seal": "",  # No seal for PAUSE — action is neither approved nor denied
                            "latency_ms": latency_ms,
                            "classification_meta": classification_meta,
                            # PAUSE-specific fields (Phase 1.4)
                            "pause_token": pause_token,
                            "pause_reason": pause_reason,
                            "resume_endpoint": build_resume_endpoint(pause_token),
                            "expires_at_utc": expires_at_utc,
                            "estimated_wait_seconds": estimated_wait,
                            "retry_after_seconds": estimated_wait,
                            # Audit receipt
                            "pause_receipt": pause_receipt,
                            "agent_id": agent_id,
                        }

                    # ── DENY path (default for hard violations) ────────────────
                    # This is the fallback for all other decisions (including
                    # explicitly classified DENY). Preserves existing behavior.
                    span.set_attribute("cage.verdict", GovernanceDecision.DENY)
                    span.set_attribute(OBSERVATION_OUTPUT, json.dumps(violations))
                    span.set_status(Status(StatusCode.ERROR))
                    logger.warning(
                        "🚫 validate_action DENIED: action=%s violations=%s reason=%s",
                        action,
                        violations,
                        classification_meta.get("classification_reason", ""),
                    )
                    _va_thread_id = str(
                        params.get("transaction_id", "")
                        or params.get("thread_id", "")
                        or "unknown"
                    )
                    _va_tier_failures = result.get("tier_failures", [])
                    _va_first_tf = _va_tier_failures[0] if _va_tier_failures else None
                    receipt = RefusalReceipt(
                        thread_id=_va_thread_id,
                        action=action,
                        violated_tier=_va_first_tf.tier
                        if _va_first_tf
                        else "SYMBOLIC_GOVERNOR",
                        violated_rule=violations[0],
                        standing_at_refusal=self._build_standing(tier_violations),
                        # ── 5-part proof chain (Terry Snyder) ──
                        schema_version="v2",
                        attempted_params={
                            k: v
                            for k, v in params.items()
                            if k not in ("thread_id", "transaction_id")
                        },
                        standing_snapshot=_va_first_tf.governing_state
                        if _va_first_tf
                        else {},
                        control_id=_va_first_tf.control_id if _va_first_tf else "",
                        protected_consequence=_va_first_tf.protected_consequence
                        if _va_first_tf
                        else "",
                        non_formation_proof="action_blocked_pre_commit",
                        tier_failures=tuple(_va_tier_failures),
                    )
                    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
                    raise GovernanceError(violations[0], receipt=receipt)

                # ── Issue routing seal AFTER full pipeline approval ───────────
                # The seal is generated here — after _run_checks() has completed
                # all 7 tiers — so that it cryptographically attests to complete
                # governance approval, not just a partial CBF+OPA check.
                #
                # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                # which blocks on evidence commit when EVIDENCE_CHAIN_BLOCKING=true.
                from src.gateway.governance.routing_seal import (
                    generate_seal_with_evidence,
                )

                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = await generate_seal_with_evidence(action, params)
                    seal_span.set_attribute("cage.seal_issued", True)

                span.set_attribute("cage.verdict", GovernanceDecision.ALLOW)
                span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.ALLOW)
                span.set_status(Status(StatusCode.OK))
                logger.info(
                    "✅ validate_action ALLOW: action=%s (%.1fms)",
                    action,
                    latency_ms,
                )

                # Extract agent_id from _caller_principal (injected by agent_gateway_adapter)
                agent_id = params.get("_caller_principal", "")

                return {
                    "verdict": GovernanceDecision.ALLOW,
                    "violations": [],
                    "seal": seal,
                    "latency_ms": latency_ms,
                    "agent_id": agent_id,
                }
            except GovernanceError:
                raise
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                raise


def assert_safe_operational_state() -> None:
    """Raise RuntimeError if the system is in a combined high-risk operational state.

    Specifically, raises if BOTH of the following are true simultaneously:
      - CBF_FAIL_OPEN=true (CBF gate is bypassed)
      - KMSGovernanceSigner is in HMAC fallback mode (no non-repudiation)

    Either condition alone is a compliance gap. Together they mean:
      - No independent cash balance verification (CBF bypassed)
      - No externally verifiable governance attestation (HMAC fallback)
    This combined state is the highest-risk operational posture and must
    never occur in production.

    Also warns (CRITICAL log) or raises (production) when
    RECONCILIATION_PROVIDER=stub, which means the CBF is evaluating against
    self-reported balances — POAM-023 open gap.

    Call this during application startup.
    """
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

    cbf_fail_open = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"
    if not cbf_fail_open:
        return  # CBF is active — combined risk state is not present

    # CBF is bypassed — check if KMS is also in fallback mode
    try:
        from src.gateway.governance.kms_signer import get_governance_signer

        signer = get_governance_signer()
        kms_active = signer.is_kms_active
    except Exception:
        kms_active = False  # Cannot determine — assume worst case

    if not kms_active:
        msg = (
            "CAGE STARTUP FAILURE: Combined high-risk operational state detected. "
            "CBF_FAIL_OPEN=true (CBF gate bypassed) AND KMSGovernanceSigner is in "
            "HMAC fallback mode (no non-repudiation). "
            "This means: (1) cash balance cannot be independently verified, "
            "(2) governance attestations cannot be externally verified. "
            "Resolve by: setting KMS_GOVERNANCE_KEY and/or setting CBF_FAIL_OPEN=false."
        )
        if _is_production:
            raise RuntimeError(msg)
        else:
            logger.critical(
                json.dumps(
                    {
                        "event": "COMBINED_HIGH_RISK_STATE",
                        "severity": "CRITICAL",
                        "cbf_fail_open": True,
                        "kms_active": False,
                        "environment": env,
                        "audit_note": msg,
                    }
                )
            )


# ---------------------------------------------------------------------------
# DeferQueue integration for DEFER path
# ---------------------------------------------------------------------------


async def _park_defer_context(
    action: str,
    params: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    thread_id: str | None,
    confidence: float,
    classification_meta: dict[str, Any],
    violations: list[str],
) -> str:
    """Park deferred action context in DeferQueue db=1 and return the defer_id.

    Connects to Redis db=1 via REDIS_URL (matching the deployment contract
    documented in defer_queue.py — the DEFER token store is isolated from the
    LangGraph checkpointer at db=0) and parks the token through the existing
    DeferQueue infrastructure. Falls back to a local, unpersisted UUID token
    if Redis is unavailable — the DEFER verdict is still returned, but external
    HITL API resolution (GET /v1/defer/pending, POST /v1/defer/{id}/escalate)
    will not find this token in that fallback case, since it was never written
    to Redis.

    Args:
        action:              The action type being deferred.
        params:              The action parameters (sanitized).
        metadata:            Request metadata including thread_id.
        thread_id:           LangGraph thread ID for audit trail correlation.
        confidence:          Model confidence score [0, 1] at decision time.
        classification_meta: Classification metadata from _classify_violation().
        violations:          List of violation strings from OPA/STPA.

    Returns:
        The defer_id (UUID string) — either from DeferQueue.park() or a local
        fallback UUID if Redis is unavailable.
    """
    import uuid

    from src.gateway.governance.defer_queue import DeferQueue, DeferReason, DeferToken

    # Generate a stable thread_id if not provided
    effective_thread_id = thread_id or str(uuid.uuid4())

    # Build the OPA input snapshot for later replay/escalation
    opa_input_snapshot = {
        "action": action,
        "params": params or {},
        "metadata": metadata or {},
        "violations": violations,
        "classification_reason": classification_meta.get("classification_reason", ""),
    }

    # Map classification reason to DeferReason enum
    reason_str = classification_meta.get("classification_reason", "")
    if "confidence" in reason_str.lower():
        defer_reason = DeferReason.CONFIDENCE_BELOW_THRESHOLD
    elif "context" in reason_str.lower() or "missing" in reason_str.lower():
        defer_reason = DeferReason.INSUFFICIENT_CONTEXT
    elif "ambiguous" in reason_str.lower():
        defer_reason = DeferReason.AMBIGUOUS_SEMANTIC_DISTANCE
    elif "data" in reason_str.lower() and "starvation" in reason_str.lower():
        defer_reason = DeferReason.DATA_STARVATION
    else:
        defer_reason = DeferReason.CONFIDENCE_BELOW_THRESHOLD

    token = DeferToken(
        thread_id=effective_thread_id,
        defer_reason=defer_reason,
        opa_input_snapshot=opa_input_snapshot,
        confidence_score=confidence,
        aarm_vector="AARM-V7",  # Context Window Overflow / Data Starvation
    )

    async def _park() -> str:
        import redis.asyncio as aioredis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        try:
            queue = DeferQueue(client)
            return await queue.park(token)
        finally:
            await client.aclose()

    try:
        return await _park()
    except Exception as exc:
        # Redis unavailable — fall back to local UUID
        # The DEFER verdict still holds, but the token is NOT persisted
        # and cannot be retrieved via GET /v1/defer/pending
        logger.warning(
            "DeferQueue park failed (%s) — using local defer_id only "
            "(token NOT persisted to Redis; HITL API will not find it). "
            "action=%s thread_id=%s",
            exc,
            action,
            effective_thread_id,
        )
        return token.defer_id
