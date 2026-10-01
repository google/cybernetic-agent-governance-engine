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
IrreversibilityClassifier — loads the active domain's FTRA terminal registry
and classifies action names against it.

Fail-closed contract
--------------------
Any action name absent from the registry is classified as IRREVERSIBLE_TERMINAL.
This mirrors the OPA ``default stpa_allow = false`` pattern: unknown actions
are treated as maximally dangerous until explicitly classified otherwise.

Every classification carries its provenance (:class:`RegistryState`), so the
boundary stage can tell "the registry says irreversible" (HITL) from "the
registry is silent" (HITL, different code) from "the registry is unreadable"
(HARD — no human can approve against an authority that failed to load).

Autonomous envelope
-------------------
A registry may grant a terminal action an ``autonomous_envelope``
(``{"execute_trade": {"max_magnitude": 10000.0}}``) under which it clears FTRA
without a human (see :mod:`src.gateway.governance.ftra.autonomy`). The envelope
is authority, so a registry that declares one must carry a ``manifest_sha256``
and the digest covers the envelope as well as the terminals.

Caching strategy
----------------
The registry is loaded once and cached (module-level singleton).
A SIGUSR1 handler (or FTRA_REGISTRY_RELOAD=true env flag) triggers a cache
bust without pod restart — matching the ControlRegistry pattern in constants.py.

Usage::

    classifier = IrreversibilityClassifier()
    classification = classifier.classify("execute_action")
    # → TerminalClassification.IRREVERSIBLE_TERMINAL

    provenance = classifier.classify_with_provenance("execute_action")
    # → ClassificationProvenance(classification=..., registry_state=..., envelope=...)

Rehash a registry after editing it::

    python -m src.gateway.governance.ftra.classifier --rehash config/ftra/terminal_registry.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import signal
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from src.gateway.governance.ftra.autonomy import (
    ENVELOPE_CLASSIFICATIONS,
    AutonomousEnvelope,
)
from src.gateway.governance.ftra.models import RegistryState, TerminalClassification
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("Gateway.Governance.FTRA.Classifier")

_ENVELOPE_KEY = "autonomous_envelope"
_ENVELOPE_FIELDS = frozenset({"max_magnitude"})

# ---------------------------------------------------------------------------
# Registry path: supplied by the active domain's DomainConfig (CAGE_DOMAIN).
# ---------------------------------------------------------------------------


def _active_registry_path() -> Path:
    from src.gateway.governance.plugin_loader import active_domain_config

    return active_domain_config().ftra_registry_path


# ---------------------------------------------------------------------------
# Registry document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TerminalRegistry:
    """A loaded, digest-verified terminal registry."""

    terminals: Mapping[str, str]
    """Action name → classification string (validated lazily, per action)."""

    autonomous_envelope: Mapping[str, AutonomousEnvelope] = field(
        default_factory=lambda: MappingProxyType({})
    )
    """Registered terminal → the ceiling under which it clears FTRA autonomously."""


@dataclass(frozen=True)
class ClassificationProvenance:
    """A classification, where it came from, and any autonomous envelope."""

    classification: TerminalClassification
    registry_state: RegistryState
    envelope: AutonomousEnvelope | None = None


def registry_digest(raw: Mapping[str, Any]) -> str:
    """SHA-256 of the JCS-canonical authority block of a registry document.

    The authority block is the ``terminals`` dict alone when the document has
    no ``autonomous_envelope`` (unchanged from Issue #107, so existing digests
    stay valid), and ``{"autonomous_envelope": ..., "terminals": ...}`` when it
    does — so a tampered ceiling fails the same check a tampered terminal does.
    ``manifest_sha256`` itself is never part of its own hash.
    """
    terminals = raw.get("terminals")
    if _ENVELOPE_KEY in raw:
        block: dict[str, Any] = {
            _ENVELOPE_KEY: raw[_ENVELOPE_KEY],
            "terminals": terminals,
        }
    else:
        block = terminals  # type: ignore[assignment]
    return hashlib.sha256(jcs_canonicalize_plan(block)).hexdigest()


def _parse_envelope(
    raw_envelope: Any, terminals: Mapping[str, str], path: Path
) -> dict[str, AutonomousEnvelope]:
    """Validate the ``autonomous_envelope`` block; raise ValueError on anything off."""
    if not isinstance(raw_envelope, dict):
        raise ValueError(f"FTRA registry at {path}: '{_ENVELOPE_KEY}' must be an object.")
    envelopes: dict[str, AutonomousEnvelope] = {}
    for action, spec in raw_envelope.items():
        raw_class = terminals.get(action)
        if raw_class is None:
            raise ValueError(
                f"FTRA registry at {path}: envelope for {action!r}, which is not "
                "in 'terminals' — an envelope can only widen a registered terminal."
            )
        try:
            classification = TerminalClassification(raw_class)
        except ValueError:
            raise ValueError(
                f"FTRA registry at {path}: envelope for {action!r}, whose "
                f"classification {raw_class!r} is not recognised."
            ) from None
        if classification not in ENVELOPE_CLASSIFICATIONS:
            raise ValueError(
                f"FTRA registry at {path}: envelope for {action!r} ({classification.value}); "
                "only terminal classifications take an envelope."
            )
        if not isinstance(spec, dict) or set(spec) != _ENVELOPE_FIELDS:
            raise ValueError(
                f"FTRA registry at {path}: envelope for {action!r} must be exactly "
                f"{{'max_magnitude': <number>}}, got {spec!r}."
            )
        envelopes[action] = AutonomousEnvelope(max_magnitude=spec["max_magnitude"])
    return envelopes


def _load_registry_document(path: Path) -> TerminalRegistry:
    """Load, digest-verify and parse a terminal registry document.

    Raises:
        FileNotFoundError: If the registry file does not exist.
        ValueError: If the JSON is malformed, missing ``terminals``, fails its
            manifest digest, or declares an envelope that is unsigned or invalid.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"FTRA terminal registry not found: {path}. "
            "Run: python -m src.gateway.governance.stpa_compiler compile --targets ftra"
        )
    with open(path) as fh:
        raw: dict[str, Any] = json.load(fh)
    terminals = raw.get("terminals")
    if not isinstance(terminals, dict):
        raise ValueError(
            f"FTRA terminal registry at {path} is missing the 'terminals' key "
            "or it is not a dict."
        )

    # Manifest integrity check (Issue #107 — Mayur Agnihotri). Detects
    # staleness or tampering of the authority block (see registry_digest).
    expected_digest = raw.get("manifest_sha256")
    if expected_digest:
        actual_digest = registry_digest(raw)
        if actual_digest != expected_digest:
            raise ValueError(
                f"FTRA terminal registry integrity check FAILED at {path}. "
                f"Expected SHA-256: {expected_digest!r} "
                f"Actual SHA-256:   {actual_digest!r} "
                "The registry authority block may be stale or tampered. "
                "Regenerate manifest_sha256 with: "
                "python -m src.gateway.governance.ftra.classifier --rehash <path>"
            )
        logger.info(
            "✅ FTRA registry manifest digest verified: %s...",
            actual_digest[:16],
        )
    elif _ENVELOPE_KEY in raw:
        raise ValueError(
            f"FTRA terminal registry at {path} declares an '{_ENVELOPE_KEY}' but "
            "has no manifest_sha256 — an unsigned envelope is not authority. "
            "Run: python -m src.gateway.governance.ftra.classifier --rehash <path>"
        )
    else:
        logger.warning(
            "FTRA terminal registry at %s has no manifest_sha256 field — "
            "staleness detection is disabled (Issue #107 — Mayur Agnihotri).",
            path,
        )

    envelopes = (
        _parse_envelope(raw[_ENVELOPE_KEY], terminals, path)
        if _ENVELOPE_KEY in raw
        else {}
    )

    logger.info(
        "✅ FTRA terminal registry loaded: %d actions (%d with an autonomous "
        "envelope) from %s",
        len(terminals),
        len(envelopes),
        path,
    )
    return TerminalRegistry(
        terminals=MappingProxyType(dict(terminals)),
        autonomous_envelope=MappingProxyType(envelopes),
    )


def _load_registry(path: Path) -> dict[str, str]:
    """Load a registry and return its ``terminals`` dict (action → classification).

    Raises:
        FileNotFoundError: If the registry file does not exist.
        ValueError: See :func:`_load_registry_document`.
    """
    return dict(_load_registry_document(path).terminals)


# ---------------------------------------------------------------------------
# Module-level cache
# ---------------------------------------------------------------------------

_registry_lock = threading.RLock()
_registry_cache: TerminalRegistry | None = None
_registry_path_used: Path | None = None


def _get_registry_document(path: Path | None = None) -> TerminalRegistry:
    """Return the cached registry document, loading it on first call.

    Thread-safe via ``_registry_lock``.  Respects ``FTRA_REGISTRY_RELOAD=true``
    env flag to force a cache bust on each call (useful for hot-reload in dev).
    """
    global _registry_cache, _registry_path_used

    effective_path = path or _active_registry_path()
    force_reload = os.getenv("FTRA_REGISTRY_RELOAD", "false").lower() == "true"

    with _registry_lock:
        if (
            _registry_cache is None
            or force_reload
            or _registry_path_used != effective_path
        ):
            _registry_cache = _load_registry_document(effective_path)
            _registry_path_used = effective_path
        return _registry_cache


def _get_registry(path: Path | None = None) -> dict[str, str]:
    """Return the cached registry's ``terminals`` dict."""
    return dict(_get_registry_document(path).terminals)


def _bust_cache(_signum: int, _frame: Any) -> None:
    """SIGUSR1 handler — clears the registry cache for hot-reload."""
    global _registry_cache
    with _registry_lock:
        _registry_cache = None
    logger.info(
        "FTRA registry cache cleared via SIGUSR1 — will reload on next classify()."
    )


# Register SIGUSR1 handler for hot-reload (no-op on Windows or non-main threads).
try:
    signal.signal(signal.SIGUSR1, _bust_cache)
except (OSError, AttributeError, ValueError):
    pass  # Windows, worker threads, or restricted environment — hot-reload via env flag only


# ---------------------------------------------------------------------------
# Staleness gate (Issue #107 — Mayur Agnihotri follow-up)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StalenessReport:
    """Result of a registry staleness check.

    Attributes:
        unclassified: Actions present in ``live_actions`` but absent from the
            registry.  These will silently receive IRREVERSIBLE_TERMINAL at
            runtime via the fail-closed contract.  May indicate that the
            registry was not regenerated after a new action was added to the
            domain plugin.
        phantom: Actions present in the registry but absent from
            ``live_actions``.  The registry describes actions that no longer
            exist in the domain plugin — these entries are dead and create
            false confidence in coverage.
        is_clean: True only when both sets are empty.
    """

    unclassified: frozenset[str] = field(default_factory=frozenset)
    phantom: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_clean(self) -> bool:
        return not self.unclassified and not self.phantom


def check_registry_staleness(
    live_actions: frozenset[str],
    registry_path: Path | None = None,
) -> StalenessReport:
    """Compare a domain plugin's live action surface against the terminal registry.

    This is the *staleness* half of Issue #107.  The manifest digest (also in
    this module) proves nobody edited the registry file; this function proves
    the registry still describes the system.

    Completely domain-agnostic: the caller supplies ``live_actions`` (the
    frozenset of action names the domain plugin actually presents to the FTRA
    classifier).  This module never imports domain code.

    Args:
        live_actions: The canonical set of action names declared by a domain
            plugin (e.g. ``PluginContribution.registered_actions``).
        registry_path: Optional override for the registry JSON path.
            Defaults to the active domain's ``DomainConfig.ftra_registry_path``.

    Returns:
        :class:`StalenessReport` with two symmetric difference sets.

    Raises:
        FileNotFoundError: If the registry file does not exist.
        ValueError: If the registry JSON is malformed.
    """
    registry = _get_registry(registry_path)
    registry_actions = frozenset(registry.keys())

    unclassified = live_actions - registry_actions
    phantom = registry_actions - live_actions

    if unclassified:
        logger.warning(
            "FTRA staleness check: %d action(s) in live domain surface but ABSENT "
            "from registry — will default to IRREVERSIBLE_TERMINAL at runtime: %s",
            len(unclassified),
            sorted(unclassified),
        )
    if phantom:
        logger.warning(
            "FTRA staleness check: %d action(s) in registry but ABSENT from live "
            "domain surface — registry has phantom entries: %s",
            len(phantom),
            sorted(phantom),
        )
    if not unclassified and not phantom:
        logger.info(
            "✅ FTRA staleness check passed: registry covers live action surface."
        )

    return StalenessReport(unclassified=unclassified, phantom=phantom)


# ---------------------------------------------------------------------------
# IrreversibilityClassifier
# ---------------------------------------------------------------------------


class IrreversibilityClassifier:
    """Classifies action names against the compiled FTRA terminal registry.

    Fail-closed: any action not in the registry returns IRREVERSIBLE_TERMINAL.

    Args:
        registry_path: Optional override for the registry JSON path.
                       Defaults to the active domain's ``DomainConfig.ftra_registry_path``.
    """

    def __init__(self, registry_path: Path | None = None) -> None:
        self._registry_path = registry_path

    def _registry(self) -> TerminalRegistry:
        """Return the (possibly cached) terminal registry document."""
        return _get_registry_document(self._registry_path)

    def classify_with_provenance(self, action_name: str) -> ClassificationProvenance:
        """Classify *action_name* and say where the answer came from.

        Classification, provenance and envelope are read from one registry
        snapshot, so a hot-reload between them cannot mix two registries.
        Every non-REGISTERED state classifies as IRREVERSIBLE_TERMINAL with no
        envelope (fail-closed).
        """
        try:
            registry = self._registry()
        except Exception as exc:
            logger.error(
                "FTRA classifier: registry load failed (%s) — failing closed "
                "(treating '%s' as IRREVERSIBLE_TERMINAL, registry UNAVAILABLE).",
                exc,
                action_name,
            )
            return ClassificationProvenance(
                TerminalClassification.IRREVERSIBLE_TERMINAL, RegistryState.UNAVAILABLE
            )

        raw = registry.terminals.get(action_name)
        if raw is None:
            logger.warning(
                "FTRA classifier: action '%s' not in registry — "
                "failing closed (IRREVERSIBLE_TERMINAL).",
                action_name,
            )
            return ClassificationProvenance(
                TerminalClassification.IRREVERSIBLE_TERMINAL, RegistryState.UNREGISTERED
            )

        try:
            classification = TerminalClassification(raw)
        except ValueError:
            logger.error(
                "FTRA classifier: unknown classification value '%s' for action '%s' "
                "— failing closed (IRREVERSIBLE_TERMINAL).",
                raw,
                action_name,
            )
            return ClassificationProvenance(
                TerminalClassification.IRREVERSIBLE_TERMINAL, RegistryState.INVALID_ENTRY
            )

        return ClassificationProvenance(
            classification,
            RegistryState.REGISTERED,
            registry.autonomous_envelope.get(action_name),
        )

    def classify(self, action_name: str) -> TerminalClassification:
        """Return the TerminalClassification for *action_name*.

        Fail-closed: returns IRREVERSIBLE_TERMINAL for any action not present
        in the registry (or when the registry cannot be loaded).
        """
        return self.classify_with_provenance(action_name).classification

    def autonomous_envelope(self, action_name: str) -> AutonomousEnvelope | None:
        """The envelope granted to a registered *action_name*, else ``None``."""
        return self.classify_with_provenance(action_name).envelope

    def is_irreversible(self, action_name: str) -> bool:
        """Return True if *action_name* is classified as IRREVERSIBLE_TERMINAL.

        Convenience wrapper around :meth:`classify`.
        """
        return (
            self.classify(action_name) == TerminalClassification.IRREVERSIBLE_TERMINAL
        )

    def known_actions(self) -> list[str]:
        """Return the list of action names present in the registry.

        Useful for diagnostics and test assertions.
        """
        try:
            return list(self._registry().terminals.keys())
        except Exception:
            return []


# ---------------------------------------------------------------------------
# CLI: --rehash
# ---------------------------------------------------------------------------


def rehash_registry(path: Path) -> str:
    """Recompute and write ``manifest_sha256`` for the registry at *path*.

    The rewritten document is validated by loading it back, so a rehash can
    never sign an envelope the loader would reject.
    """
    raw: dict[str, Any] = json.loads(path.read_text())
    raw["manifest_sha256"] = registry_digest(raw)
    path.write_text(json.dumps(raw, indent=2) + "\n")
    _load_registry_document(path)
    return raw["manifest_sha256"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.gateway.governance.ftra.classifier",
        description="FTRA terminal registry maintenance.",
    )
    parser.add_argument(
        "--rehash",
        type=Path,
        metavar="PATH",
        required=True,
        help="Recompute and write manifest_sha256 for the registry at PATH.",
    )
    args = parser.parse_args(argv)
    digest = rehash_registry(args.rehash)
    print(f"{args.rehash}: manifest_sha256 = {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
