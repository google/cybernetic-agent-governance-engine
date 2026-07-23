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
IrreversibilityClassifier — loads config/ftra/terminal_registry.json and
classifies action names against the compiled terminal registry.

Fail-closed contract
--------------------
Any action name absent from the registry is classified as IRREVERSIBLE_TERMINAL.
This mirrors the OPA ``default stpa_allow = false`` pattern: unknown actions
are treated as maximally dangerous until explicitly classified otherwise.

Caching strategy
----------------
The registry is loaded once at module import time (module-level singleton).
A SIGUSR1 handler (or FTRA_REGISTRY_RELOAD=true env flag) triggers a cache
bust without pod restart — matching the ControlRegistry pattern in constants.py.

Usage::

    classifier = IrreversibilityClassifier()
    classification = classifier.classify("execute_trade")
    # → TerminalClassification.IRREVERSIBLE_TERMINAL

    is_bad = classifier.is_irreversible("execute_trade")
    # → True

    is_bad = classifier.is_irreversible("check_balance")
    # → False (READ_ONLY)
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
from pathlib import Path
from typing import Any

from src.gateway.governance.ftra.models import TerminalClassification

logger = logging.getLogger("Gateway.Governance.FTRA.Classifier")

# ---------------------------------------------------------------------------
# Registry path
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_REGISTRY_PATH = _REPO_ROOT / "config" / "ftra" / "terminal_registry.json"

# ---------------------------------------------------------------------------
# Module-level cache (loaded once at import time)
# ---------------------------------------------------------------------------

_registry_lock = threading.RLock()
_registry_cache: dict[str, str] | None = None
_registry_path_used: Path | None = None


def _load_registry(path: Path) -> dict[str, str]:
    """Load and parse the terminal registry JSON.

    Returns the ``terminals`` dict mapping action name → classification string.

    Raises:
        FileNotFoundError: If the registry file does not exist.
        ValueError: If the JSON is malformed or missing the ``terminals`` key.
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
    logger.info(
        "✅ FTRA terminal registry loaded: %d actions from %s",
        len(terminals),
        path,
    )
    return terminals


def _get_registry(path: Path | None = None) -> dict[str, str]:
    """Return the cached registry, loading it on first call.

    Thread-safe via ``_registry_lock``.  Respects ``FTRA_REGISTRY_RELOAD=true``
    env flag to force a cache bust on each call (useful for hot-reload in dev).
    """
    global _registry_cache, _registry_path_used

    effective_path = path or _DEFAULT_REGISTRY_PATH
    force_reload = os.getenv("FTRA_REGISTRY_RELOAD", "false").lower() == "true"

    with _registry_lock:
        if _registry_cache is None or force_reload or _registry_path_used != effective_path:
            _registry_cache = _load_registry(effective_path)
            _registry_path_used = effective_path

    return _registry_cache


def _bust_cache(signum: int, frame: Any) -> None:  # noqa: ARG001
    """SIGUSR1 handler — clears the registry cache for hot-reload."""
    global _registry_cache
    with _registry_lock:
        _registry_cache = None
    logger.info("FTRA registry cache cleared via SIGUSR1 — will reload on next classify().")


# Register SIGUSR1 handler for hot-reload (no-op on Windows where SIGUSR1 is absent).
try:
    signal.signal(signal.SIGUSR1, _bust_cache)
except (OSError, AttributeError):
    pass  # Windows or restricted environment — hot-reload via env flag only


# ---------------------------------------------------------------------------
# IrreversibilityClassifier
# ---------------------------------------------------------------------------


class IrreversibilityClassifier:
    """Classifies action names against the compiled FTRA terminal registry.

    Fail-closed: any action not in the registry returns IRREVERSIBLE_TERMINAL.

    Args:
        registry_path: Optional override for the registry JSON path.
                       Defaults to ``config/ftra/terminal_registry.json``.
    """

    def __init__(self, registry_path: Path | None = None) -> None:
        self._registry_path = registry_path

    def _registry(self) -> dict[str, str]:
        """Return the (possibly cached) terminal registry dict."""
        return _get_registry(self._registry_path)

    def classify(self, action_name: str) -> TerminalClassification:
        """Return the TerminalClassification for *action_name*.

        Fail-closed: returns IRREVERSIBLE_TERMINAL for any action not present
        in the registry.

        Args:
            action_name: The action name to classify (e.g. ``"execute_trade"``).

        Returns:
            TerminalClassification enum member.
        """
        try:
            registry = self._registry()
        except Exception as exc:
            logger.error(
                "FTRA classifier: registry load failed (%s) — failing closed "
                "(treating '%s' as IRREVERSIBLE_TERMINAL).",
                exc,
                action_name,
            )
            return TerminalClassification.IRREVERSIBLE_TERMINAL

        raw = registry.get(action_name)
        if raw is None:
            logger.warning(
                "FTRA classifier: action '%s' not in registry — "
                "failing closed (IRREVERSIBLE_TERMINAL).",
                action_name,
            )
            return TerminalClassification.IRREVERSIBLE_TERMINAL

        try:
            return TerminalClassification(raw)
        except ValueError:
            logger.error(
                "FTRA classifier: unknown classification value '%s' for action '%s' "
                "— failing closed (IRREVERSIBLE_TERMINAL).",
                raw,
                action_name,
            )
            return TerminalClassification.IRREVERSIBLE_TERMINAL

    def is_irreversible(self, action_name: str) -> bool:
        """Return True if *action_name* is classified as IRREVERSIBLE_TERMINAL.

        Convenience wrapper around :meth:`classify`.
        """
        return self.classify(action_name) == TerminalClassification.IRREVERSIBLE_TERMINAL

    def known_actions(self) -> list[str]:
        """Return the list of action names present in the registry.

        Useful for diagnostics and test assertions.
        """
        try:
            return list(self._registry().keys())
        except Exception:
            return []
