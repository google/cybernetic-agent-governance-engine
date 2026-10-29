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

"""Opt-in switches for optional governance components.

The deterministic core runs with no switch set. Each optional component stays
off until its switch turns it on:

- ``CAGE_NEMO_ENABLED``: NeMo Colang semantic rails (:func:`nemo_rails_enabled`).
- ``CAGE_CONSENSUS_CRITICS_ENABLED``: multi-model consensus critics
  (:func:`consensus_critics_enabled`).
- ``CAGE_CAUSAL_TIER_ENABLED``: the finance causal tier. ``src.cage_finance``
  owns that name and reads it through :func:`opt_in_enabled`.

All switches accept the same values, since every one of them controls a
safety component. ``true`` or ``1`` turns the component on. ``false``, ``0``,
empty or unset leaves it off. Case and surrounding whitespace are ignored. Any
other value raises :class:`ConfigurationError`, including ``yes``, ``no``,
``on`` and ``off``: an ambiguous value fails startup instead of enabling or
disabling anything.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Final

from src.gateway.governance.telemetry_provider import ConfigurationError

CAGE_NEMO_ENABLED_ENV: Final[str] = "CAGE_NEMO_ENABLED"
CAGE_CONSENSUS_CRITICS_ENABLED_ENV: Final[str] = "CAGE_CONSENSUS_CRITICS_ENABLED"

_ON: Final[frozenset[str]] = frozenset({"true", "1"})
_OFF: Final[frozenset[str]] = frozenset({"false", "0", ""})


def opt_in_enabled(name: str, environ: Mapping[str, str] | None = None) -> bool:
    """Return whether the opt-in switch *name* is on.

    Args:
        name: Environment variable holding the switch.
        environ: Mapping to read instead of ``os.environ``.

    Raises:
        ConfigurationError: the value is set but is not one of ``true``,
            ``false``, ``1`` or ``0``.
    """
    env = os.environ if environ is None else environ
    raw = env.get(name, "").strip().lower()
    if raw in _ON:
        return True
    if raw in _OFF:
        return False
    raise ConfigurationError(
        f"Invalid {name}={raw!r}; expected 'true' or 'false' (or '1' / '0')."
    )


def nemo_rails_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether the NeMo Colang semantic rails are on (``CAGE_NEMO_ENABLED``).

    The deterministic input and output controls (Presidio and regex PII
    redaction, the Stage 1 keyword scan) run either way. This switch adds the
    LLM-backed rails on top.
    """
    return opt_in_enabled(CAGE_NEMO_ENABLED_ENV, environ)


def consensus_critics_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether multi-model consensus critics are on (``CAGE_CONSENSUS_CRITICS_ENABLED``).

    When off, actions at or above the domain magnitude threshold, or listed in
    ``high_stakes_actions``, escalate to human review with
    ``NOTIONAL_THRESHOLD_ESCALATION``. No critic model is called.
    """
    return opt_in_enabled(CAGE_CONSENSUS_CRITICS_ENABLED_ENV, environ)
