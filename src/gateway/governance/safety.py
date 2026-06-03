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
DEPRECATED — safety.py

This module is a backward-compatibility shim only.  It was split into two
canonical modules:

  - ``src.gateway.governance.text_filter`` — stateless text safety
        Exports: ``ac_keyword_scan``

  - ``src.gateway.governance.cbf`` — stateful Redis-backed financial invariant
        Exports: ``ControlBarrierFunction``, ``safety_filter``

All imports from this module will emit a ``DeprecationWarning`` at runtime.
Update your imports to use the canonical paths above.

**This module will be removed in the next major version.**

Known callers that have already been migrated to direct imports:
  - src/gateway/governance/singletons.py       → cbf.safety_filter
  - src/gateway/server/governance_middleware.py → text_filter.ac_keyword_scan
  - src/gateway/server/inference_proxy.py       → text_filter.ac_keyword_scan
"""

from __future__ import annotations

import warnings

# ---------------------------------------------------------------------------
# Lazy re-exports with per-symbol deprecation warnings (Python 3.7+ __getattr__)
# ---------------------------------------------------------------------------

_SYMBOL_ORIGINS: dict[str, str] = {
    "ac_keyword_scan": "src.gateway.governance.text_filter",
    "ControlBarrierFunction": "src.gateway.governance.cbf",
    "safety_filter": "src.gateway.governance.cbf",
}


def __getattr__(name: str):
    """Emit a DeprecationWarning and return the symbol from its canonical module."""
    if name not in _SYMBOL_ORIGINS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    canonical = _SYMBOL_ORIGINS[name]
    warnings.warn(
        f"Importing {name!r} from 'src.gateway.governance.safety' is deprecated "
        f"and will be removed in the next major version. "
        f"Import it directly from '{canonical}' instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    import importlib
    module = importlib.import_module(canonical)
    return getattr(module, name)


__all__ = list(_SYMBOL_ORIGINS.keys())
