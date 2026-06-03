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
DEPRECATED — stpa_validator.py

This module is a backward-compatibility shim only.  All STPA constraint logic
(UCA-1, UCA-2, UCA-5, UCA-6, UCA-8, UCA-9, SC-1, FIN-2) has been migrated to
``src.gateway.governance.generated_stpa_validator.GeneratedSTPAValidator``.

Canonical import paths going forward:

    from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator

``STPAValidator`` is now an alias for ``GeneratedSTPAValidator``.  The
``validate()`` method delegates to ``validate_generated()`` so that existing
call-sites continue to work without modification during the transition period.

**This module will be removed in the next major version.**  Update all imports
to use ``generated_stpa_validator`` directly.  The ``symbolic_governor`` module
has already been updated to bypass this shim.
"""

import warnings

warnings.warn(
    "stpa_validator.STPAValidator is deprecated and will be removed in the next major "
    "version. Import GeneratedSTPAValidator from "
    "src.gateway.governance.generated_stpa_validator instead.",
    DeprecationWarning,
    stacklevel=2,
)

from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator  # noqa: E402


class STPAValidator(GeneratedSTPAValidator):
    """Deprecated alias for GeneratedSTPAValidator.

    Provides a ``validate()`` shim that delegates to ``validate_generated()``
    so that existing call-sites (e.g. tests, external integrations) continue to
    work without modification.

    **Will be removed in the next major version.**  Migrate to:

        from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator

    and call ``validate_generated(action_name, params)`` directly.
    """

    def validate(self, action_name: str, params: dict) -> list[str]:
        """Backward-compatible shim — delegates to validate_generated().

        .. deprecated::
            Use ``GeneratedSTPAValidator.validate_generated()`` directly.
        """
        warnings.warn(
            "STPAValidator.validate() is deprecated. "
            "Use GeneratedSTPAValidator.validate_generated() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.validate_generated(action_name, params)


__all__ = ["STPAValidator"]
