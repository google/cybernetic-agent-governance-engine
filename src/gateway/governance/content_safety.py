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

"""Content-safety verdict vocabulary (POAM-2026-124).

A content-safety check either reaches a verdict or it does not. Only the
exact :data:`SAFE_VERDICT` means the semantic rails ran and passed the text.
Every path that reaches no verdict is reported as blocked with a reason
code, never as safe. That covers rails switched off, rails enabled but
absent, NeMo raising "No main flow found", any other error, and no
inference backend. The codes let the evidence chain tell "a rail blocked
this" apart from "nothing could check this". They also tell "nothing was
configured to check this" apart from "the check failed to start".

The gateway's ``verify_content_safety`` tool, the semantic rail provider and
the advisor all read this one vocabulary.
"""

from __future__ import annotations

from typing import Final

SAFE_VERDICT: Final[str] = "SAFE"
BLOCKED_PREFIX: Final[str] = "BLOCKED"

# The rails are enabled but absent, or present only as the transparent-fallback
# stub: they should be running and are not.
CONTENT_SAFETY_RAILS_UNAVAILABLE: Final[str] = "CONTENT_SAFETY_RAILS_UNAVAILABLE"
# CAGE_NEMO_ENABLED=false: the rails are off by configuration. Nothing failed;
# nothing was configured to check the text.
CONTENT_SAFETY_RAILS_DISABLED: Final[str] = "CONTENT_SAFETY_RAILS_DISABLED"
# NeMo raised "No main flow found": the rails ran no flow, so no verdict exists.
CONTENT_SAFETY_NO_MAIN_FLOW: Final[str] = "CONTENT_SAFETY_NO_MAIN_FLOW"
# Any other error while checking.
CONTENT_SAFETY_ERROR: Final[str] = "CONTENT_SAFETY_ERROR"
# CAGE_INFERENCE_BACKEND=none: no rails are built, by design.
CONTENT_SAFETY_NO_INFERENCE_BACKEND: Final[str] = "CONTENT_SAFETY_NO_INFERENCE_BACKEND"


def refusal_reason(code: str, detail: str) -> str:
    """Return a refusal reason that leads with its reason code."""
    return f"{code}: {detail}"


def blocked_verdict(reason: str) -> str:
    """Return the tool-level verdict string for a refusal."""
    return f"{BLOCKED_PREFIX}: {reason}"


def is_safe_verdict(verdict: object) -> bool:
    """True only for the exact SAFE verdict; every other output is not safe."""
    return verdict == SAFE_VERDICT
