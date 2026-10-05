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

"""Startup guard: the advisor must never be configured with a signing key.

The advisor is the untrusted neural plane (POAM-2026-079). It hosts no
``SymbolicGovernor``, verifies no routing seals and runs without a cloud
identity; only the gateway and the reconciler sign. A signing-key reference in
its environment means a deployment re-attached a signing identity, so the
process refuses to start instead of serving with a key it must not hold.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

# Signing-key references read by the kernel's signer factory, the
# reconciler trust anchor, and the compliance bridge batch signer, for every
# supported KMS provider.
FORBIDDEN_SIGNING_KEY_VARS: tuple[str, ...] = (
    "KMS_GOVERNANCE_KEY",
    "RECONCILER_KMS_KEY",
    "EVIDENCE_KMS_KEY",
    "AWS_KMS_KEY_ID",
    "AZURE_KMS_KEY_NAME",
)


def assert_no_signing_identity(environ: Mapping[str, str] | None = None) -> None:
    """Raise ``RuntimeError`` if any signing-key reference is set.

    Applies in every environment: the advisor has no legitimate use for a
    signing key, so there is no development exemption.
    """
    env = os.environ if environ is None else environ
    present = sorted(
        name for name in FORBIDDEN_SIGNING_KEY_VARS if env.get(name, "").strip()
    )
    if present:
        raise RuntimeError(
            "Refusing to start: the advisor must hold no signing identity "
            f"(POAM-2026-079), but {', '.join(present)} is set. Signing belongs "
            "to the gateway and the reconciler; remove these variables."
        )
