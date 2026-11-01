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

"""Decision digests: the one format every evidence writer checks.

An evidence record names the governance decision behind it by a SHA-256
digest, never by the value the digest was computed from. Two fields carry
one, and each has exactly one meaning (POAM-2026-149):

* ``governance_decision_digest``: ``seal_digest(seal)``, the SHA-256 of the
  routing seal that authorised an action. ``ExecutionClearance``, the
  actuation receipts, a clearance-triggered ``QuarantineDirective`` and
  actuator_02's OCSF telemetry carry it.
* ``refusal_proof_hash``: the ``proof_hash`` of the ``RefusalReceipt`` whose
  DENY triggered a kernel quarantine. A refusal has no seal, so it has no
  ``governance_decision_digest``.

Both are lowercase SHA-256 hex, matched in full with ``re.fullmatch``: an
anchored ``re.match`` with ``$`` also admits a trailing newline. Both seal
formats contain ``.``, so a seal never passes. A refusal names the field and
never echoes the value, because the value may be a seal on its way into a log
or a receipt finding. The stream oracle's ``digest_format`` rule
(``proof/stream_invariants.py``) checks the same format on every record.

Architectural Invariant:
    This module must NEVER import from ``src.gateway.governance`` or any other
    kernel module. It imports only the standard library, so a writer in any
    layer can apply the rule without pulling in the kernel.
"""

from __future__ import annotations

import re
from typing import TypeGuard

#: ``seal_digest(seal)``: the routing seal that authorised an action.
GOVERNANCE_DECISION_DIGEST = "governance_decision_digest"

#: ``RefusalReceipt.proof_hash``: the refusal that triggered a quarantine.
REFUSAL_PROOF_HASH = "refusal_proof_hash"

#: Every field that names a governance decision by digest.
DECISION_DIGEST_FIELDS: frozenset[str] = frozenset(
    {GOVERNANCE_DECISION_DIGEST, REFUSAL_PROOF_HASH}
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def is_sha256_hex(value: object) -> TypeGuard[str]:
    """True iff ``value`` is a ``str`` of exactly 64 lowercase hex characters."""
    return isinstance(value, str) and _SHA256_HEX.fullmatch(value) is not None


def require_sha256_hex(value: object, *, field: str) -> str:
    """Return ``value`` if it is a lowercase SHA-256 hex digest.

    Raises:
        ValueError: ``value`` is anything else. The message names ``field``
            and never contains ``value``.
    """
    if is_sha256_hex(value):
        return value
    raise ValueError(
        f"{field} must be a lowercase SHA-256 hex digest (64 characters, 0-9a-f); "
        "a seal or any other bearer value must not enter evidence"
    )


__all__ = [
    "DECISION_DIGEST_FIELDS",
    "GOVERNANCE_DECISION_DIGEST",
    "REFUSAL_PROOF_HASH",
    "is_sha256_hex",
    "require_sha256_hex",
]
