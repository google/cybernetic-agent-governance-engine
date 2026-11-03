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

"""Multi-Ring Agent Containment & Monotonic Epoch Autotomy (Layer 1 Kernel).

Enforces mathematical and cryptographic verification at agent boundaries:
  - Monotonic epoch autotomy (Gen N -> Gen N + 1) across local handles and global registries
  - Cryptographic epoch-derived HMAC verification with constant-time comparison
  - Case-insensitive lateral sink isolation
  - Fail-closed role and breakout gating
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from enum import StrEnum
from typing import Any

from src.gateway.governance.quarantine_actuator import (
    advance_workload_epoch as _actuator_advance_workload_epoch,
)
from src.gateway.governance.quarantine_actuator import (
    get_workload_min_epoch as _actuator_get_workload_min_epoch,
)

logger = logging.getLogger("Gateway.Governance.ArmContainmentRing")

# High-privilege sink suffixes that quarantined or untrusted roles cannot message
_RESTRICTED_SINK_LITERALS: frozenset[str] = frozenset(
    {
        "accountingledgerwrite",
        "ledgerwrite",
        "fundtransfer",
        "secretsmanagement",
        "kernelcontrol",
        "rootprivilege",
    }
)


class ArmRole(StrEnum):
    """Exhaustive role variants for multi-ring agent containment."""

    COORDINATOR = "COORDINATOR"
    WORKER = "WORKER"
    OBSERVER = "OBSERVER"
    SANDBOX_EXECUTOR = "SANDBOX_EXECUTOR"
    UNTRUSTED = "UNTRUSTED"
    FUZZING = "FUZZING"
    QUARANTINED = "QUARANTINED"


async def advance_workload_epoch(
    workload_id: str,
    new_epoch: int,
    redis_client: Any | None = None,
) -> int:
    """Monotonically advance the workload generation epoch (Gen N -> Gen N+1).

    Delegates to the kernel quarantine actuator registry, ensuring atomic Redis
    CAS or in-process monotonicity.
    """
    normalized_id = workload_id.strip().lower()
    return await _actuator_advance_workload_epoch(
        normalized_id, new_epoch, redis_client=redis_client
    )


async def get_workload_min_epoch(
    workload_id: str,
    redis_client: Any | None = None,
) -> int:
    """Return the current minimum required generation epoch for workload_id."""
    normalized_id = workload_id.strip().lower()
    return await _actuator_get_workload_min_epoch(
        normalized_id, redis_client=redis_client
    )


class ArmContainmentRing:
    """Per-Arm containment ring and epoch verification guard."""

    def __init__(self, master_seed: bytes) -> None:
        if len(master_seed) < 32:
            raise ValueError("ArmContainmentRing master_seed must be at least 32 bytes")
        self._master_seed = master_seed
        self._local_epochs: dict[str, int] = {}
        self._arm_roles: dict[str, ArmRole] = {}

    def register_arm(self, arm_id: str, role: ArmRole, initial_epoch: int = 1) -> None:
        """Register an arm with an initial monotonic generation epoch and role."""
        normalized_id = arm_id.strip().lower()
        self._arm_roles[normalized_id] = role
        self._local_epochs[normalized_id] = max(1, initial_epoch)

    def get_epoch(self, arm_id: str) -> int:
        """Return the current generation epoch for arm_id."""
        normalized_id = arm_id.strip().lower()
        return self._local_epochs.get(normalized_id, 0)

    def advance_epoch(self, arm_id: str) -> int:
        """Monotonically advance the local generation epoch for an arm (N -> N+1)."""
        normalized_id = arm_id.strip().lower()
        current = self._local_epochs.get(normalized_id, 0)
        new_epoch = current + 1
        self._local_epochs[normalized_id] = new_epoch
        return new_epoch

    def derive_epoch_key(self, arm_id: str, epoch: int, role: ArmRole) -> bytes:
        """Cryptographically derive an epoch key using HKDF-like HMAC-SHA256."""
        normalized_id = arm_id.strip().lower()
        info = f"{normalized_id}:{epoch}:{role.value}".encode()
        return hmac.new(self._master_seed, info, hashlib.sha256).digest()

    def sign_message(
        self, arm_id: str, epoch: int, role: ArmRole, message: bytes
    ) -> bytes:
        """Sign an inter-agent message with the arm's derived epoch key."""
        key = self.derive_epoch_key(arm_id, epoch, role)
        return hmac.new(key, message, hashlib.sha256).digest()

    def verify_message(
        self,
        arm_id: str,
        epoch: int,
        role: ArmRole,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Verify an inter-agent message signature using constant-time comparison."""
        normalized_id = arm_id.strip().lower()
        current_epoch = self._local_epochs.get(normalized_id, 0)
        if epoch < current_epoch:
            logger.warning(
                "Stale epoch rejection in ArmContainmentRing: arm=%s, msg_epoch=%s < current=%s",
                arm_id,
                epoch,
                current_epoch,
            )
            return False

        expected_key = self.derive_epoch_key(arm_id, epoch, role)
        expected_sig = hmac.new(expected_key, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected_sig, signature)

    def can_access_sink(self, sender_arm_id: str, sink_identifier: str) -> bool:
        """Case-insensitive lateral sink isolation check.

        Blocks untrusted, fuzzing, or quarantined roles from high-privilege sinks.
        """
        normalized_arm = sender_arm_id.strip().lower()
        normalized_sink = sink_identifier.strip().lower()

        role = self._arm_roles.get(normalized_arm, ArmRole.UNTRUSTED)
        if role in (ArmRole.UNTRUSTED, ArmRole.FUZZING, ArmRole.QUARANTINED):
            for restricted in _RESTRICTED_SINK_LITERALS:
                if restricted in normalized_sink:
                    logger.warning(
                        "Blocked lateral sink access: arm=%s (role=%s) -> sink=%s",
                        sender_arm_id,
                        role,
                        sink_identifier,
                    )
                    return False

        if role == ArmRole.QUARANTINED:
            return False

        return True


__all__ = [
    "ArmContainmentRing",
    "ArmRole",
    "advance_workload_epoch",
    "get_workload_min_epoch",
]
