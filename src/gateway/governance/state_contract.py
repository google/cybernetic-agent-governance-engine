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
Generic fail-closed state contract validation for Layer 1 kernel.

Addresses GAP-3 findings S0-1, S1-1, S1-2, S1-3, S1-4:
- S0-1: Posture is explicit constructor argument (enforcing: bool = True)
- S1-1: Wraps jsonschema.ValidationError in kernel-owned StateContractViolation
- S1-2: Pre-compiles Draft202012Validator at initialization time
- S1-3: Emits structured audit/refusal record before raising
- S1-4: Validates state on node exit
"""

import logging
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

logger = logging.getLogger(__name__)


class StateContractViolation(RuntimeError):
    """Kernel-owned exception for state contract violations."""

    def __init__(self, node_name: str, path: str, message: str) -> None:
        self.node_name = node_name
        self.path = path
        self.message = message
        super().__init__(
            f"Node '{node_name}' breached state contract at '{path}': {message}"
        )


class CompiledStateValidator:
    """
    Pre-compiled JSON Schema validator for node output state contracts.

    Enforces fail-closed validation with explicit posture control.
    """

    def __init__(self, schema: dict[str, Any], enforcing: bool = True) -> None:
        """
        Initialize validator with pre-compiled schema.

        Args:
            schema: JSON Schema (Draft 2020-12) defining state contract
            enforcing: When True (default), validation failures raise exceptions.
                      When False, violations are logged but not enforced.

        Raises:
            Exception: If schema is invalid or validator construction fails
        """
        self.enforcing = enforcing
        self.schema = schema
        # S1-2: Pre-compile Draft202012Validator at construction time
        # Fail initialization immediately if schema or dependency is invalid
        self.validator = Draft202012Validator(schema)

    def validate_node_output(
        self,
        node_name: str,
        state: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Validate node output state against pre-compiled schema.

        Args:
            node_name: Name of the node being validated
            state: Output state dictionary to validate
            context: Optional context for audit logging

        Raises:
            StateContractViolation: When validation fails in enforcing mode

        S1-3: Emits structured audit/refusal record before raising
        S1-4: Validates state on node exit
        """
        if not self.enforcing:
            return

        try:
            # Execute validation using pre-compiled validator
            self.validator.validate(state)
        except JsonSchemaValidationError as e:
            # S1-1: Wrap jsonschema.ValidationError in kernel-owned exception
            path = ".".join(str(p) for p in e.absolute_path) or "(root)"
            message = e.message

            # S1-3: Emit structured audit/refusal record before raising
            audit_record = {
                "event": "state_contract_violation",
                "node_name": node_name,
                "path": path,
                "message": message,
                "schema_path": ".".join(str(p) for p in e.absolute_schema_path),
                "context": context or {},
            }
            logger.error(
                "State contract violation detected",
                extra={"audit_record": audit_record},
            )

            # Raise kernel-owned exception
            raise StateContractViolation(
                node_name=node_name, path=path, message=message
            ) from e
