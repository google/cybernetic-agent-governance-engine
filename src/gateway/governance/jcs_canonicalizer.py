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
RFC 8785 JSON Canonicalization Scheme (JCS) utility.
"""

from typing import Any

from src.gateway.governance.vendor.jcs import canonicalize


def _prepare_for_canonicalization(obj: Any) -> Any:
    """Recursively convert non-JSON-serializable objects to dicts.
    
    Handles Violation dataclass instances that may appear in standing_at_refusal
    or other nested structures before JCS canonicalization.
    """
    from src.gateway.governance.contracts import Violation
    
    if isinstance(obj, Violation):
        # Convert Violation to dict for JSON serialization
        return {
            "tier": obj.tier,
            "code": obj.code,
            "message": obj.message,
            "kind": obj.kind.value,  # Serialize enum to string
        }
    elif isinstance(obj, dict):
        return {k: _prepare_for_canonicalization(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_prepare_for_canonicalization(item) for item in obj]
    else:
        return obj


def jcs_canonicalize_plan(plan: dict[str, Any]) -> bytes:
    """Produce an RFC 8785 deterministic byte representation of a payload.

    This replaces ad-hoc json.dumps(sort_keys=True) which is vulnerable to
    floating-point canonicalization drift between different languages (e.g. Python vs Go).
    
    Preprocesses the payload to convert any Violation dataclass instances to dicts
    before canonicalization.
    """
    prepared_plan = _prepare_for_canonicalization(plan)
    return canonicalize(prepared_plan)
