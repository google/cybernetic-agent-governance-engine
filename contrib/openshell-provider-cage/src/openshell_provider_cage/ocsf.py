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

"""OCSF v1.1.0 event helpers for OpenShell sandbox telemetry."""

from __future__ import annotations

import re
import time
from typing import Any

# Prohibited credential patterns per CAGE secret hygiene policy
_CRED_PATTERNS = [
    re.compile(r"pk-lf-[A-Za-z0-9_-]+"),
    re.compile(r"sk-lf-[A-Za-z0-9_-]+"),
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    re.compile(r"redis://[^:]+:[^@]+@"),
]


def scrub_credentials(obj: Any) -> Any:
    """Recursively redact secrets and credentials from telemetry objects."""
    if isinstance(obj, str):
        cleaned = obj
        for pat in _CRED_PATTERNS:
            cleaned = pat.sub("[REDACTED_CREDENTIAL]", cleaned)
        return cleaned
    if isinstance(obj, dict):
        return {k: scrub_credentials(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_credentials(item) for item in obj]
    return obj


def build_ocsf_network_event(
    *,
    sandbox_id: str,
    thread_id: str,
    dst_endpoint: str,
    http_verb: str,
    action_taken: str,  # "allowed" | "denied"
    status_code: int = 200,
) -> dict[str, Any]:
    """Build OCSF Class 4001 (Network Activity) event."""
    return scrub_credentials(
        {
            "class_uid": 4001,
            "category_uid": 4,
            "activity_id": 1,
            "time": int(time.time()),
            "action": action_taken,
            "status_code": status_code,
            "actor": {
                "id": sandbox_id,
                "type": "sandbox_workload",
            },
            "unmapped": {
                "thread_id": thread_id,
                "requested_endpoint": dst_endpoint,
                "http_verb": http_verb,
            },
        }
    )
