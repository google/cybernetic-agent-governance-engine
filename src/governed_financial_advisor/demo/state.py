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

from typing import Any


class DemoState:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.reset()
        return cls._instance

    def reset(self):
        """Resets the state to default."""
        self.simulated_latency: float = 0.0
        self.forced_risk_profile: str | None = None
        self.pipeline_status: dict[str, Any] = {
            "status": "idle",
            "message": "Ready to start.",
        }
        self.latest_generated_rules: str = ""
        self.latest_trace_id: str | None = None


# Global Singleton
demo_state = DemoState()
