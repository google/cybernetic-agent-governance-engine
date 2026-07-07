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

from fastapi import APIRouter
from pydantic import BaseModel

from src.governed_financial_advisor.demo.state import demo_state

demo_router = APIRouter(prefix="/demo", tags=["demo"])


class PipelineRequest(BaseModel):
    strategy: str


class ContextRequest(BaseModel):
    latency: float
    risk_profile: str = "Balanced"


@demo_router.get("/status")
def get_status():
    """Returns the current demo state."""
    return {
        "pipeline": demo_state.pipeline_status,
        "latency": demo_state.simulated_latency,
        "rules": demo_state.latest_generated_rules,
        "trace_id": demo_state.latest_trace_id,
    }


@demo_router.post("/context")
def set_context(req: ContextRequest):
    """Updates the simulated environment context."""
    demo_state.simulated_latency = req.latency
    demo_state.forced_risk_profile = req.risk_profile
    return {"status": "updated", "latency": req.latency}


@demo_router.post("/reset")
def reset_demo():
    """Resets the demo state."""
    demo_state.reset()
    return {"status": "reset"}
