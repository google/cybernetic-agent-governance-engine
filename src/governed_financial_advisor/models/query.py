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

"""Agent query request/response models for POST /agent/query endpoint.

Eliminates triple-source schema drift (S0-2, S0-3, S1-5) by defining the
canonical wire contract in a single location. All refusal paths (NeMo, OPA,
STPA, Evaluator) route through `explainer` and conform to QueryResponse.
"""

from pydantic import BaseModel, ConfigDict, Field

from src.governed_financial_advisor.models.principal import (
    PRINCIPAL_MAX_LEN,
    PRINCIPAL_PATTERN,
)


class QueryRequest(BaseModel):
    """Request payload for POST /agent/query endpoint.

    ``user_id`` is the end-user principal asserted by the caller. The advisor
    does not authenticate it: ``CAGE_API_KEY`` authenticates the client, not a
    user. It is forwarded to the gateway as ``x-cage-principal`` for
    attribution and per-principal rate limiting, so it must already fit the
    gateway's principal charset and 64-character cap.
    """

    prompt: str
    user_id: str = Field(
        ...,
        min_length=1,
        max_length=PRINCIPAL_MAX_LEN,
        pattern=PRINCIPAL_PATTERN,
        description="End-user principal asserted by the caller; not authenticated.",
    )
    thread_id: str = "default_thread"


class QueryResponse(BaseModel):
    """Canonical response model for POST /agent/query endpoint.

    Every refusal path (NeMo, OPA, STPA, Evaluator) routes through `explainer`
    and returns HTTP 200 with this schema. Trace ID is formatted via OpenTelemetry
    as `f"{ctx.trace_id:032x}"` (32-char lowercase hex W3C/OTel trace ID) or None
    when tracing is disabled or unsampled.

    Attributes:
        response: Advisor response or structured governance explanation (refusal).
        trace_id: 32-character lowercase hex W3C/OTel trace ID, or None if
                  tracing is disabled or request was unsampled.
    """

    response: str = Field(
        ..., description="Advisor response or structured governance explanation"
    )
    trace_id: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{32}$",
        description="32-character lowercase hex W3C/OTel trace ID, or None if unsampled/disabled",
    )
    model_config = ConfigDict(frozen=True)
