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

"""Governor test fixtures: install an in-memory OpenTelemetry TracerProvider."""

from __future__ import annotations

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from src.gateway.governance.governor import governor as governor_module
from src.gateway.governance.governor.stages import domain_tiers as domain_tiers_module


@pytest.fixture(autouse=True)
def _configure_otel_tracer_for_governor_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Install a fresh SDK TracerProvider per test so tier spans have valid trace IDs."""
    provider = TracerProvider()
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", provider)
    monkeypatch.setattr(
        governor_module,
        "tracer",
        trace.get_tracer(governor_module.__name__),
    )
    monkeypatch.setattr(
        domain_tiers_module,
        "tracer",
        trace.get_tracer(domain_tiers_module.__name__),
    )
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "memory")
