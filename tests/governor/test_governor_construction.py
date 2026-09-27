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

"""``SymbolicGovernor`` requires an explicit ``ClassificationEngine``.

The old default called ``ClassificationEngine()`` without its required
``narrower_registry`` and crashed.  A silent default would also ignore the
deployment's defer/narrow/pause posture, so the engine is now mandatory.
"""

from unittest.mock import MagicMock

import pytest

from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.narrower import NarrowerRegistry

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _deps() -> dict[str, MagicMock]:
    return {"opa_client": MagicMock(), "safety_filter": MagicMock(), "consensus_engine": MagicMock()}


def test_missing_classification_engine_is_rejected() -> None:
    with pytest.raises(TypeError, match="classification_engine"):
        SymbolicGovernor(**_deps())  # type: ignore[call-arg]


def test_none_classification_engine_is_rejected() -> None:
    with pytest.raises(TypeError, match="requires a classification_engine"):
        SymbolicGovernor(**_deps(), classification_engine=None)  # type: ignore[arg-type]


def test_supplied_classification_engine_is_used() -> None:
    engine = ClassificationEngine(narrower_registry=NarrowerRegistry(narrowers=[]))
    governor = SymbolicGovernor(**_deps(), classification_engine=engine)
    assert governor._classifier is engine
