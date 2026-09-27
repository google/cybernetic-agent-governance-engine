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
deployment's defer/narrow/pause posture, so the classifier is mandatory on
``GovernorComponents`` and the governor accepts nothing but components.
"""

from unittest.mock import MagicMock

import pytest

from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.governor.assembly import GovernorComponents
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.narrower import NarrowerRegistry
from tests.fixtures.governor import allow_opa

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_missing_classifier_is_rejected() -> None:
    with pytest.raises(TypeError, match="classifier"):
        GovernorComponents(opa=allow_opa(), core_stages=())  # type: ignore[call-arg]


def test_none_classifier_is_rejected() -> None:
    with pytest.raises(TypeError, match="requires a classifier"):
        GovernorComponents(opa=allow_opa(), core_stages=(), classifier=None)  # type: ignore[arg-type]


def test_legacy_kwargs_constructor_is_gone() -> None:
    with pytest.raises(TypeError):
        SymbolicGovernor(opa_client=MagicMock(), safety_filter=MagicMock(), consensus_engine=MagicMock())  # type: ignore[call-arg]


def test_supplied_classifier_is_used() -> None:
    engine = ClassificationEngine(narrower_registry=NarrowerRegistry(narrowers=[]))
    governor = SymbolicGovernor(GovernorComponents(opa=allow_opa(), core_stages=(), classifier=engine))
    assert governor.components.classifier is engine
