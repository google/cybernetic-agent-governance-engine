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

"""Package-scoped configuration for the finance domain-plugin test suite."""

import pytest


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Stamp every test in this package with the `financial` domain marker.

    Domain membership is a property of location, not of the individual test, so it is
    applied structurally here rather than repeated in 17 modules.  This marker is
    *additive*: it never satisfies the selection guard in tests/conftest.py, so each
    module must still declare `unit`/`local` explicitly.
    """
    for item in items:
        if str(item.nodeid).startswith("tests/cage_finance/"):
            item.add_marker(pytest.mark.financial)
