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

"""How the opt-in flags select ``live_external`` tests.

``pytest.ini`` documents ``--run-partner-integration`` as the flag that enables
``partner_integration`` tests. Every partner live test also carries
``live_external``, and ``conftest.py`` skips ``live_external`` items unless they
are enabled here. The partner flag must therefore enable them too, or it
enables nothing.

Every selection decision reads the markers applied to an item
(:func:`applied_marker_names`), never ``item.keywords``: keywords also hold the
name of every parent node, so a hermetic test under ``tests/integration/`` would
read as ``integration`` and be skipped, and a test under ``tests/unit/`` would
satisfy the marker contract while ``-m "local or unit"`` never selects it.
"""

from __future__ import annotations

from collections.abc import Container

import pytest


def applied_marker_names(item: pytest.Item) -> frozenset[str]:
    """Names of the markers applied to ``item`` (module, class and function).

    These are exactly the markers a ``-m`` expression matches; directory,
    module and class names are excluded.
    """
    return frozenset(mark.name for mark in item.iter_markers())


def live_external_enabled(
    keywords: Container[str],
    *,
    run_live_external: bool,
    run_partner_integration: bool,
) -> bool:
    """Whether a ``live_external`` item may run.

    ``--run-live-external`` enables every ``live_external`` item.
    ``--run-partner-integration`` enables only the ones also marked
    ``partner_integration``.
    """
    return run_live_external or (
        run_partner_integration and "partner_integration" in keywords
    )
