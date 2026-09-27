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

"""Static guard: Redis maxmemory-policy is noeviction in every environment.

Governance state (ground-truth snapshots, CBF local debits, fence epoch,
DEFER tokens, evidence stream) must never be silently evicted. An evicting
policy in any environment lets dev/staging validate behaviour that differs
from production, and in the worst case drops a fence epoch or a debit.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_INFRA = _REPO / "infra"
_EVICTING = re.compile(r"(allkeys|volatile)-(lru|lfu|random|ttl)")


def _tf_files() -> list[Path]:
    return [p for p in _INFRA.rglob("*.tf*") if ".terraform" not in p.parts]


def test_redis_cache_module_hardcodes_noeviction() -> None:
    main_tf = (_INFRA / "modules/redis_cache/main.tf").read_text()
    assert "maxmemory-policy noeviction" in main_tf


def test_redis_cache_module_exposes_no_policy_variable() -> None:
    variables_tf = (_INFRA / "modules/redis_cache/variables.tf").read_text()
    assert 'variable "maxmemory_policy"' not in variables_tf


def test_no_evicting_policy_anywhere_in_infra() -> None:
    offenders = [
        f"{p.relative_to(_REPO)}:{n}"
        for p in _tf_files()
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if _EVICTING.search(line)
    ]
    assert offenders == [], f"Evicting Redis policy found: {offenders}"


def test_memorystore_instances_set_noeviction() -> None:
    for p in _tf_files():
        text = p.read_text()
        for match in re.finditer(r'resource\s+"google_redis_instance"', text):
            block = text[match.start() : match.start() + 4000]
            assert re.search(r'"maxmemory-policy"\s*=\s*"noeviction"', block), (
                f"{p.relative_to(_REPO)}: google_redis_instance without noeviction"
            )


def test_guard_detects_evicting_policy() -> None:
    """The guard must observe a violation, not only pass on clean input."""
    assert _EVICTING.search('maxmemory_policy = "allkeys-lru"')
    assert _EVICTING.search("maxmemory-policy volatile-lru")
    assert not _EVICTING.search("maxmemory-policy noeviction")
