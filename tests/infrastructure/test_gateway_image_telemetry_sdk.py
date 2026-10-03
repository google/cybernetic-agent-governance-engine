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

"""The gateway image carries the SDK of every telemetry provider its manifests select.

Every gateway manifest sets ``CAGE_TELEMETRY_PROVIDER=remote``, which resolves to
``src/integrations/telemetry_langfuse`` and imports ``langfuse`` at startup. The
image is built by ``src/gateway/Dockerfile`` from the locked extras, so the
``langfuse`` extra must be in its ``uv sync``. Without it the gateway raises
``ConfigurationError`` in ``bootstrap_governor()`` and crash-loops (staging,
2026-10-03).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_DOCKERFILE = _REPO / "src" / "gateway" / "Dockerfile"
_MANIFESTS = [
    _REPO / "deployment" / "k8s" / "gateway.yaml",
    _REPO / "deployment" / "k8s" / "gateway.yaml.tpl",
    _REPO / "deployment" / "k8s" / "gateway-deployment.yaml.tpl",
    _REPO / "infra" / "modules" / "gateway" / "main.tf",
]
_REMOTE = re.compile(r"CAGE_TELEMETRY_PROVIDER[\"']?\s*\n?\s*(?:value\s*[:=]\s*)[\"']remote[\"']")


def _synced_extras() -> set[str]:
    text = _DOCKERFILE.read_text()
    sync_lines = [line for line in text.splitlines() if line.strip().startswith("RUN uv sync")]
    assert sync_lines, "src/gateway/Dockerfile has no `uv sync` step"
    return {m for line in sync_lines for m in re.findall(r"--extra\s+(\S+)", line)}


def test_manifests_select_remote_telemetry() -> None:
    # Guards the regex: if no manifest matches, the contract below is vacuous.
    selecting = [p.name for p in _MANIFESTS if _REMOTE.search(p.read_text())]
    assert selecting, "no gateway manifest selects CAGE_TELEMETRY_PROVIDER=remote"


def test_gateway_image_installs_the_langfuse_extra() -> None:
    assert "langfuse" in _synced_extras(), (
        "a gateway manifest selects CAGE_TELEMETRY_PROVIDER=remote, which imports "
        "langfuse; add `--extra langfuse` to the `uv sync` in src/gateway/Dockerfile"
    )
