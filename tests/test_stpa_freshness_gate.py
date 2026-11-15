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

"""STPA & OSCAL freshness gate: fail-closed SHA-256 content verification (POAM-2026-221)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_stpa_freshness.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_stpa_freshness", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def synthetic_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "repo"
    (repo / "config" / "stpa").mkdir(parents=True)
    source = repo / "config" / "stpa" / "core.yaml"
    artifact = repo / "generated.rego"
    source.write_text("hazards: []\n", encoding="utf-8")
    artifact.write_text("# Generated: 2000-01-01T00:00:00+00:00\n", encoding="utf-8")

    module = _load_gate()
    monkeypatch.setattr(module, "_REPO_ROOT", repo)
    monkeypatch.setattr(module, "_SOURCE_DIR", repo / "config" / "stpa")
    monkeypatch.setattr(module, "_DOMAIN_STPA_DIRS", [])
    monkeypatch.setattr(module, "_GENERATED_ARTIFACTS", [artifact])
    return module, repo, source, artifact


def test_matching_regenerated_content_is_fresh(synthetic_gate) -> None:
    module, _, _, artifact = synthetic_gate
    assert (
        module.check_freshness(
            regenerated={artifact: "# Generated: 2026-11-15T00:00:00+00:00\n"}
        )
        == []
    )


def test_differing_regenerated_content_is_stale(synthetic_gate) -> None:
    module, _, _, artifact = synthetic_gate
    errors = module.check_freshness(
        regenerated={artifact: "# Generated: 2026-11-15T00:00:00+00:00\n# drifted\n"}
    )
    assert len(errors) == 1
    assert "content differs from a fresh compile (sha256)" in errors[0]


def test_missing_artifact_is_reported(synthetic_gate) -> None:
    module, _, _, artifact = synthetic_gate
    artifact.unlink()
    errors = module.check_freshness(regenerated={artifact: "# content\n"})
    assert len(errors) == 1
    assert errors[0].startswith("MISSING artifact")


def test_unregenerable_artifact_fails_closed(synthetic_gate) -> None:
    """Inability to regenerate an artifact in memory is a hard failure, never a skip."""
    module, _, _, artifact = synthetic_gate
    errors = module.check_freshness(regenerated={artifact: None})
    assert len(errors) == 1
    assert "UNABLE TO CHECK" in errors[0]


def test_unreciped_artifact_in_generated_list_fails_closed(synthetic_gate) -> None:
    """Every entry in _GENERATED_ARTIFACTS must have a registered content recipe."""
    module, *_ = synthetic_gate
    errors = module.check_freshness()
    assert len(errors) == 1
    assert "UNABLE TO CHECK" in errors[0]
    assert "no registered regeneration recipe" in errors[0]


def test_missing_dependency_import_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replays the #694..#767 failure: ModuleNotFoundError in OSCAL export fails the gate."""
    from src.gateway.governance import oscal_ssp_exporter

    module = _load_gate()

    def _missing_otel(*_args: object, **_kwargs: object) -> dict[Path, str | None]:
        raise ModuleNotFoundError("No module named 'opentelemetry'")

    monkeypatch.setattr(
        oscal_ssp_exporter, "render_default_oscal_artifacts", _missing_otel
    )
    errors = module.check_freshness()
    assert len(errors) == 1
    assert "UNABLE TO CHECK" in errors[0]
    assert "ModuleNotFoundError" in errors[0]
    assert "opentelemetry" in errors[0]

    monkeypatch.setattr("sys.argv", ["check_stpa_freshness.py"])
    assert module.main() == 1


def test_missing_ruff_for_formatted_target_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing ruff binary when formatted Python/LangGraph targets exist fails closed."""
    module = _load_gate()
    monkeypatch.setattr(module, "_ruff_binary", lambda: None)
    errors = module.check_freshness()
    assert len(errors) == 1
    assert "UNABLE TO CHECK" in errors[0]
    assert "ruff binary is required" in errors[0]


def test_volatile_stamps_are_masked_before_hashing() -> None:
    module = _load_gate()
    a = (
        '# Generated: 2000-01-01T00:00:00+00:00\n{"generated_at": "2000-01-01T00:00:00Z",'
        ' "issued_at": "2000-01-01T00:00:00Z", "expires_at": "2001-01-01T00:00:00Z"}\n'
    )
    b = (
        '# Generated: 2026-10-01T14:00:00.1+00:00\n{"generated_at": "2026-10-01T14:00:00Z",'
        ' "issued_at": "2026-10-01T14:00:00Z", "expires_at": "2027-10-01T14:00:00Z"}\n'
    )
    assert module.content_digest(a) == module.content_digest(b)
    assert module.content_digest(a) != module.content_digest(a + "rule\n")


def test_every_committed_artifact_matches_a_fresh_compile() -> None:
    """Every real STPA and US_FED OSCAL artifact regenerates byte-identically."""
    module = _load_gate()
    results = module.check_content()
    assert {a.name: r.value for a, r in results.items()} == {
        a.name: "match" for a in module._GENERATED_ARTIFACTS
    }


def test_generated_artifacts_include_oscal_files() -> None:
    """All three US_FED OSCAL artifacts are tracked in _GENERATED_ARTIFACTS."""
    module = _load_gate()
    names = {a.name for a in module._GENERATED_ARTIFACTS}
    assert {
        "system-security-plan.yaml",
        "component-definition.yaml",
        "stpa_compiler_ssp_patch.yaml",
    }.issubset(names)


def test_planted_divergence_in_us_fed_ssp_reported_by_check_stpa_freshness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Planting a divergence in the US_FED SSP is caught by check_stpa_freshness.py."""
    module = _load_gate()
    real_ssp = module._OSCAL_SSP
    fake_ssp = tmp_path / "system-security-plan.yaml"
    original_text = real_ssp.read_text(encoding="utf-8")

    diverged = original_text.replace(
        "uuid: g7000099-stpa-4000-8000-compiler00001\n      control-id: sa-11",
        "uuid: g7000099-stpa-4000-8000-compiler00001\n      control-id: sa-999",
        1,
    )
    assert diverged != original_text
    fake_ssp.write_text(diverged, encoding="utf-8")

    monkeypatch.setattr(module, "_OSCAL_SSP", fake_ssp)
    monkeypatch.setattr(module, "_GENERATED_ARTIFACTS", [fake_ssp])

    errors = module.check_freshness()
    assert len(errors) == 1
    assert "content differs from a fresh compile (sha256)" in errors[0]
    assert "system-security-plan.yaml" in errors[0]
    assert "oscal_ssp_exporter export" in errors[0]


def test_planted_divergence_in_compiled_stpa_artifact_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Planting a divergence in a compiled STPA artifact fails check_stpa_freshness.py."""
    module = _load_gate()
    real_nemo = module._REPO_ROOT / "config" / "rails" / "generated_stpa_rails.co"
    fake_nemo = tmp_path / "generated_stpa_rails.co"
    fake_nemo.write_text(
        real_nemo.read_text(encoding="utf-8") + "\n# planted drift\n",
        encoding="utf-8",
    )

    recipes = dict(module._ARTIFACT_RECIPES)
    recipes[fake_nemo] = recipes[real_nemo]
    monkeypatch.setattr(module, "_ARTIFACT_RECIPES", recipes)
    monkeypatch.setattr(module, "_GENERATED_ARTIFACTS", [fake_nemo])

    errors = module.check_freshness()
    assert len(errors) == 1
    assert "content differs from a fresh compile (sha256)" in errors[0]
    assert "generated_stpa_rails.co" in errors[0]
    assert "stpa_compiler compile" in errors[0]


# Regression coverage binding: POAM-2026-176, POAM-2026-221
