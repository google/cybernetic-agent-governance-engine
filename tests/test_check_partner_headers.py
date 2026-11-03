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

"""scripts/check_partner_headers.py: banners and canonical slot-to-vendor tables.

The banner states only what holds for every partner document, sits directly
under the title, and links to a status table that lists every partner. Files a
MANIFEST.sha256 pins and anything that is not Markdown are never modified.
The README tables (``## Directory Index`` and ``## Live Verification Status``)
must match ``PARTNER_SLOTS``, which in turn matches the adapter classes in
``src/integrations/``.
"""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Callable
from pathlib import Path

import pytest

from scripts import check_partner_headers as gate
from src.gateway.governance.attestation_aggregator import _load_attestation_provider
from src.gateway.governance.normative_provider import get_normative_provider

pytestmark = [pytest.mark.unit, pytest.mark.local]

_STATUS_README = """# Partners

## Directory Index

| Provider Namespace | Partner / Vendor | Integration Role & Protocol | Documentation Directory | Adapter Implementation |
|---|---|---|---|---|
| `provider_01` | **FlowSignal** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_01/`](provider_01/) | [`src/integrations/provider_01/`](../../src/integrations/provider_01/) |
| `provider_02` | **NexArt** | Attestation Provider & Cryptographic Evidence Resolver (`AttestationProvider`, CER) | [`provider_02/`](provider_02/) | [`src/integrations/provider_02/`](../../src/integrations/provider_02/) |

## Live Verification Status

| Adapter | Result |
|---|---|
| `provider_01` FlowSignal | Not run |
| `provider_02` NexArt | Not run |

## Next section
"""

_SEAM_METHODS: dict[str, tuple[str, ...]] = {
    "NormativeProvider": ("fetch_baseline", "validate_fria", "submit_evidence"),
    "AttestationProvider": ("fetch_attestations",),
    "WarrantSource": ("fetch", "provider_name"),
    "ExecutionActuator": ("actuate", "get_capabilities", "health_check"),
    "PolicyAdvisorBridge": ("evaluate_proposal",),
    "QuarantineActuator": ("quarantine_workload", "health_check"),
}


def _tree(tmp_path: Path) -> Path:
    """A minimal docs/partners tree with one pinned deposit and one JSON record."""
    root = tmp_path / "docs" / "partners"
    (root / "provider_01").mkdir(parents=True)
    (root / "provider_02" / "deposit").mkdir(parents=True)
    (root / "README.md").write_text(_STATUS_README, encoding="utf-8")
    (root / "provider_01" / "SPEC.md").write_text("# Spec\n\nBody.\n", encoding="utf-8")
    (root / "provider_01" / "record.json").write_text('{"a": 1}\n', encoding="utf-8")
    deposit = root / "provider_02" / "deposit"
    (deposit / "README.md").write_text("# Deposited\n", encoding="utf-8")
    (deposit / "NOTES.md").write_text("# Not pinned\n", encoding="utf-8")
    digest = hashlib.sha256((deposit / "README.md").read_bytes()).hexdigest()
    (deposit / "MANIFEST.sha256").write_text(f"{digest}  README.md\n", encoding="utf-8")
    return root


def _readme_tree(tmp_path: Path) -> Path:
    """A docs/partners tree carrying the repository README.md and empty slot dirs."""
    root = tmp_path / "docs" / "partners"
    root.mkdir(parents=True)
    for slot in gate.PARTNER_SLOTS:
        (root / slot).mkdir()
    (root / "README.md").write_text(
        (gate.PARTNERS_ROOT / "README.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return root


def _snapshot(root: Path) -> dict[Path, bytes]:
    return {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_every_partner_document_in_the_repository_carries_the_banner() -> None:
    assert gate.violations() == []
    assert len(gate.partner_docs()) > 0


def test_banner_states_only_what_holds_for_every_document() -> None:
    banner = gate.expected_banner(gate.PARTNERS_ROOT / "provider_01" / "SPEC.md")
    prose = " ".join(line.removeprefix("> ") for line in banner.splitlines())
    assert "Third-party integration material" in prose
    assert "not a Google certification or endorsement of the partner" in prose
    assert "](../README.md#live-verification-status)" in prose
    # The prototype's claims do not hold for every document (spec §4.2, item 2).
    for claim in ("Partner-authored", "Google-authored", "CLA", "AUTHOR_SELF_TEST"):
        assert claim not in prose


def test_the_link_climbs_to_the_status_table_from_any_depth(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    nested = root / "provider_02" / "deposit" / "NOTES.md"
    assert "](../../README.md#live-verification-status)" in gate.expected_banner(
        nested, root
    )


def test_apply_inserts_the_banner_under_the_title_once(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    spec = root / "provider_01" / "SPEC.md"
    assert any("provider_01/SPEC.md" in error for error in gate.violations(root))

    changed = gate.apply_banners(root)
    assert spec in changed
    banner = gate.expected_banner(spec, root)
    assert spec.read_text(encoding="utf-8") == f"# Spec\n\n{banner}\n\nBody.\n"
    assert gate.violations(root) == []
    assert gate.apply_banners(root) == [], "applying twice must change nothing"


@pytest.mark.parametrize(
    "edit",
    [
        lambda text: text.replace("../README.md", "../OTHER.md"),
        lambda text: text.replace("Third-party", "Partner-authored"),
        lambda text: text.replace("# Spec\n\n", "# Spec\n\nIntro first.\n\n"),
    ],
    ids=["stale-link", "edited-wording", "misplaced"],
)
def test_stale_or_misplaced_banners_fail_and_apply_restores_them(
    tmp_path: Path, edit: Callable[[str], str]
) -> None:
    root = _tree(tmp_path)
    gate.apply_banners(root)
    spec = root / "provider_01" / "SPEC.md"
    spec.write_text(edit(spec.read_text(encoding="utf-8")), encoding="utf-8")
    assert any("provider_01/SPEC.md" in error for error in gate.violations(root))
    gate.apply_banners(root)
    assert gate.violations(root) == []


def test_pinned_deposits_and_non_markdown_files_are_never_modified(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path)
    before = _snapshot(root)
    changed = set(gate.apply_banners(root))
    after = _snapshot(root)

    deposit = root / "provider_02" / "deposit"
    assert root / "README.md" not in changed
    assert deposit / "README.md" not in gate.partner_docs(root)
    assert deposit / "NOTES.md" in changed, "only files the manifest pins are exempt"
    untouched = [
        root / "README.md",
        root / "provider_01" / "record.json",
        deposit / "README.md",
        deposit / "MANIFEST.sha256",
    ]
    for path in untouched:
        assert after[path] == before[path], path


def test_the_status_table_must_list_every_partner_directory(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    gate.apply_banners(root)
    (root / "provider_03").mkdir()
    assert gate.violations(root) == [
        "docs/partners/README.md: '## Directory Index' has no row for provider_03",
        "docs/partners/README.md: '## Live Verification Status' has no row for "
        "provider_03",
    ]


def test_the_status_heading_must_exist(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    gate.apply_banners(root)
    readme = root / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace("## Live Verification", "## Old"),
        encoding="utf-8",
    )
    (error,) = gate.violations(root)
    assert "no '## Live Verification Status' heading" in error


README_PLANTS: dict[str, tuple[Callable[[Path], None], str]] = {
    "provider_02 vendor cell carries InferTheta and Vector3 (#218 defect)": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace(
                "| `provider_02` | **NexArt** |",
                "| `provider_02` | **InferTheta / NexArt / Vector3** |",
            ),
            encoding="utf-8",
        ),
        "row 'provider_02' has vendor '**InferTheta / NexArt / Vector3**', expected '**NexArt**'",
    ),
    "actuator_01 vendor cell misattributed to OpsCanvas": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace(
                "| `actuator_01` | **Archytan** |", "| `actuator_01` | **OpsCanvas** |"
            ),
            encoding="utf-8",
        ),
        "row 'actuator_01' has vendor '**OpsCanvas**', expected '**Archytan**'",
    ),
    "provider_07 role cell omits NormativeProvider (#218 defect)": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace(
                "Synchronous Normative Provider (`NormativeProvider`) — Bayesian Causal Suitability Oracle",
                "Graph Topology & Governance Schema Provider",
            ),
            encoding="utf-8",
        ),
        "row 'provider_07' role cell is missing `NormativeProvider`",
    ),
    "provider_02 role cell claims NormativeProvider": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace(
                "(`AttestationProvider`, CER)",
                "(`AttestationProvider`, `NormativeProvider`, CER)",
            ),
            encoding="utf-8",
        ),
        "row 'provider_02' role cell names `NormativeProvider`, which provider_02 does not implement",
    ),
    "actuator_01 documentation link is *(Reference)* instead of actuator_01/": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace("[`actuator_01/`](actuator_01/)", "*(Reference)*"),
            encoding="utf-8",
        ),
        "row 'actuator_01' has documentation link '*(Reference)*', expected '[`actuator_01/`](actuator_01/)'",
    ),
    "status table pairs provider_02 with InferTheta": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace("| `provider_02` NexArt |", "| `provider_02` InferTheta |"),
            encoding="utf-8",
        ),
        "row 'provider_02' has adapter label 'InferTheta', expected 'NexArt'",
    ),
    "directory index heading removed": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace("## Directory Index", "## Old Index"),
            encoding="utf-8",
        ),
        "no '## Directory Index' heading",
    ),
    "unknown partner directory created": (
        lambda root: (root / "vector3").mkdir(),
        "unknown partner directory 'vector3' (not in PARTNER_SLOTS)",
    ),
    "duplicate row in directory index": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace(
                "| `provider_01` | **FlowSignal** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_01/`](provider_01/) | [`src/integrations/provider_01/`](../../src/integrations/provider_01/) |",
                "| `provider_01` | **FlowSignal** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_01/`](provider_01/) | [`src/integrations/provider_01/`](../../src/integrations/provider_01/) |\n"
                "| `provider_01` | **FlowSignal** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_01/`](provider_01/) | [`src/integrations/provider_01/`](../../src/integrations/provider_01/) |",
            ),
            encoding="utf-8",
        ),
        "'## Directory Index' has duplicate row for provider_01",
    ),
    "duplicate row in status table": (
        lambda root: (root / "README.md").write_text(
            (root / "README.md")
            .read_text(encoding="utf-8")
            .replace(
                "| `provider_02` NexArt |",
                "| `provider_02` NexArt | Not run | none | none |\n| `provider_02` NexArt |",
            ),
            encoding="utf-8",
        ),
        "'## Live Verification Status' has duplicate row for provider_02",
    ),
}


@pytest.mark.parametrize("name", sorted(README_PLANTS))
def test_partner_readme_attribution_and_role_drift_is_reported(
    tmp_path: Path, name: str
) -> None:
    plant, expected = README_PLANTS[name]
    root = _readme_tree(tmp_path)
    assert gate.violations(root) == []
    plant(root)
    problems = gate.violations(root)
    assert any(expected in problem for problem in problems), problems


def test_partner_slots_match_adapter_classes_and_seam_factories() -> None:
    """PARTNER_SLOTS in check_partner_headers.py agrees with src/integrations/ and kernel factories."""
    partner_dirs = {p.name for p in gate.PARTNERS_ROOT.iterdir() if p.is_dir()}
    assert partner_dirs == set(gate.PARTNER_SLOTS)

    integrations_root = gate.REPO_ROOT / "src" / "integrations"
    integration_slots = {
        p.name
        for p in integrations_root.iterdir()
        if p.is_dir() and p.name.startswith(("provider_", "actuator_"))
    }
    # provider_09 is a planned adapter whose seam + factory live in estate_provider.py.
    assert integration_slots == set(gate.PARTNER_SLOTS) - {"provider_09"}

    for slot, spec in gate.PARTNER_SLOTS.items():
        if slot == "provider_09":
            assert spec.seams == ("EstateProvider",)
            continue
        mod = importlib.import_module(f"src.integrations.{slot}")
        classes = [
            getattr(mod, attr)
            for attr in getattr(mod, "__all__", dir(mod))
            if isinstance(getattr(mod, attr, None), type)
        ]
        implemented = frozenset(
            seam_name
            for seam_name, methods in _SEAM_METHODS.items()
            if any(all(hasattr(cls, method) for method in methods) for cls in classes)
        )
        assert implemented == frozenset(spec.seams), (
            f"{slot}: adapter classes implement {sorted(implemented)}, "
            f"PARTNER_SLOTS declares {sorted(spec.seams)}"
        )

    with pytest.raises(ValueError, match="AttestationProvider"):
        get_normative_provider("provider_02")
    with pytest.raises(ValueError, match="Unknown attestation provider"):
        _load_attestation_provider("provider_01")
