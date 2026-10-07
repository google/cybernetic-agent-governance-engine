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

"""Regional overlay of ``domains.<section>`` thresholds (kernel, domain-agnostic).

* The merge is a deep overlay with annotation keys stripped, and it fails
  closed on a missing file, a regional section without a global counterpart,
  or a shape change.
* Unknown keys introduced by a region fail governor assembly through the
  domain's own schema.
* Every region's effective finance values (confidence floor, CBF gamma,
  drawdown, consensus, STPA UCA-5/UCA-6/FIN-1/FIN-2) are the ones its
  baseline declares; the universal confidence band is identical everywhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.cage_finance.thresholds import FinanceThresholds
from src.gateway.governance.contracts import PluginContribution
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import (
    DecisionFlags,
    GovernorAssemblyError,
    assemble_governor,
)
from src.gateway.governance.jurisdiction import resolve_jurisdiction
from src.gateway.governance.schemas import thresholds as thresholds_module
from src.gateway.governance.schemas.regional_overlay import (
    REGIONAL_THRESHOLDS_DIR,
    RegionalOverlayError,
    load_regional_domains,
    overlay_domains,
)
from src.gateway.governance.schemas.thresholds import (
    GovernanceThresholds,
    load_and_validate_thresholds,
)
from tests.fixtures.governor import allow_opa, clean_stpa

pytestmark = [pytest.mark.unit, pytest.mark.local]

REGIONS = ("US_FED", "EU_ECB", "APAC_MAS")


# ── Merge semantics ──────────────────────────────────────────────────────────


def test_overlay_deep_merges_and_keeps_unset_global_values() -> None:
    base = {"alpha": {"limits": {"low": 1, "high": 9}, "mode": "a", "tags": [1, 2]}}
    overlay = {"alpha": {"limits": {"high": 5}, "tags": [3]}}

    merged = overlay_domains(base, overlay)

    assert merged == {
        "alpha": {"limits": {"low": 1, "high": 5}, "mode": "a", "tags": [3]}
    }


def test_overlay_does_not_mutate_its_inputs() -> None:
    base = {"alpha": {"limits": {"high": 9}}}
    overlay = {"alpha": {"limits": {"high": 5}}}

    overlay_domains(base, overlay)

    assert base == {"alpha": {"limits": {"high": 9}}}
    assert overlay == {"alpha": {"limits": {"high": 5}}}


def test_overlay_strips_annotation_keys_at_every_level() -> None:
    base = {"alpha": {"_comment": "g", "limits": {"high": 9, "_comment_high": "g"}}}
    overlay = {"_note": "r", "alpha": {"_comment": "r", "limits": {"_why": "r"}}}

    assert overlay_domains(base, overlay) == {"alpha": {"limits": {"high": 9}}}


def test_overlay_without_regional_sections_is_the_global_tree() -> None:
    base = {"alpha": {"x": 1}, "beta": {"y": 2}}
    assert overlay_domains(base, {}) == base


def test_overlay_rejects_section_absent_from_global() -> None:
    with pytest.raises(RegionalOverlayError, match="no global counterpart"):
        overlay_domains({"alpha": {"x": 1}}, {"gamma": {"x": 2}})


@pytest.mark.parametrize(
    ("base", "overlay"),
    [
        ({"alpha": {"limits": {"high": 9}}}, {"alpha": {"limits": 5}}),
        ({"alpha": {"high": 9}}, {"alpha": {"high": {"value": 5}}}),
    ],
    ids=["scalar-over-object", "object-over-scalar"],
)
def test_overlay_rejects_shape_change(base: Any, overlay: Any) -> None:
    with pytest.raises(RegionalOverlayError, match="changes shape"):
        overlay_domains(base, overlay)


# ── Regional file loading ────────────────────────────────────────────────────


def test_missing_regional_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(RegionalOverlayError, match="cannot read"):
        load_regional_domains("XX_NOWHERE", tmp_path)


def test_malformed_regional_file_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "XX_BASELINE.json").write_text("{not json")
    with pytest.raises(RegionalOverlayError, match="cannot read"):
        load_regional_domains("XX", tmp_path)


@pytest.mark.parametrize(
    "domains", [["finance"], {"finance": 0.97}], ids=["list", "scalar-section"]
)
def test_regional_domains_must_be_object_of_objects(
    tmp_path: Path, domains: Any
) -> None:
    (tmp_path / "XX_BASELINE.json").write_text(json.dumps({"domains": domains}))
    with pytest.raises(RegionalOverlayError, match="must be an object"):
        load_regional_domains("XX", tmp_path)


def test_regional_file_without_domains_overlays_nothing(tmp_path: Path) -> None:
    (tmp_path / "XX_BASELINE.json").write_text(json.dumps({"_hitl": {}}))
    assert load_regional_domains("XX", tmp_path) == {}


@pytest.mark.parametrize("region", REGIONS)
def test_regional_baselines_carry_no_flat_finance_sections(region: str) -> None:
    """Finance values live under domains.finance, the only overlaid namespace."""
    raw = json.loads((REGIONAL_THRESHOLDS_DIR / f"{region}_BASELINE.json").read_text())
    flat = {"cbf", "drawdown", "stpa", "consensus", "confidence"} & raw.keys()
    assert not flat, (
        f"{region}: top-level finance sections {sorted(flat)} are never read"
    )


# ── Effective values per region (all four groups) ────────────────────────────

_EXPECTED: dict[str, dict[str, float | bool | str]] = {
    "US_FED": {
        "confidence.min_trade_confidence.value": 0.95,
        "confidence.min_trade_confidence.requires_warrant": False,
        "cbf.gamma": 0.5,
        "cbf.min_cash_balance": 1000.0,
        "drawdown.limit": 0.05,
        "consensus.threshold_usd": 10000.0,
        "stpa.uca5_drawdown_threshold_pct": 4.5,
        "stpa.uca6_max_order_volume_fraction": 0.01,
        "stpa.max_sell_portfolio_fraction": 0.1,
        "stpa.max_latency_ms": 200.0,
    },
    "EU_ECB": {
        "confidence.min_trade_confidence.value": 0.97,
        "confidence.min_trade_confidence.requires_warrant": True,
        "confidence.min_trade_confidence.governing_version": "cage-policy-2.1.0",
        "cbf.gamma": 0.6,
        "cbf.min_cash_balance": 1000.0,
        "drawdown.limit": 0.04,
        "consensus.threshold_usd": 7500.0,
        "stpa.uca5_drawdown_threshold_pct": 3.5,
        "stpa.uca6_max_order_volume_fraction": 0.005,
        "stpa.max_sell_portfolio_fraction": 0.08,
        "stpa.max_latency_ms": 150.0,
    },
    "APAC_MAS": {
        "confidence.min_trade_confidence.value": 0.96,
        "confidence.min_trade_confidence.requires_warrant": False,
        "cbf.gamma": 0.55,
        "cbf.min_cash_balance": 1000.0,
        "drawdown.limit": 0.045,
        "consensus.threshold_usd": 8500.0,
        "stpa.uca5_drawdown_threshold_pct": 4.0,
        "stpa.uca6_max_order_volume_fraction": 0.008,
        "stpa.max_sell_portfolio_fraction": 0.09,
        "stpa.max_latency_ms": 175.0,
    },
}


@pytest.mark.parametrize("region", REGIONS)
def test_effective_finance_values_per_region(region: str) -> None:
    thresholds = load_and_validate_thresholds(region=region)

    assert thresholds.region == region
    for path, expected in _EXPECTED[region].items():
        assert thresholds.resolve(f"domains.finance.{path}") == expected, (region, path)
    # The effective section is what the finance schema validates at assembly.
    FinanceThresholds.model_validate(thresholds.domains["finance"])


@pytest.mark.parametrize("region", REGIONS)
def test_universal_confidence_band_is_region_neutral(region: str) -> None:
    """The kernel band (EV-1/EV-2) never takes a regional value."""
    band = load_and_validate_thresholds(region=region).confidence
    assert band.agent_threshold == 0.95
    assert band.defer_floor == 0.70
    assert band.min_score == 0.95


def test_global_finance_section_is_the_us_fed_effective_section() -> None:
    """US_FED states only CTRL_AGT_001; every other value is the global one."""
    raw = json.loads(
        (
            Path(thresholds_module.__file__).parents[4]
            / "config"
            / "governance_thresholds.json"
        ).read_text()
    )
    global_finance = overlay_domains(raw["domains"], {})["finance"]
    assert (
        load_and_validate_thresholds(region="US_FED").domains["finance"]
        == global_finance
    )


def test_process_thresholds_use_the_active_region() -> None:
    """Hermetic runs are pinned to US_FED; THRESHOLDS carries that overlay."""
    from src.gateway.governance.schemas.thresholds import THRESHOLDS

    assert THRESHOLDS.region == "US_FED"
    assert "_comment" not in THRESHOLDS.domains["finance"]


# ── Fail closed at assembly on unknown keys ──────────────────────────────────


class _SectionPlugin:
    """Declares only a threshold section, validated by the real finance schema."""

    api_version = "2.0"
    name = "finance"
    domain_config = None

    def contribute(self) -> PluginContribution:
        return PluginContribution(
            domain="finance", threshold_sections={"finance": FinanceThresholds}
        )


def _assemble_with_overlay(
    monkeypatch: pytest.MonkeyPatch, regional_finance: dict[str, Any]
) -> Any:
    base = load_and_validate_thresholds(region="US_FED")
    effective = base.model_copy(
        update={"domains": overlay_domains(base.domains, {"finance": regional_finance})}
    )
    assert isinstance(effective, GovernanceThresholds)
    monkeypatch.setattr(thresholds_module, "THRESHOLDS", effective)
    return _assemble(resolve_jurisdiction("US_FED"))


def _assemble(jurisdiction: Any = None) -> Any:
    return assemble_governor(
        [_SectionPlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=False, narrow=False),
        jurisdiction=jurisdiction,
    )


@pytest.mark.parametrize(
    "regional_finance",
    [
        {"confidence": {"min_trade_confidnce": 0.97}},
        {"cbf": {"gama": 0.6}},
        {"stpa": {"uca7_unknown": 1.0}},
        {"surprise": {"x": 1}},
    ],
    ids=["typo-confidence", "typo-cbf", "unknown-stpa-key", "unknown-group"],
)
def test_unknown_regional_key_fails_assembly(
    monkeypatch: pytest.MonkeyPatch, regional_finance: dict[str, Any]
) -> None:
    with pytest.raises(GovernorAssemblyError, match="failed validation"):
        _assemble_with_overlay(monkeypatch, regional_finance)


@pytest.mark.parametrize(
    "regional_finance",
    [
        {"confidence": {"min_trade_confidence": {"value": 1.5}}},
        {"confidence": {"min_trade_confidence": {"requires_warrant": True}}},
        {"confidence": {"min_trade_confidence": {"requires_warrant": "yes"}}},
        {"cbf": {"gamma": 0.0}},
        {"drawdown": {"limit": "4%"}},
    ],
    ids=[
        "confidence-above-one",
        "warranted-without-governing-version",
        "requires-warrant-not-a-bool",
        "gamma-zero",
        "drawdown-not-a-number",
    ],
)
def test_invalid_regional_value_fails_assembly(
    monkeypatch: pytest.MonkeyPatch, regional_finance: dict[str, Any]
) -> None:
    with pytest.raises(GovernorAssemblyError, match="failed validation"):
        _assemble_with_overlay(monkeypatch, regional_finance)


def test_valid_regional_override_assembles(monkeypatch: pytest.MonkeyPatch) -> None:
    governor = _assemble_with_overlay(
        monkeypatch, {"confidence": {"min_trade_confidence": {"value": 0.99}}}
    )
    assert governor is not None


# ── Fail closed at assembly on a thresholds/jurisdiction region mismatch ─────

_REGIONS = ("APAC_MAS", "EU_ECB", "US_FED")


@pytest.mark.parametrize(
    ("thresholds_region", "jurisdiction_region"),
    [(t, j) for t in _REGIONS for j in _REGIONS if t != j],
)
def test_region_mismatch_fails_assembly(
    monkeypatch: pytest.MonkeyPatch, thresholds_region: str, jurisdiction_region: str
) -> None:
    """An EU jurisdiction must never assemble on another region's limits."""
    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        load_and_validate_thresholds(region=thresholds_region),
    )
    with pytest.raises(GovernorAssemblyError, match="region mismatch") as exc:
        _assemble(resolve_jurisdiction(jurisdiction_region))
    assert thresholds_region in str(exc.value)
    assert jurisdiction_region in str(exc.value)


@pytest.mark.parametrize("region", _REGIONS)
def test_matching_explicit_region_assembles(
    monkeypatch: pytest.MonkeyPatch, region: str
) -> None:
    monkeypatch.setattr(
        thresholds_module, "THRESHOLDS", load_and_validate_thresholds(region=region)
    )
    governor = _assemble(resolve_jurisdiction(region))
    assert governor.components.jurisdiction.region == region


def test_default_jurisdiction_matches_pinned_region(each_region: str) -> None:
    """``jurisdiction=None`` resolves the active region, which the thresholds share."""
    assert thresholds_module.THRESHOLDS.region == each_region
    governor = _assemble()
    assert governor.components.jurisdiction.region == each_region
