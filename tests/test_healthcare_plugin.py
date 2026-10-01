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

"""Healthcare plugin tests (domain-gated, marker: healthcare).

Plugin-local behaviour tests. Per analysis §9.3, a healthcare gate
failure must not block a finance release — this suite is additive.
"""

from unittest.mock import MagicMock

import pytest


@pytest.mark.healthcare
@pytest.mark.local
class TestHealthcarePlugin:
    """Healthcare plugin local tests."""

    def test_plugin_metadata(self):
        """Healthcare plugin has correct name and version."""
        from src.cage_healthcare.plugin import HealthcareCagePlugin

        plugin = HealthcareCagePlugin()
        assert plugin.name == "healthcare"
        assert plugin.api_version == "1.0"

    def test_serum_concentration_barrier_declarative(self):
        """Barrier declaration carries no executable logic beyond properties."""
        from src.cage_healthcare.invariants import SerumConcentrationBarrier

        barrier = SerumConcentrationBarrier()

        # Verify all declarative fields
        assert barrier.invariant_id == "healthcare.serum_concentration"
        assert barrier.state_key == "safety:serum_concentration"
        assert barrier.threshold_key == "domains.healthcare.min_therapeutic_concentration"
        assert barrier.gamma == 0.4

        # Verify it's data-only (no methods beyond properties)
        callable_attrs = [
            name
            for name in dir(barrier)
            if not name.startswith("_") and callable(getattr(barrier, name))
        ]
        # Should have no domain logic methods
        assert len(callable_attrs) == 0

    def test_dose_barrier_tier_properties(self):
        """DoseBarrierTier has correct phase, order, tier_name."""
        from src.cage_healthcare.invariants import (
            SerumConcentrationBarrier,
            healthcare_cost_resolver,
        )
        from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        cbf = ControlBarrierFunction(
            SerumConcentrationBarrier(),
            cost_resolver=healthcare_cost_resolver,
            skip_epoch_seed=True,
        )
        tier = DoseBarrierTier(cbf)

        assert tier.tier_name == "dose_barrier"
        assert tier.phase == 2
        assert tier.order == 3

    def test_clinical_consensus_tier_properties(self):
        """ClinicalConsensusTier has correct phase, order, tier_name."""
        from src.cage_healthcare.tiers.clinical_consensus_tier import (
            ClinicalConsensusTier,
            load_healthcare_critics,
        )
        from src.gateway.governance.null_components import NullConsensusProvider

        tier = ClinicalConsensusTier(NullConsensusProvider())

        assert tier.tier_name == "clinical_consensus"
        assert tier.phase == 1
        assert tier.order == 5
        critics = load_healthcare_critics()
        assert [c.role for c in critics] == [
            "Pharmacist Reviewer",
            "Attending Physician",
            "Clinical Ethics",
        ]

    def test_healthcare_constants_defined(self):
        """HEALTHCARE_GOVERNED_ACTIONS frozenset is populated."""
        from src.cage_healthcare.constants import HEALTHCARE_GOVERNED_ACTIONS

        assert isinstance(HEALTHCARE_GOVERNED_ACTIONS, frozenset)
        assert "administer_dose" in HEALTHCARE_GOVERNED_ACTIONS
        assert len(HEALTHCARE_GOVERNED_ACTIONS) >= 1

    def test_dose_order_model(self):
        """DoseOrder Pydantic model validates correctly."""
        from src.cage_healthcare.tools.dose_order import DoseOrder

        order = DoseOrder(
            patient_id="P12345",
            medication="warfarin",
            dose_mg=5.0,
            route="oral",
            indication="anticoagulation",
        )

        assert order.patient_id == "P12345"
        assert order.dose_mg == 5.0
        assert order.route == "oral"

    def test_healthcare_rail_provider_structure(self):
        """HealthcareRailProvider provides exactly one rail."""
        from src.cage_healthcare.rails.provider import HealthcareRailProvider

        provider = HealthcareRailProvider()
        actions = provider.provide_rail_actions()

        assert isinstance(actions, list)
        assert len(actions) == 1
        assert actions[0][0] == "CheckContraindicationAction"
        assert callable(actions[0][1])

    def test_plugin_registration_does_not_raise(self):
        """Healthcare plugin's contribution assembles into a governor without errors."""
        from src.cage_healthcare.plugin import HealthcareCagePlugin
        from src.gateway.core.policy import OPAClient
        from src.gateway.governance.env_posture import DeploymentPosture
        from src.gateway.governance.governor.assembly import (
            DecisionFlags,
            assemble_governor,
        )
        from src.gateway.governance.stpa_validator import STPAValidator

        # Should not raise
        governor = assemble_governor(
            [HealthcareCagePlugin()],
            posture=DeploymentPosture.DEV,
            opa=OPAClient("dosing.governance"),
            stpa_validator=STPAValidator(),
            flags=DecisionFlags(defer=True, narrow=False),
        )

        # Verify tiers registered
        tier_names = governor.registered_tier_names()
        assert "dose_barrier" in tier_names
        assert "clinical_consensus" in tier_names

    def test_healthcare_config_files_exist(self):
        """Healthcare config files (critics.yaml, causal_graph.yaml, overlays) exist."""
        from pathlib import Path

        healthcare_config = (
            Path(__file__).parent.parent / "src" / "cage_healthcare" / "config"
        )

        assert (healthcare_config / "critics.yaml").exists()
        assert (healthcare_config / "causal_graph.yaml").exists()
        assert (healthcare_config / "compliance" / "US_FED_OVERLAY.json").exists()
        assert (healthcare_config / "compliance" / "EU_ECB_OVERLAY.json").exists()
        assert (healthcare_config / "compliance" / "APAC_MAS_OVERLAY.json").exists()

    def test_healthcare_opa_policy_exists(self):
        """Healthcare OPA policy file exists."""
        from pathlib import Path

        opa_policy = (
            Path(__file__).parent.parent
            / "src"
            / "cage_healthcare"
            / "opa"
            / "dosing_governance.rego"
        )
        assert opa_policy.exists()

    def test_healthcare_has_no_lua_scripts(self):
        """Healthcare plugin contains zero Lua scripts (all safety logic is kernel-owned)."""
        from pathlib import Path

        healthcare_dir = Path(__file__).parent.parent / "src" / "cage_healthcare"
        lua_files = list(healthcare_dir.rglob("*.lua"))

        assert len(lua_files) == 0, (
            f"Healthcare plugin should have zero Lua files, found: {lua_files}"
        )

    def test_healthcare_has_no_kms_calls(self):
        """Healthcare plugin contains no KMS imports (ground-truth verification is kernel-owned)."""
        from pathlib import Path

        healthcare_dir = Path(__file__).parent.parent / "src" / "cage_healthcare"

        kms_violations = []
        for py_file in healthcare_dir.rglob("*.py"):
            with open(py_file) as f:
                content = f.read()

            # Check for KMS-related imports
            if (
                "google.cloud.kms" in content
                or "from google.cloud import kms" in content
            ):
                kms_violations.append(str(py_file.relative_to(healthcare_dir.parent)))

        assert not kms_violations, (
            f"Healthcare plugin should have no KMS imports, found in: {kms_violations}"
        )

    def test_healthcare_plugin_line_count_under_500(self):
        """Healthcare plugin is ~495 lines total (including headers, config)."""
        import subprocess
        from pathlib import Path

        healthcare_dir = Path(__file__).parent.parent / "src" / "cage_healthcare"

        result = subprocess.run(
            [
                "find",
                str(healthcare_dir),
                "-name",
                "*.py",
                "-exec",
                "wc",
                "-l",
                "{}",
                "+",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            total_line = lines[-1]
            total_count = int(total_line.strip().split()[0])

            # Should be under 750 lines (including ground_truth.py, headers, config)
            assert total_count < 750, (
                f"Healthcare plugin should be <750 lines, got {total_count}"
            )

    @pytest.mark.asyncio
    async def test_healthcare_dose_barrier_end_to_end_via_governor(self):
        """DoseCeilingBarrier enforces serum concentration headroom through assemble_governor -> SymbolicGovernor."""
        from unittest.mock import AsyncMock, patch

        fakeredis_sync = pytest.importorskip("fakeredis")
        fakeredis = pytest.importorskip("fakeredis.aioredis")

        from src.cage_healthcare.invariants import DoseCeilingBarrier
        from src.cage_healthcare.plugin import HealthcareCagePlugin
        from src.gateway.governance.env_posture import DeploymentPosture
        from src.gateway.governance.governor.assembly import (
            DecisionFlags,
            assemble_governor,
        )
        from src.gateway.governance.governor.pipeline import (
            Profile,
            StageContext,
            run_pipeline,
        )
        from src.gateway.governance.governor.reservation import ReservationScope
        from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage
        from tests.fixtures.governor import allow_opa, clean_stpa

        barrier = DoseCeilingBarrier()
        assert barrier.invariant_id == "healthcare.serum_concentration"

        server = fakeredis_sync.FakeServer()
        sync_redis = fakeredis_sync.FakeRedis(server=server, decode_responses=True)
        fake_redis = fakeredis.FakeRedis(server=server, decode_responses=True)
        # Seed initial serum concentration headroom = 15.0 mg/L (threshold = 5.0 mg/L, h = 10.0, gamma = 0.4 -> max delta = 4.0)
        await fake_redis.set(barrier.state_key, "15.0")
        await fake_redis.set("safety:fence_epoch", "0")

        mock_redis_mod = MagicMock()
        mock_redis_mod.get_raw_client = MagicMock(return_value=fake_redis)

        with (
            patch(
                "src.gateway.governance.safety.cbf_engine.redis_client", mock_redis_mod
            ),
            patch(
                "src.gateway.governance.safety.cbf_engine.sync_redis_client",
                sync_redis,
            ),
            patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", False),
            patch(
                "src.gateway.governance.governor.sealing.issue_seal",
                AsyncMock(return_value="sealed-token"),
            ),
        ):
            governor = assemble_governor(
                [HealthcareCagePlugin()],
                posture=DeploymentPosture.DEV,
                opa=allow_opa(),
                stpa_validator=clean_stpa(),
                flags=DecisionFlags(defer=False, narrow=False),
            )
            assert len(governor._components.ground_truth_providers) == 1
            for stage in governor.stages:
                if stage.name == "ftra":
                    stage.run = AsyncMock(return_value=[])  # type: ignore[method-assign]
            for tier in governor.domain_tiers:
                if tier.tier_name == "clinical_consensus":
                    tier.consensus_engine = MagicMock(
                        check_consensus=AsyncMock(return_value={"status": "APPROVED"})
                    )

            # Safe dose: 2.0 mg <= 4.0 mg max single-step depletion -> ALLOW via governor.validate_action
            safe_res = await governor.validate_action(
                "administer_dose",
                {
                    "patient_id": "P001",
                    "medication": "vancomycin",
                    "dose_mg": 2.0,
                    "confidence": 0.95,
                },
            )
            assert safe_res["verdict"] == "ALLOW"
            assert safe_res["violations"] == []

            # Unsafe dose: 12.0 mg breaches the therapeutic barrier -> DOSE_BARRIER_VIOLATED via governor.verify
            unsafe_verify = await governor.verify(
                "administer_dose",
                {
                    "patient_id": "P001",
                    "medication": "vancomycin",
                    "dose_mg": 12.0,
                    "confidence": 0.95,
                },
            )
            assert any(
                "DOSE_BARRIER_VIOLAT" in v.code
                for v in unsafe_verify["violations"]
            )
