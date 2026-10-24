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

"""
Unit tests for src/gateway/governance/ingress/agp_policy_uploader.py.

All tests are hermetic — no GCP credentials or network calls required.
The _get_credentials() function and requests library are mocked.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Constants from the module under test (copy for assertions)
# ---------------------------------------------------------------------------
_AGP_CHAR_BUDGET = 5_000


# ---------------------------------------------------------------------------
# Helper: build a just-right policy text
# ---------------------------------------------------------------------------


def _policy_text(chars: int = 100) -> str:
    return "A" * chars


# ---------------------------------------------------------------------------
# Tests: _validate_policy_text
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestValidatePolicyText:
    """Tests for the internal _validate_policy_text() validator."""

    def test_empty_text_raises_value_error(self):
        """Empty (or whitespace-only) policy text raises ValueError."""
        from src.gateway.governance.ingress.agp_policy_uploader import (
            _validate_policy_text,
        )

        with pytest.raises(ValueError, match="empty"):
            _validate_policy_text("")

        with pytest.raises(ValueError, match="empty"):
            _validate_policy_text("   \n  ")

    def test_text_over_budget_raises_value_error(self):
        """Policy text exceeding _AGP_CHAR_BUDGET raises ValueError."""
        from src.gateway.governance.ingress.agp_policy_uploader import (
            _validate_policy_text,
        )

        with pytest.raises(ValueError, match="budget"):
            _validate_policy_text("X" * (_AGP_CHAR_BUDGET + 1))

    def test_text_with_truncated_sentinel_raises_value_error(self):
        """Policy text containing '# TRUNCATED' raises ValueError."""
        from src.gateway.governance.ingress.agp_policy_uploader import (
            _validate_policy_text,
        )

        with pytest.raises(ValueError, match="TRUNCATED"):
            _validate_policy_text("Some policy\n# TRUNCATED\nmore text")

    def test_valid_text_does_not_raise(self):
        """Valid policy text (non-empty, within budget, no sentinel) passes."""
        from src.gateway.governance.ingress.agp_policy_uploader import (
            _validate_policy_text,
        )

        _validate_policy_text("A valid policy statement about governance rules.")

    def test_text_at_exact_budget_is_valid(self):
        """Policy text of exactly _AGP_CHAR_BUDGET characters is accepted."""
        from src.gateway.governance.ingress.agp_policy_uploader import (
            _validate_policy_text,
        )

        _validate_policy_text("A" * _AGP_CHAR_BUDGET)


# ---------------------------------------------------------------------------
# Tests: upload_agp_policy — dry_run mode (no network)
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestUploadAgpPolicyDryRun:
    """Tests for upload_agp_policy() in dry_run=True mode."""

    def test_dry_run_returns_resource_name_string(self):
        """dry_run=True returns a resource name string without calling the API."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        result = upload_agp_policy(
            policy_text="A valid policy statement.",
            project="my-project",
            location="us-central1",
            dry_run=True,
        )

        assert isinstance(result, str)
        assert "my-project" in result
        assert "us-central1" in result
        assert "dry-run" in result

    def test_dry_run_uses_env_project_when_not_passed(self):
        """dry_run=True uses GOOGLE_CLOUD_PROJECT env var when project not passed."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        with patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "env-project"}):
            result = upload_agp_policy(
                policy_text="Valid policy.",
                dry_run=True,
            )

        assert "env-project" in result

    def test_dry_run_raises_if_no_project(self):
        """dry_run=True raises RuntimeError when no project can be resolved."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        env_without_project = {
            k: v for k, v in os.environ.items() if k != "GOOGLE_CLOUD_PROJECT"
        }
        with patch.dict(os.environ, env_without_project, clear=True):
            with pytest.raises(RuntimeError, match="project"):
                upload_agp_policy(policy_text="Valid.", dry_run=True)

    def test_dry_run_raises_for_empty_policy_text(self):
        """dry_run=True still validates policy text before returning."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        with pytest.raises(ValueError, match="empty"):
            upload_agp_policy(
                policy_text="",
                project="my-project",
                dry_run=True,
            )

    def test_dry_run_raises_for_oversize_policy_text(self):
        """dry_run=True rejects policy text that exceeds the character budget."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        with pytest.raises(ValueError, match="budget"):
            upload_agp_policy(
                policy_text="X" * (_AGP_CHAR_BUDGET + 1),
                project="my-project",
                dry_run=True,
            )

    def test_dry_run_with_policy_id_includes_id_path(self):
        """dry_run uses us-central1 when no explicit location is given."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        with patch.dict(os.environ, {"GOOGLE_CLOUD_LOCATION": "eu-west1"}):
            result = upload_agp_policy(
                policy_text="Policy text here.",
                project="proj",
                dry_run=True,
            )

        assert "eu-west1" in result


# ---------------------------------------------------------------------------
# Tests: upload_agp_policy — reads from file
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestUploadAgpPolicyFromFile:
    """Tests for upload_agp_policy() reading policy text from a file path."""

    def test_file_not_found_raises(self, tmp_path):
        """FileNotFoundError is raised when the path does not exist."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        nonexistent = tmp_path / "missing.txt"
        with pytest.raises(FileNotFoundError, match="not found"):
            upload_agp_policy(
                policy_text_path=str(nonexistent),
                project="p",
                dry_run=True,
            )

    def test_reads_policy_text_from_file(self, tmp_path):
        """Reads policy text from the file when policy_text is None."""
        from src.gateway.governance.ingress.agp_policy_uploader import upload_agp_policy

        policy_file = tmp_path / "policy.txt"
        policy_file.write_text("This is the governance policy text.", encoding="utf-8")

        result = upload_agp_policy(
            policy_text_path=str(policy_file),
            project="my-project",
            dry_run=True,
        )

        assert "my-project" in result


# ---------------------------------------------------------------------------
# Tests: _get_credentials
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGetCredentials:
    """Tests for _get_credentials() — GCP ADC wrapper."""

    def test_import_error_raises_runtime_error(self):
        """RuntimeError is raised when google.auth is not installed."""
        from src.gateway.governance.ingress.agp_policy_uploader import _get_credentials

        with patch.dict(
            "sys.modules", {"google.auth": None, "google.auth.transport.requests": None}
        ):
            with pytest.raises((RuntimeError, ImportError)):
                _get_credentials()

    def test_auth_exception_raises_runtime_error(self):
        """RuntimeError is raised when google.auth.default() raises an exception."""
        mock_google_auth = MagicMock()
        mock_google_auth.default.side_effect = Exception("no credentials")

        import sys

        original = sys.modules.get("google.auth")
        sys.modules["google.auth"] = mock_google_auth
        sys.modules["google.auth.transport.requests"] = MagicMock()

        try:
            from src.gateway.governance.ingress.agp_policy_uploader import (
                _get_credentials,
            )

            with pytest.raises(RuntimeError, match="credentials"):
                _get_credentials()
        finally:
            if original is None:
                sys.modules.pop("google.auth", None)
            else:
                sys.modules["google.auth"] = original


# ---------------------------------------------------------------------------
# Tests: verify_and_transition_gateway_mode (Module M3)
# ---------------------------------------------------------------------------

_AGENT_PRINCIPAL = "principal://agents.global.org-12345.system.id.goog/resources/aiplatform/projects/p/locations/l/reasoningEngines/1"


async def _accepting_cer_verifier(artifact):
    return True, "VERIFIED"


async def _refusing_cer_verifier(artifact):
    return False, "static_only_receipt"


@pytest.mark.unit
@pytest.mark.local
class TestGatewayEnforcementTransition:
    """Tests for GEAP 4-step DRY_RUN -> ENFORCED Agent Gateway transition gate."""

    def _build_valid_catalog(self):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            RegistryCatalog,
        )

        return RegistryCatalog(
            agents={
                _AGENT_PRINCIPAL: {
                    "display_name": "Advisor Agent",
                    "allowed_tools": ["lookup_customer"],
                    "roles": ["advisor"],
                }
            },
            fetched_at=1_700_000_000.0,
            registry_resource_name="projects/p/locations/l/agentRegistries/reg",
            mcp_servers={
                "urn:geap:mcp:crm-service": {
                    "display_name": "CRM MCP",
                    "interfaces": [{"url": "https://mcp.crm-service.internal/sse"}],
                    "tools": [],
                }
            },
            endpoints={
                "urn:geap:endpoint:pubsub": {
                    "display_name": "PubSub Endpoint",
                    "destination_urls": ["https://pubsub.googleapis.com"],
                }
            },
        )

    def _valid_bindings(self):
        return [
            {
                "role": "roles/iap.egressor",
                "target": "*",
                "members": [_AGENT_PRINCIPAL],
                "condition": {
                    "expression": 'resource.type == "networkservices" && destination.mcp.tool.name in ["lookup_customer"]'
                },
            }
        ]

    async def _transition(self, **cer_kwargs):
        from src.gateway.governance.ingress.agp_policy_uploader import (
            verify_and_transition_gateway_mode,
        )

        return await verify_and_transition_gateway_mode(
            gateway_id="cage-egress-gw-01",
            discovered_targets=["mcp.crm-service.internal", "pubsub.googleapis.com"],
            catalog=self._build_valid_catalog(),
            iap_bindings=self._valid_bindings(),
            **cer_kwargs,
        )

    @pytest.mark.asyncio
    async def test_transitions_to_enforced_when_all_gates_pass(self):
        seen: list[dict] = []

        async def verifier(artifact):
            seen.append(dict(artifact))
            return True, "VERIFIED"

        artifact = {"schema_version": "cage.skill.cer.v2", "skill_name": "s"}
        res = await self._transition(cer_artifacts=[artifact], cer_verifier=verifier)
        assert res.transition_allowed is True
        assert res.effective_mode == "ENFORCED"
        assert res.unregistered_targets == ()
        assert res.missing_iap_bindings == ()
        assert res.cer_verified is True
        assert res.blocking_reasons == ()
        assert seen == [artifact]

    @pytest.mark.asyncio
    async def test_blocks_transition_on_unregistered_target(self):
        from src.gateway.governance.ingress.agp_policy_uploader import (
            verify_and_transition_gateway_mode,
        )

        catalog = self._build_valid_catalog()
        discovered = ["mcp.crm-service.internal", "rogue-exfil.external.io"]
        bindings = [
            {
                "role": "roles/iap.egressor",
                "target": "*",
                "members": ["principal://agents.global.org-12345"],
                "condition": {"expression": 'resource.type == "networkservices"'},
            }
        ]

        res = await verify_and_transition_gateway_mode(
            gateway_id="cage-egress-gw-01",
            discovered_targets=discovered,
            catalog=catalog,
            iap_bindings=bindings,
            cer_artifacts=[{"skill_name": "s"}],
            cer_verifier=_accepting_cer_verifier,
        )
        assert res.transition_allowed is False
        assert res.effective_mode == "DRY_RUN"
        assert "rogue-exfil.external.io" in res.unregistered_targets

    @pytest.mark.asyncio
    async def test_blocks_transition_on_missing_cel_and_refused_cer(self):
        from src.gateway.governance.ingress.agp_policy_uploader import (
            verify_and_transition_gateway_mode,
        )

        catalog = self._build_valid_catalog()
        discovered = ["mcp.crm-service.internal"]
        # Binding has empty CEL expression
        bindings = [
            {
                "role": "roles/iap.egressor",
                "target": "mcp.crm-service.internal",
                "members": ["principal://agents.global.org-12345"],
                "condition": {"expression": ""},
            }
        ]

        res = await verify_and_transition_gateway_mode(
            gateway_id="cage-egress-gw-01",
            discovered_targets=discovered,
            catalog=catalog,
            iap_bindings=bindings,
            cer_artifacts=[{"skill_name": "s"}],
            cer_verifier=_refusing_cer_verifier,
        )
        assert res.transition_allowed is False
        assert res.effective_mode == "DRY_RUN"
        assert "mcp.crm-service.internal" in res.missing_iap_bindings
        assert res.cer_verified is False

    @pytest.mark.asyncio
    async def test_blocks_transition_without_cer_verifier(self):
        """A presence-only artifact no longer passes: a verifier is mandatory."""
        res = await self._transition(
            cer_artifacts=[{"status": "CERTIFIED", "signature": "sig-ed25519-ok"}]
        )
        assert res.transition_allowed is False
        assert res.effective_mode == "DRY_RUN"
        assert res.cer_verified is False
        assert any("No .cer verifier configured" in r for r in res.blocking_reasons)

    @pytest.mark.asyncio
    async def test_blocks_transition_with_failing_cer_verifier(self):
        res = await self._transition(
            cer_artifacts=[{"skill_name": "s"}], cer_verifier=_refusing_cer_verifier
        )
        assert res.transition_allowed is False
        assert res.effective_mode == "DRY_RUN"
        assert res.cer_verified is False
        assert res.blocking_reasons == (
            ".cer artifact[0] failed verifier: static_only_receipt",
        )

    @pytest.mark.asyncio
    async def test_blocks_transition_when_cer_verifier_raises(self):
        async def exploding_verifier(artifact):
            raise RuntimeError("key manifest unreachable")

        res = await self._transition(
            cer_artifacts=[{"skill_name": "s"}], cer_verifier=exploding_verifier
        )
        assert res.transition_allowed is False
        assert res.cer_verified is False
        assert res.blocking_reasons == (
            ".cer artifact[0] verifier raised RuntimeError.",
        )

    @pytest.mark.asyncio
    async def test_blocks_transition_when_verifier_result_is_not_true(self):
        async def truthy_verifier(artifact):
            return "VERIFIED", "truthy but not True"

        res = await self._transition(
            cer_artifacts=[{"skill_name": "s"}], cer_verifier=truthy_verifier
        )
        assert res.transition_allowed is False
        assert res.cer_verified is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("artifacts", [None, []])
    async def test_blocks_transition_without_cer_artifacts(self, artifacts):
        res = await self._transition(
            cer_artifacts=artifacts, cer_verifier=_accepting_cer_verifier
        )
        assert res.transition_allowed is False
        assert res.cer_verified is False
        assert any("No .cer artifacts provided" in r for r in res.blocking_reasons)

    @pytest.mark.asyncio
    async def test_blocks_transition_on_non_mapping_artifact(self):
        res = await self._transition(
            cer_artifacts=["not-a-receipt"], cer_verifier=_accepting_cer_verifier
        )
        assert res.transition_allowed is False
        assert res.blocking_reasons == (".cer artifact[0] is not a mapping.",)

    @pytest.mark.asyncio
    async def test_real_cer_verifier_gates_the_transition(self, tmp_path):
        """End to end: signed v2 receipts through `GcsSkillCertificationVerifier`."""
        from src.eval_harness import CerEvidenceLevel
        from src.eval_harness.static_linter import lint_skill_file
        from src.integrations.gcp_eval import (
            GcpSkillCertifier,
            GcsSkillCertificationVerifier,
        )
        from tests.fixtures.skill_certification import (
            SAFE_OPS_EVALS,
            SAFE_OPS_SKILL_MD,
            SAFE_OPS_WEAK_BASELINE_TRACES,
            SAFE_OPS_WITH_SKILL_TRACES,
            make_ed25519_signer_and_jwks,
            make_lift_report,
            write_json,
            write_text,
        )

        provider, jwks = make_ed25519_signer_and_jwks(tmp_path, "agp-cer-kid")
        certifier = GcpSkillCertifier(key_id="agp-cer-kid", kms_provider=provider)
        skill_md = write_text(tmp_path / "safe-ops" / "SKILL.md", SAFE_OPS_SKILL_MD)
        static_report = lint_skill_file(skill_md)
        paired = certifier.create_and_sign_receipt(
            skill_md_path=skill_md,
            static_report=static_report,
            stages_run=(0, 2),
            evidence_level=CerEvidenceLevel.PAIRED_TRACES,
            lift_report=make_lift_report(),
            evals_json_path=write_json(tmp_path / "evals.json", SAFE_OPS_EVALS),
            baseline_traces_path=write_json(
                tmp_path / "base.json", SAFE_OPS_WEAK_BASELINE_TRACES
            ),
            with_skill_traces_path=write_json(
                tmp_path / "skill.json", SAFE_OPS_WITH_SKILL_TRACES
            ),
        )
        static_only = certifier.create_and_sign_receipt(
            skill_md_path=skill_md,
            static_report=static_report,
            stages_run=(0,),
            evidence_level=CerEvidenceLevel.STATIC_ONLY,
        )
        verifier = GcsSkillCertificationVerifier(jwks)
        skill_store = {"safe-ops": skill_md.read_bytes()}

        async def cer_verifier(artifact):
            skill_bytes = skill_store.get(str(artifact.get("skill_name")))
            if skill_bytes is None:
                return False, "unknown_skill"
            return await verifier.verify_cer_receipt(
                artifact, expected_skill_md_bytes=skill_bytes
            )

        allowed = await self._transition(
            cer_artifacts=[paired.to_dict()], cer_verifier=cer_verifier
        )
        assert allowed.transition_allowed is True
        assert allowed.effective_mode == "ENFORCED"

        blocked = await self._transition(
            cer_artifacts=[paired.to_dict(), static_only.to_dict()],
            cer_verifier=cer_verifier,
        )
        assert blocked.transition_allowed is False
        assert blocked.blocking_reasons == (
            ".cer artifact[1] failed verifier: static_only_receipt",
        )

        presence_only = await self._transition(
            cer_artifacts=[{"status": "CERTIFIED", "signature": "sig-ed25519-ok"}],
            cer_verifier=cer_verifier,
        )
        assert presence_only.transition_allowed is False
        assert presence_only.cer_verified is False


pytestmark = [pytest.mark.unit, pytest.mark.local]
