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
Test suite for code audit remediation fixes.

Validates fixes for the 7 issues discovered during documentation audit:
1. FTRA acronym (verified already correct)
2. AgwAdapter fail-closed authentication (SECURITY)
3. Empty BoundingContractConfig validation (SECURITY)
4. Healthcare plugin entry point (verified already present)
5. Stage migration completion
6. adapt_legacy_violations_to_findings documentation
7. Terminal registry v3.0 schema compliance (SECURITY)
"""

import json
import pytest
from pathlib import Path

from src.gateway.governance.ftra.bounding_contract import (
    BoundingContractConfig,
    BoundingContractEnforcer,
)
from src.gateway.governance.ingress.agw_adapter import AgwAdapter


# Issue #2: AgwAdapter fail-closed authentication
@pytest.mark.asyncio
@pytest.mark.local
async def test_agw_adapter_fails_closed_on_invalid_oidc():
    """Verify AgwAdapter returns success=False when OIDC validation fails."""
    adapter = AgwAdapter()
    
    # Test with missing token
    result = await adapter.process({
        "agent_id": "test-agent",
        "tool": {"name": "execute_trade", "parameters": {}},
        "auth": {"token": ""},  # Empty token
    })
    
    # Issue #2 fix: success must be False when identity_verified is False
    assert result.success is False, "success should be False when OIDC validation fails"
    assert result.identity_verified is False
    assert "OIDC token validation failed" in result.error


@pytest.mark.asyncio
@pytest.mark.local
async def test_agw_adapter_success_coupled_to_identity():
    """Verify AgwAdapter couples success to identity_verified (no hardcoded True)."""
    adapter = AgwAdapter()
    
    # Even with valid-looking request structure, no OIDC issuer means fail-closed
    result = await adapter.process({
        "agent_id": "test-agent",
        "tool": {"name": "execute_trade", "parameters": {"quantity": 100}},
        "auth": {"token": "fake-jwt-token"},
        "trace_id": "test-trace-123",
    })
    
    # Both success and identity_verified must be False
    assert result.success == result.identity_verified, (
        "success must match identity_verified (no decoupling)"
    )
    assert result.success is False


# Issue #3: Empty BoundingContractConfig validation
@pytest.mark.local
def test_empty_bounding_contract_config_rejected():
    """Verify BoundingContractEnforcer rejects empty configuration (fail-safe)."""
    # Empty config (no whitelists) should raise ValueError
    empty_config = BoundingContractConfig()
    
    with pytest.raises(ValueError, match="must specify at least one of"):
        BoundingContractEnforcer(empty_config)


@pytest.mark.local
def test_bounding_contract_requires_at_least_one_whitelist():
    """Verify at least one critical whitelist must be populated."""
    # Only allowed_instruments populated - should succeed
    config_with_instruments = BoundingContractConfig(
        allowed_instruments={"AAPL", "MSFT"}
    )
    enforcer = BoundingContractEnforcer(config_with_instruments)
    assert enforcer.config.allowed_instruments == {"AAPL", "MSFT"}
    
    # Only allowed_venues populated - should succeed
    config_with_venues = BoundingContractConfig(
        allowed_venues={"NYSE", "NASDAQ"}
    )
    enforcer = BoundingContractEnforcer(config_with_venues)
    assert enforcer.config.allowed_venues == {"NYSE", "NASDAQ"}


# Issue #5: Stage migration exports
@pytest.mark.local
def test_cbf_and_fiscal_stages_exported():
    """Verify CbfSafetyStage and FiscalLimitStage are exported from stages package."""
    from src.gateway.governance.pipeline.stages import (
        CbfSafetyStage,
        FiscalLimitStage,
        BoundedAutonomyStage,
        FtraBoundaryStage,
    )
    
    # Verify all expected stages are importable
    assert CbfSafetyStage is not None
    assert FiscalLimitStage is not None
    assert BoundedAutonomyStage is not None
    assert FtraBoundaryStage is not None
    
    # Verify stage names
    cbf = CbfSafetyStage()
    fiscal = FiscalLimitStage()
    assert cbf.name == "cbf_safety"
    assert fiscal.name == "fiscal_limit"


# Issue #6: adapt_legacy_violations_to_findings documentation
@pytest.mark.local
def test_adapt_legacy_violations_has_migration_docs():
    """Verify adapt_legacy_violations_to_findings has transitional status documented."""
    from src.gateway.governance.arbitration import adapt_legacy_violations_to_findings
    
    # Verify function has docstring explaining transitional nature
    assert adapt_legacy_violations_to_findings.__doc__ is not None
    docstring = adapt_legacy_violations_to_findings.__doc__
    
    assert "Issue #6 remediation" in docstring
    assert "transitional" in docstring.lower() or "migration" in docstring.lower()
    assert "substring" in docstring.lower()  # Documents substring matching approach


# Issue #7: Terminal registry v3.0 schema compliance
@pytest.mark.local
def test_terminal_registry_version_3_0():
    """Verify terminal registry uses v3.0 schema format."""
    registry_path = Path("config/ftra/terminal_registry.json")
    
    with open(registry_path) as f:
        registry = json.load(f)
    
    # Version must be 3.0 (not 2.0)
    assert registry["version"] == "3.0", "Registry must use v3.0 schema"
    
    # v3.0 requires domain field
    assert "domain" in registry, "v3.0 schema requires domain field"
    assert registry["domain"] == "finance"
    
    # Serial must be >= 2 (incremented from v2.0)
    assert registry["serial"] >= 2, "Serial must increment on version upgrade"
    
    # v3.0 schema-required fields
    assert "issued_at" in registry
    assert "expires_at" in registry
    assert "terminals" in registry


@pytest.mark.local
def test_terminal_registry_schema_validation():
    """Verify terminal registry validates against v3.0 schema."""
    import jsonschema
    
    registry_path = Path("config/ftra/terminal_registry.json")
    schema_path = Path("config/schemas/terminal_registry_schema.json")
    
    with open(registry_path) as f:
        registry = json.load(f)
    
    with open(schema_path) as f:
        schema = json.load(f)
    
    # Should validate without errors
    try:
        jsonschema.validate(instance=registry, schema=schema)
    except jsonschema.ValidationError as e:
        pytest.fail(f"Registry does not validate against v3.0 schema: {e.message}")


# Issue #1: FTRA acronym verification
@pytest.mark.local
def test_ftra_acronym_documentation_consistency():
    """Verify FTRA is consistently expanded as 'Forward-Looking Trajectory Reachability Analyzer'."""
    # This is a documentation audit - code grep found zero instances of the incorrect expansion
    # Test verifies the correct expansion is used in key source files
    
    from src.gateway.governance import ftra
    
    # Verify FTRA module docstring has correct expansion
    assert ftra.__doc__ is not None
    assert "Forward-Looking Trajectory Reachability Analyzer" in ftra.__doc__
    
    # Verify source file comments have correct expansion
    import inspect
    ftra_source = inspect.getsourcefile(ftra)
    assert ftra_source is not None
    
    with open(ftra_source.replace("__init__.py", "../constants.py")) as f:
        constants_content = f.read()
        # constants.py line 204 has the docstring with correct expansion
        assert "Forward-Looking Trajectory Reachability Analyzer" in constants_content
        assert "Financial Trading" not in constants_content  # Verify wrong expansion absent


# Issue #4: Healthcare plugin entry point verification
@pytest.mark.local
def test_healthcare_plugin_entry_point_registered():
    """Verify healthcare plugin has proper entry point in pyproject.toml."""
    pyproject_path = Path("pyproject.toml")
    
    # Read pyproject.toml manually (toml not in dependencies)
    with open(pyproject_path) as f:
        content = f.read()
    
    # Verify both plugins are present in [project.entry-points."cage.plugins"]
    assert '[project.entry-points."cage.plugins"]' in content
    assert 'finance = "cage_finance.plugin:FinanceCagePlugin"' in content
    assert 'healthcare = "cage_healthcare.plugin:HealthcareCagePlugin"' in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
