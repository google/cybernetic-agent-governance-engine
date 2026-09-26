import pytest
from src.gateway.governance.governor.pipeline import PROFILE_STAGES as PROD_PROFILES
from proof.model import PROFILE_STAGES as PROOF_PROFILES

@pytest.mark.unit
@pytest.mark.local
class TestFormalProfileParity:
    """Ensures the formal model profiles match production precisely."""

    def test_proof_profiles_match_production(self) -> None:
        """Proof profiles must exactly match production profiles."""
        assert set(PROOF_PROFILES.keys()) == set(PROD_PROFILES.keys()), "Profile names mismatch"

        for profile_name, prod_tiers in PROD_PROFILES.items():
            proof_tiers = PROOF_PROFILES[profile_name]
            assert proof_tiers == prod_tiers, f"Tiers mismatch for profile {profile_name}"
