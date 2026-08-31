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

import logging
import os

from src.gateway.core.policy import OPAClient
from src.gateway.governance.generated_stpa_validator import (
    GeneratedSTPAValidator as STPAValidator,
)
from src.gateway.governance.symbolic_governor import SymbolicGovernor

logger = logging.getLogger("Gateway.Governance.Singletons")

# Singleton Instances
opa_client = OPAClient()
stpa_validator = STPAValidator()


symbolic_governor = SymbolicGovernor(
    opa_client=opa_client,
    stpa_validator=stpa_validator,
)

logger.info("✅ Governance Singletons Initialized.")
