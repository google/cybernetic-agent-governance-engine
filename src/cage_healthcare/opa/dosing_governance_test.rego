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

package dosing.governance_test

import rego.v1

import data.dosing.governance

test_compliant_administer_dose_is_allowed if {
	inp := {
		"action": "administer_dose",
		"dose_mg": 250,
		"contraindication_present": false,
	}
	governance.allow with input as inp
}

test_compliant_prescribe_medication_without_contraindication_flag_is_allowed if {
	inp := {
		"action": "prescribe_medication",
		"dose_mg": 100,
	}
	governance.allow with input as inp
}

test_zero_dose_is_denied if {
	inp := {
		"action": "administer_dose",
		"dose_mg": 0,
	}
	not governance.allow with input as inp
}

test_dose_at_or_above_500mg_ceiling_is_denied if {
	inp := {
		"action": "administer_dose",
		"dose_mg": 500,
	}
	not governance.allow with input as inp
}

test_excessive_dose_is_denied if {
	inp := {
		"action": "adjust_dosage",
		"dose_mg": 750,
	}
	not governance.allow with input as inp
}

test_contraindication_present_is_denied if {
	inp := {
		"action": "administer_medication",
		"dose_mg": 125,
		"contraindication_present": true,
	}
	not governance.allow with input as inp
}

test_cross_domain_action_is_denied if {
	inp := {
		"action": "execute_trade",
		"dose_mg": 100,
	}
	not governance.allow with input as inp
}

test_empty_input_defaults_to_deny if {
	not governance.allow with input as {}
}
