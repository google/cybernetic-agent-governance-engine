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

package dosing.governance

import rego.v1

# Healthcare domain OPA policy stub
# Real policy would enforce contraindications, dosing ranges, protocol adherence

default allow := false

governed_dosing_actions := {
    "administer_dose",
    "prescribe_medication",
    "adjust_dosage",
    "administer_medication",
    "dose_order",
    "order_controlled_substance",
}

allow if {
    governed_dosing_actions[input.action]
    input.dose_mg > 0
    input.dose_mg < 500
    not input.contraindication_present
}
