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

"""Healthcare domain action names and their declared consequence magnitudes."""

from src.gateway.governance.contracts import ConsequenceMagnitude, MagnitudePath

# Healthcare-governed actions (T-D5)
HEALTHCARE_GOVERNED_ACTIONS = frozenset(
    {"administer_dose", "prescribe_medication", "adjust_dosage", "dose_order"}
)

# Always convene consensus.
HIGH_STAKES_CLINICAL_ACTIONS: frozenset[str] = frozenset(
    {"administer_medication", "override_contraindication", "order_controlled_substance"}
)
# Equals the FTRA registry's terminals (config/ftra/terminal_registry.json).
REGISTERED_ACTIONS = HEALTHCARE_GOVERNED_ACTIONS | HIGH_STAKES_CLINICAL_ACTIONS

#: A dose: ``dose_mg``, a float number of milligrams (``DoseOrder``; the
#: domain's magnitude extractor reads the same key). Six minor-unit digits
#: are whole nanograms: real doses go below a microgram (calcitriol 0.25 micrograms is
#: 0.00025 mg), so whole micrograms would refuse them as dust.
DOSE_MG = MagnitudePath(("dose_mg",), minor_unit_digits=6)

#: Declared for the actions that give, prescribe or order a dose, for which a
#: zero dose is no dose (``DoseOrder.dose_mg`` is ``gt=0``). Deliberately
#: undeclared, so refused wherever a consequence is checked (the EU_ECB FRIA
#: pre-flight, minting, consumption):
#:
#: * ``adjust_dosage``: no code defines its payload, and a zero or negative
#:   change may be a legitimate reduction or stop, which the kernel's
#:   strictly-positive rule would refuse;
#: * ``override_contraindication``: an override decision; no code defines
#:   whether its payload carries a dose.
#:
#: Neither has a tool or an actuator; both stay reachable outside EU_ECB.
_DOSED_ACTIONS = REGISTERED_ACTIONS - {"adjust_dosage", "override_contraindication"}
CONSEQUENCE_MAGNITUDES: tuple[ConsequenceMagnitude, ...] = tuple(
    ConsequenceMagnitude(action, (DOSE_MG,)) for action in sorted(_DOSED_ACTIONS)
)
