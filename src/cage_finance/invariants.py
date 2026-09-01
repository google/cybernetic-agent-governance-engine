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

"""Finance domain safety barrier declarations.

Per PR C §7.4: barriers are declarative, not callable. The kernel compiles
(state_key, threshold_key, gamma) into the Lua script at invocation time.

This file contains NO executable safety logic — only data declarations that
parameterize the kernel's ControlBarrierFunction engine.
"""


class CashBarrier:
    """Finance domain barrier: h(x) = cash_balance - min_cash_balance.
    
    Declarative specification for the affine barrier that prevents
    the agent from depleting its cash reserves below the regulatory floor.
    
    The barrier algebra (h(x) = x - threshold) is evaluated atomically
    inside Redis via the Lua script in gateway/governance/safety/cbf_engine.py.
    This class only declares the parameters.
    """

    invariant_id = "finance.cash_balance"
    state_key = "safety:current_cash"
    threshold_key = "cbf.min_cash_balance"
    gamma = 0.5  # Must match THRESHOLDS.cbf.gamma — asserted at registration
