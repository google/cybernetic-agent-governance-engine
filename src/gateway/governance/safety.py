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

# safety.py — backward-compatibility shim
# This module has been split into text_filter.py (stateless text safety)
# and cbf.py (stateful Redis-backed financial invariant).
# This shim re-exports all public symbols for backward compatibility.
from src.gateway.governance.text_filter import ac_keyword_scan
from src.gateway.governance.cbf import ControlBarrierFunction, safety_filter

__all__ = ["ac_keyword_scan", "ControlBarrierFunction", "safety_filter"]
