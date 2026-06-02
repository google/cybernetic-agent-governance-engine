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
DEPRECATED: This module has been removed.

The local OPAClient stub is no longer used. All governance policy evaluation
is performed by the Gateway service via its OPA sidecar.

Any code that imports from this module must be updated to route requests
through the Gateway instead of calling OPA directly.
"""

raise ImportError(
    "governance.client is deprecated and has been removed. "
    "Policy evaluation must go through the Gateway service."
)
