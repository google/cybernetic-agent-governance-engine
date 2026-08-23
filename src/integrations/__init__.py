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
src/integrations — Third-Party Vendor Integration Packages
===========================================================

This directory contains isolated, self-contained integration packages
for external compliance and attestation vendors. Each subdirectory
is a complete vendor integration boundary:

  integrations/
  ├── provider_01/  — Normative compliance provider
  ├── provider_02/  — CER attestation + LangGraph adapter
  ├── provider_03/  — Decision governance provider
  ├── provider_04/  — Attestation provider + envelope mapper
  └── provider_05/  — Verifiable Execution Evidence Pack

Vendor packages MUST NOT introduce imports into the CAGE kernel.
All vendor code is loaded lazily via the provider factory in
``src/gateway/governance/normative_provider.py``.

Adding a new vendor
-------------------
1. Create ``src/integrations/{provider_XX}/``
2. Implement the ``NormativeProvider`` protocol (or vendor-specific surface)
3. Add ``__init__.py`` with clean re-exports
4. Register in ``get_normative_provider()`` factory (lazy import)
5. Add tests in ``src/integrations/{provider_XX}/tests/``
"""
