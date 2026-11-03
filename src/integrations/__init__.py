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
  ├── provider_01/  — Synchronous normative compliance provider (FlowSignal)
  ├── provider_02/  — CER attestation provider + LangGraph callback (NexArt)
  ├── provider_03/  — Synchronous decision governance provider (Veritas)
  ├── provider_05/  — Execution warrant source & three-axiom attestation (VEIP)
  ├── provider_06/  — Synchronous agent integrity verifier (Guardian Cyber)
  ├── provider_07/  — Bayesian causal suitability normative oracle (InferTheta)
  ├── provider_08/  — Runtime evidence normative provider & Rekor custody (Verdict Systems)
  ├── actuator_01/  — Downstream mTLS execution actuator (Archytan)
  ├── actuator_02/  — Dynamic sandbox supervisor & OCSF ingestor (NVIDIA OpenShell)
  └── actuator_03/  — Out-of-band DPU hardware quarantine actuator (NVIDIA Sentry / DOCA)

Vendor packages MUST NOT introduce imports into the CAGE kernel.
All vendor code is loaded lazily via the allowlisted kernel seam factories
(``normative_provider.py``, ``attestation_aggregator.py``,
``warrant/source_factory.py``, ``estate_provider.py``,
``execution_actuator.py``, and ``quarantine_actuator.py``).

Adding a new vendor
-------------------
1. Create ``src/integrations/{provider_XX}/`` (or ``actuator_XX``)
2. Implement the corresponding seam protocol in ``src/gateway/governance/seams/``
3. Add ``__init__.py`` with clean re-exports
4. Register in the seam factory (lazy import) and ``docs/partners/README.md``
5. Add tests in ``tests/integrations/{provider_XX}/``
"""
