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
Finance-Specific Governance Constants
"""

HITL_CITATIONS: dict[str, str] = {
    "US_FED": "SR 26-2 §3.2 (Federal Reserve HITL SLA — 4 hours)",
    "EU_ECB": "DORA Art. 10 (ICT incident management — 2 hours for major incidents)",
    "APAC_MAS": "MAS FEAT §3.2 (human oversight of AI decisions — 1 hour)",
}

HITL_SLA_HOURS: dict[str, float] = {
    "US_FED": 4.0,
    "EU_ECB": 2.0,
    "APAC_MAS": 1.0,
}

PII_RETENTION_AUTHORITY: dict[str, str] = {
    "US_FED": "FISMA AU-11",
    "EU_ECB": "GDPR Art. 5(1)(e)",
    "APAC_MAS": "MAS Notice 655 §4.3",
}

INJECTION_CITATION: dict[str, str] = {
    "US_FED": "AI 600-1 §2.3 (prompt injection — US Federal posture)",
    "EU_ECB": "EU AI Act Art. 9 (risk management system — robustness)",
    "APAC_MAS": "MAS FEAT Principle 2 (Ethics — robustness against adversarial inputs)",
}
