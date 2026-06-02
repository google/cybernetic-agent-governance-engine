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

import re

# Deterministic patterns for Zero-Trust Redaction (Defense-in-Depth)
PII_PATTERNS = {
    "SSN": r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "PHONE": r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b"
}

def scrub_pii(text: str) -> str:
    """
    Deterministic PII scrubbing utility.
    Transforms sensitive data into non-identifying tokens.
    """
    if not isinstance(text, str):
        return text
    
    scrubbed = text
    for entity, pattern in PII_PATTERNS.items():
        # Using specific REDACTED labels helps with audit reasoning
        scrubbed = re.sub(pattern, f"[REDACTED-{entity}-UCA-3]", scrubbed)
        
    return scrubbed
