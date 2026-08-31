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

import time

import pytest

from src.gateway.infrastructure.privacy import scrub_pii


@pytest.mark.local
def test_email_redacted():
    assert "[REDACTED-EMAIL-UCA-3]" in scrub_pii("reach me at user@example.com")


@pytest.mark.local
def test_multi_label_email_redacted():
    assert "[REDACTED-EMAIL-UCA-3]" in scrub_pii(
        "first.last+tag@mail.sub.example.co.uk"
    )


@pytest.mark.local
def test_clean_text_unchanged():
    assert scrub_pii("no pii in this line") == "no pii in this line"


@pytest.mark.local
def test_email_pattern_no_quadratic_backtracking():
    # "a@a.a.a.…!" has no valid TLD and used to trigger O(n^2) backtracking in
    # the unbounded email regex. scrub_pii runs inline on unauthenticated
    # /v1/chat/completions message content, so this is a pre-auth stall vector.
    # With length-bounded quantifiers the scan is linear.
    payload = "a@" + "a." * 60_000 + "!"
    start = time.perf_counter()
    result = scrub_pii(payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, (
        f"scrub_pii took {elapsed:.2f}s — regex backtracking regressed"
    )
    assert result == payload  # no email present, nothing redacted
