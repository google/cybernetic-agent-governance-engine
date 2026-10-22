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

_OPEN_TAG = "<think>"
_CLOSE_TAG = "</think>"


def strip_thinking_tags(text: str) -> str:
    """Remove ``<think>...</think>`` blocks from ``text`` in linear O(N) time.

    Handles:
      - One or more complete ``<think>...</think>`` blocks (including multiline).
      - Unclosed trailing ``<think>...`` blocks (e.g., generation truncated mid-thought).
      - Orphan ``...</think>`` prefixes when the opening ``<think>`` tag was split or omitted.
    """
    if not text:
        return ""

    # 1. Remove all complete <think>...</think> blocks and any unclosed <think>... tail
    if _OPEN_TAG in text:
        parts: list[str] = []
        remaining = text
        while True:
            before, sep, after = remaining.partition(_OPEN_TAG)
            parts.append(before)
            if not sep:
                break
            _thought, close_sep, tail = after.partition(_CLOSE_TAG)
            if not close_sep:
                # Unclosed <think>: discard everything after <think>
                break
            remaining = tail
        cleaned = "".join(parts)
    else:
        cleaned = text

    # 2. Handle standalone </think> if the opening tag was missed or split
    if _CLOSE_TAG in cleaned:
        _, _, cleaned = cleaned.rpartition(_CLOSE_TAG)

    return cleaned.strip()
