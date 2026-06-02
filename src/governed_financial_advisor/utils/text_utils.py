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

def strip_thinking_tags(text: str) -> str:
    """
    Removes <think>...</think> blocks from the text.
    Handles multiline content and ensures whitespace is trimmed.
    """
    if not text:
        return ""
    # Remove <think>...</think> (non-greedy)
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    
    # Handle unclosed <think> tags (e.g. if generation stopped mid-stream)
    # This will remove everything after <think> if the closing tag is missing.
    cleaned = re.sub(r'<think>.*', '', cleaned, flags=re.DOTALL)
    
    # Also handle standalone </think> if the opening tag was missed or split
    cleaned = re.sub(r'.*?</think>', '', cleaned, flags=re.DOTALL)
    
    return cleaned.strip()
