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

"""null_signer.py — Local/Development Signer Implementation (Layer 1)"""

import asyncio
import hashlib
import json
from collections.abc import Callable
from typing import Any

from .signer import EvidenceSigner


class NullSigner(EvidenceSigner):
    """A synchronous no-op signer for local development and testing."""

    def enqueue(
        self,
        record_hash: str,
        payload: dict[str, Any],
        callback: Callable[[str, str], None] | None = None,
    ) -> None:
        if callback:
            dummy_sig = hashlib.sha256(json.dumps(payload).encode("utf-8")).hexdigest()
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon(callback, record_hash, dummy_sig)
            except RuntimeError:
                callback(record_hash, dummy_sig)

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def drain(self) -> int:
        return 0
