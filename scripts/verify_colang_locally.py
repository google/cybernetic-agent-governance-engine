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

import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

from src.gateway.governance.nemo.manager import load_rails


def test_colang_syntax():
    print("🔍 Verifying Colang syntax in config/rails/...")
    try:
        # Attempt to load rails
        load_rails()
        print("✅ Colang syntax is VALID.")
        return 0
    except Exception as e:
        print("\n❌ Colang syntax is INVALID.")
        print(f"Error details: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(test_colang_syntax())
