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
from pathlib import Path
env_path = Path('.env')
if not env_path.exists():
    print(f"Warning: .env file not found at {env_path.absolute()} — skipping", file=__import__('sys').stderr)
else:
    with open(env_path) as f:
        text = f.read()
    for line in text.split('\n'):
        if 'GOOGLE_' in line or 'OIDC' in line or 'Workload Identity' in line:
            print(line)
