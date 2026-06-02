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
from pathlib import Path

HEADER = """# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# limitations under the License.

"""

TS_HEADER = HEADER.replace("#", "//")

def patch_files():
    for root_dir in ["src", "tests", "deployment"]:
        for path in Path(root_dir).rglob("*"):
            if path.suffix in [".py", ".ts", ".js", ".tsx", ".jsx"]:
                if "node_modules" in str(path) or ".venv" in str(path) or "dist" in str(path):
                    continue
                if not path.is_file():
                    continue
                with open(path, "r") as f:
                    content = f.read()
                if "Copyright 2026 Google LLC" not in content:
                    print(f"Patching {path}")
                    header_to_use = TS_HEADER if path.suffix in [".ts", ".js", ".tsx", ".jsx"] else HEADER
                    # Prepend header, but keep shebang if present
                    if content.startswith("#!"):
                        lines = content.split("\n", 1)
                        if len(lines) > 1:
                            new_content = lines[0] + "\n" + header_to_use + lines[1]
                        else:
                            new_content = lines[0] + "\n" + header_to_use
                    else:
                        new_content = header_to_use + content
                    with open(path, "w") as f:
                        f.write(new_content)

if __name__ == "__main__":
    patch_files()
