#!/usr/bin/env python3
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
Capture SHA256 baseline of LUA_ATOMIC_CBF for PR C Stage 1 verification.

This script extracts and hashes the Lua script directly from the source file,
bypassing import machinery to work even when imports are broken during refactoring.

Per the implementation plan §7.2, Stage 1 must preserve SHA256(LUA_ATOMIC_CBF)
byte-identical. This script establishes the cryptographic baseline.
"""

import hashlib
import re
from pathlib import Path


def extract_lua_script(file_path: Path) -> str:
    """Extract LUA_ATOMIC_CBF string literal from the source file."""
    content = file_path.read_text(encoding="utf-8")
    
    # Match: LUA_ATOMIC_CBF: str = """..."""
    pattern = r'LUA_ATOMIC_CBF:\s*str\s*=\s*"""(.*?)"""'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        raise ValueError(f"Could not find LUA_ATOMIC_CBF in {file_path}")
    
    return match.group(1)


def main():
    repo_root = Path(__file__).parent.parent
    cbf_file = repo_root / "src" / "gateway" / "governance" / "safety" / "cbf_engine.py"
    
    if not cbf_file.exists():
        print(f"❌ CBF file not found at expected location: {cbf_file}")
        print("   Looking for old location...")
        cbf_file = repo_root / "src" / "cage_finance" / "safety" / "cbf.py"
        if not cbf_file.exists():
            print(f"❌ CBF file not found at old location either: {cbf_file}")
            return 1
    
    try:
        lua_script = extract_lua_script(cbf_file)
    except ValueError as e:
        print(f"❌ {e}")
        return 1
    
    sha256_hash = hashlib.sha256(lua_script.encode('utf-8')).hexdigest()
    
    print(f"✅ CBF Lua Script Baseline")
    print(f"   File: {cbf_file.relative_to(repo_root)}")
    print(f"   SHA256: {sha256_hash}")
    print(f"   Length: {len(lua_script)} characters")
    
    # Write to a baseline file for later comparison
    baseline_file = repo_root / "tests" / "parity" / "cbf_lua_baseline_sha256.txt"
    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    baseline_file.write_text(f"{sha256_hash}\n", encoding="utf-8")
    print(f"   Baseline saved to: {baseline_file.relative_to(repo_root)}")
    
    return 0


if __name__ == "__main__":
    exit(main())
