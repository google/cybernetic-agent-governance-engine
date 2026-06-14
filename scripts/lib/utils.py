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
import subprocess
import shutil
import sys
from pathlib import Path

def load_dotenv():
    """Load environment variables from .env file."""
    # adjust path to be relative to this file inside deployment/lib/
    # deployment/lib/utils.py -> deployment/lib/ -> deployment/ -> root
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        print(f"📂 Loading config from: {env_path}")
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    # Override existing env vars to ensure .env is source of truth
                    if key.strip() in os.environ:
                        print(f"⚠️ Overriding env var {key.strip()} from .env")
                    os.environ[key.strip()] = value.strip()
    else:
        print(f"⚠️ No .env file found at {env_path}")

def run_command(command, check=True, capture_output=False, env=None):
    """
    Runs a shell command and prints the output.

    Args:
        command (list): The command to run.
        check (bool): Whether to raise an exception on failure.
        capture_output (bool): Whether to capture stdout/stderr.
        env (dict): Environment variables to pass.

    Returns:
        subprocess.CompletedProcess or subprocess.CalledProcessError
    """
    print(f"🚀 Running: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=check,
            capture_output=capture_output,
            text=True,
            env=env or os.environ.copy()
        )
        if capture_output and result.stdout:
            print(result.stdout.strip())
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running command: {e}")
        if capture_output and e.stderr:
            print(f"Error details: {e.stderr}")
        if check:
            sys.exit(1)
        return e

def check_tool_availability(tool_name):
    """Checks if a CLI tool is available in the PATH."""
    return shutil.which(tool_name) is not None
