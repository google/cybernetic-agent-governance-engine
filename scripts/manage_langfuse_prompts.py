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

import sys
import os

if os.environ.get("AGENT_RUNTIME") == "1":
    raise ImportError(
        "This ops script must not be imported in agent runtime context. "
        "Set AGENT_RUNTIME=1 is reserved for the financial advisor service."
    )

from dotenv import load_dotenv

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(".env")

from langfuse import Langfuse
client = Langfuse()

def list_and_clean_prompts():
    # Unfortunately Langfuse Python SDK doesn't have a direct `list_prompts` method easily exposed in the standard client.
    # We will use the REST API directly or the Fern client.
    from langfuse.api.client import FernLangfuse
    api = FernLangfuse(
        username=os.environ["LANGFUSE_PUBLIC_KEY"],
        password=os.environ["LANGFUSE_SECRET_KEY"],
        base_url=os.environ.get("LANGFUSE_HOST", "http://localhost:3000")
    )
    
    # Wait, the Fern client doesn't have a `prompt` resource directly, we may need to use HTTP requests.
    import requests
    auth = (os.environ["LANGFUSE_PUBLIC_KEY"], os.environ["LANGFUSE_SECRET_KEY"])
    host = os.environ.get("LANGFUSE_HOST", "http://localhost:3000")
    
    url = f"{host}/api/public/prompts"
    resp = requests.get(url, auth=auth)
    if resp.status_code == 200:
        prompts = resp.json().get("data", [])
        print(f"Found {len(prompts)} prompts in Langfuse.")
        for p in prompts:
            print(f"- {p['name']} (v{p['version']}) labels: {p.get('labels')}")
    else:
        print(f"Failed to list prompts: {resp.text}")

list_and_clean_prompts()
