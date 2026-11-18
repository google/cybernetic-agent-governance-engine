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

if os.environ.get("AGENT_RUNTIME") == "1":
    raise ImportError(
        "This ops script must not be imported in agent runtime context. "
        "Set AGENT_RUNTIME=1 is reserved for the financial advisor service."
    )


def list_and_clean_prompts() -> None:
    import requests
    from dotenv import load_dotenv

    load_dotenv(".env")
    auth = (os.environ["LANGFUSE_PUBLIC_KEY"], os.environ["LANGFUSE_SECRET_KEY"])
    host = os.environ.get("LANGFUSE_HOST", "http://localhost:3000")

    url = f"{host}/api/public/prompts"
    resp = requests.get(url, auth=auth, timeout=10)
    if resp.status_code == 200:
        prompts = resp.json().get("data", [])
        print(f"Found {len(prompts)} prompts in Langfuse.")
        for p in prompts:
            print(f"- {p['name']} (v{p['version']}) labels: {p.get('labels')}")
    else:
        print(f"Failed to list prompts: {resp.text}")


if __name__ == "__main__":
    list_and_clean_prompts()
