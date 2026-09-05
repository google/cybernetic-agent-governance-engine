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

import logging
import os

import httpx
import yaml

logger = logging.getLogger("PromptFetcher")


def fetch_managed_prompts() -> str | None:
    """
    Fetches the NeMo Guardrails 'self_check_input' and 'self_check_output' prompts
    from Langfuse Prompt Management via compliance-bridge HTTP proxy and returns
    them as a YAML formatted string. Returns None if fetching fails.

    Maintains Layer 1 → Layer 2 → Layer 3 separation by proxying through
    compliance-bridge instead of importing Langfuse SDK directly.
    """
    bridge_host = os.environ.get(
        "COMPLIANCE_BRIDGE_HOST",
        "http://compliance-bridge.governance-stack.svc.cluster.local:80",
    )

    if not bridge_host:
        logger.warning(
            "COMPLIANCE_BRIDGE_HOST not set. Falling back to local prompts.yml"
        )
        return None

    try:
        nemo_prompts = []

        # 1. Fetch Input Check via compliance-bridge proxy
        try:
            url = f"{bridge_host}/v1/prompts/nemo/self_check_input"
            params = {"label": "production"}

            with httpx.Client(timeout=5.0) as client:
                response = client.get(url, params=params)
                response.raise_for_status()
                data = response.json()

            if data and "text" in data:
                nemo_prompts.append(
                    {"task": "self_check_input", "content": data["text"]}
                )
        except Exception as e:
            logger.error(f"Failed to fetch nemo/self_check_input via bridge: {e}")

        # 2. Fetch Output Check via compliance-bridge proxy
        try:
            url = f"{bridge_host}/v1/prompts/nemo/self_check_output"
            params = {"label": "production"}

            with httpx.Client(timeout=5.0) as client:
                response = client.get(url, params=params)
                response.raise_for_status()
                data = response.json()

            if data and "text" in data:
                nemo_prompts.append(
                    {"task": "self_check_output", "content": data["text"]}
                )
        except Exception as e:
            logger.error(f"Failed to fetch nemo/self_check_output via bridge: {e}")

        if not nemo_prompts:
            logger.warning(
                "No NeMo prompts fetched via compliance-bridge. Falling back to local prompts.yml"
            )
            return None

        # Format as NeMo config YAML
        config_data = {"prompts": nemo_prompts}
        yaml_str = yaml.dump(config_data, default_flow_style=False)

        logger.info(
            f"Successfully fetched {len(nemo_prompts)} prompts via compliance-bridge proxy"
        )
        return yaml_str

    except Exception as e:
        logger.error(f"Critical failure fetching prompts via compliance-bridge: {e}")
        return None
