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
import yaml
import logging
from typing import Optional, Dict

logger = logging.getLogger("PromptFetcher")

def fetch_managed_prompts() -> Optional[str]:
    """
    Fetches the NeMo Guardrails 'self_check_input' and 'self_check_output' prompts
    from Langfuse Prompt Management and returns them as a YAML formatted string.
    Returns None if fetching fails.
    """
    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")

    if not public_key or not secret_key:
        logger.warning("Langfuse credentials not found. Falling back to local prompts.yml")
        return None

    try:
        from langfuse import Langfuse
        
        # We configure the client explicitly to ensure it points to our internal host
        langfuse = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host
        )

        nemo_prompts = []
        
        # 1. Fetch Input Check
        try:
            input_prompt_obj = langfuse.get_prompt("nemo/self_check_input", label="production")
            if input_prompt_obj and hasattr(input_prompt_obj, 'prompt'):
                nemo_prompts.append({
                    "task": "self_check_input",
                    "content": input_prompt_obj.prompt
                })
        except Exception as e:
            logger.error(f"Failed to fetch nemo/self_check_input from Langfuse: {e}")

        # 2. Fetch Output Check
        try:
            output_prompt_obj = langfuse.get_prompt("nemo/self_check_output", label="production")
            if output_prompt_obj and hasattr(output_prompt_obj, 'prompt'):
                nemo_prompts.append({
                    "task": "self_check_output",
                    "content": output_prompt_obj.prompt
                })
        except Exception as e:
            logger.error(f"Failed to fetch nemo/self_check_output from Langfuse: {e}")

        if not nemo_prompts:
            logger.warning("No NeMo prompts fetched from Langfuse. Falling back to local prompts.yml")
            return None

        # Format as NeMo config YAML
        config_data = {"prompts": nemo_prompts}
        yaml_str = yaml.dump(config_data, default_flow_style=False)
        
        logger.info(f"Successfully fetched {len(nemo_prompts)} prompts from Langfuse Prompt Management")
        return yaml_str

    except Exception as e:
        logger.error(f"Critical failure initializing Langfuse SDK for prompts: {e}")
        return None
