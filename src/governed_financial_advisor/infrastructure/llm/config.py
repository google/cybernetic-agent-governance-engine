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

import litellm

# Default values suitable for the vLLM setup
DEFAULT_VLLM_BASE_URL = os.getenv("VLLM_BASE_URL")
if not DEFAULT_VLLM_BASE_URL:
    raise RuntimeError(
        "VLLM_BASE_URL must be configured — no localhost fallback in production"
    )

logger = logging.getLogger(__name__)

# Pull configured models from the environment to register LiteLLM limits
DEEPSEEK_MODEL = os.getenv("MODEL_REASONING", "")
META_LLAMA_MODEL = os.getenv("MODEL_FAST", "")
DEFAULT_MODEL_NAME = META_LLAMA_MODEL

try:
    # Attempt to register using register_model (newer versions)
    litellm.register_model(
        {
            DEEPSEEK_MODEL: {
                "max_tokens": 4096,
                "input_cost_per_token": 0,
                "output_cost_per_token": 0,
                "litellm_provider": "openai",
                "mode": "chat",
            },
            META_LLAMA_MODEL: {
                "max_tokens": 4096,
                "input_cost_per_token": 0,
                "output_cost_per_token": 0,
                "litellm_provider": "openai",
                "mode": "chat",
            },
        }
    )
    logger.info("✅ Registered custom models with LiteLLM (4k context)")
except AttributeError:
    # Fallback to direct dictionary update (older versions might use model_cost)
    try:
        if hasattr(litellm, "model_alias_map"):
            litellm.model_alias_map = {
                DEEPSEEK_MODEL: {"max_tokens": 4096},
                META_LLAMA_MODEL: {"max_tokens": 4096},
            }
            logger.info("✅ Updated LiteLLM model_alias_map (fallback)")
        else:
            logger.warning(
                "⚠️ Could not register models with LiteLLM: neither register_model nor model_cost found."
            )
    except Exception as e:
        logger.warning(f"⚠️ Failed to register models with LiteLLM: {e}")
except Exception as e:
    logger.warning(f"⚠️ Failed to register models with LiteLLM: {e}")


def get_adk_model(model_name: str, api_base: str | None = None) -> str:
    """Helper to format the model string for LiteLLM/ADK compatibility."""
    # Trust the environment config

    return model_name
