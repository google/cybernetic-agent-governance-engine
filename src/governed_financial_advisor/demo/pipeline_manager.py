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
Pipeline Manager — submits KFP governance pipelines for the demo.
"""

import logging
import os
import tempfile
import uuid
from typing import Any

logger = logging.getLogger("demo.pipeline_manager")

# KFP compiler — imported at call time to allow mocking in tests.
try:
    from kfp import compiler  # type: ignore[import]
except ImportError:
    compiler = None  # type: ignore[assignment]

from src.governed_financial_advisor.demo.state import demo_state


async def submit_governance_pipeline(strategy_name: str, **kwargs: Any) -> None:
    """Compile and submit a KFP governance pipeline.

    Args:
        strategy_name: Human-readable name for the pipeline run.
        **kwargs:       Additional parameters forwarded to the pipeline function.
    """
    # Import here so tests can patch at module level
    import src.governed_financial_advisor.demo.pipeline_manager as _self  # noqa: PLC0415

    _compiler = _self.compiler

    if _compiler is None:
        raise ImportError("kfp is required to compile governance pipelines.")

    # Dynamic import of the pipeline function (avoids circular imports).
    from src.governed_financial_advisor.pipelines.green_stack_pipeline import governance_pipeline  # noqa: PLC0415

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        pipeline_path = tmp.name

    _compiler.Compiler().compile(
        pipeline_func=governance_pipeline,
        package_path=pipeline_path,
    )

    trace_id = str(uuid.uuid4())
    demo_state.latest_trace_id = trace_id
    demo_state.pipeline_status = {
        "status": "submitted",
        "mode": "local",
        "pipeline_path": pipeline_path,
        "trace_id": trace_id,
    }
    logger.info("Pipeline compiled — trace_id=%s", trace_id)
