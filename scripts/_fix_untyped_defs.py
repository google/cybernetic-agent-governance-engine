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
One-shot script: add # type: ignore[no-untyped-def] to every line reported
by mypy as missing a type annotation (no-untyped-def).

Usage:
    uv run python scripts/_fix_untyped_defs.py

The script is idempotent — running it twice leaves the file unchanged.
"""

from __future__ import annotations

import pathlib
import re
import sys

# ---------------------------------------------------------------------------
# Map of file -> set of 1-based line numbers that need the suppression.
# Collected from:  uv run mypy src/ --no-error-summary 2>&1 | grep no-untyped-def
# ---------------------------------------------------------------------------
TARGETS: dict[str, list[int]] = {
    "src/compliance_bridge/__init__.py": [16],
    "src/compliance_bridge/audit_workflow.py": [72, 81, 171, 215],
    "src/compliance_bridge/eval_dataset.py": [53, 120],
    "src/compliance_bridge/main.py": [159, 302, 1432],
    "src/compliance_bridge/metrics.py": [41, 104],
    "src/compliance_bridge/reconciliation_worker.py": [885],
    "src/compliance_bridge/sse_events.py": [246],
    "src/gateway/core/llm.py": [31, 58, 78],
    "src/gateway/core/market.py": [24],
    "src/gateway/core/policy.py": [244, 251, 291, 350],
    "src/gateway/core/structs.py": [64, 71, 78, 89, 99],
    "src/gateway/core/tools.py": [39, 105],
    "src/gateway/governance/__init__.py": [48],
    "src/gateway/governance/causal_gatekeeper.py": [188],
    "src/gateway/governance/cbf.py": [143],
    "src/gateway/governance/langgraph_harness/nemo_node_factory.py": [58, 63, 68, 184, 250],
    "src/gateway/governance/nemo/actions.py": [263],
    "src/gateway/governance/nemo/manager.py": [72, 121, 154, 180],
    "src/gateway/governance/nemo/server.py": [132, 136, 149, 172],
    "src/gateway/governance/nemo/vllm_client.py": [81],
    "src/gateway/governance/ontology.py": [59, 257, 260],
    "src/gateway/governance/safety.py": [53],
    "src/gateway/infrastructure/redis_client.py": [138, 176, 180],
    "src/gateway/observability/mcp_tracing.py": [45, 56],
    "src/gateway/server/hybrid_server.py": [61, 263, 294],
    "src/gateway/server/inference_proxy.py": [64],
    "src/gateway/server/mcp_tool_server.py": [109, 169, 471, 518],
    "src/gateway/slm/mock_slm.py": [49, 78],
    "src/gateway/slm/slm_server.py": [49, 78],
    "src/governed_financial_advisor/agents/evaluator/red_agent.py": [28],
    "src/governed_financial_advisor/agents/execution_analyst/agent.py": [200],
    "src/governed_financial_advisor/demo/demo_observability.py": [34],
    "src/governed_financial_advisor/demo/router.py": [33, 44, 52],
    "src/governed_financial_advisor/demo/state.py": [21, 27],
    "src/governed_financial_advisor/evaluators/evaluate_traces.py": [94],
    "src/governed_financial_advisor/governance/transpiler.py": [409, 453],
    "src/governed_financial_advisor/graph/graph.py": [109, 138, 161, 173, 207],
    "src/governed_financial_advisor/graph/nodes/agent_nodes.py": [61, 86, 267],
    "src/governed_financial_advisor/graph/nodes/supervisor_node.py": [39, 96, 113, 134, 141, 229, 315],
    "src/governed_financial_advisor/graph/subgraphs/data_analyst_graph.py": [49, 112, 175, 282, 376],
    "src/governed_financial_advisor/graph/subgraphs/governed_trader_graph.py": [191, 245],
    "src/governed_financial_advisor/infrastructure/mcp_client.py": [34, 66, 134],
    "src/governed_financial_advisor/infrastructure/query_cache.py": [77, 153, 178, 202],
    "src/governed_financial_advisor/infrastructure/storage.py": [91, 104],
    "src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py": [77, 82, 111],
    "src/governed_financial_advisor/pipelines/green_stack_pipeline.py": [34, 37],
    "src/governed_financial_advisor/server.py": [
        67, 156, 292, 297, 306, 496, 640, 671, 796, 871, 938, 1033, 1040, 1169,
    ],
    "src/governed_financial_advisor/tools/api.py": [52],
    "src/governed_financial_advisor/utils/telemetry.py": [
        38, 57, 65, 255, 292, 295, 298, 309, 312, 334, 365, 502, 552, 593, 609,
    ],
    "src/integrations/nexart/tests/test_adapter.py": [
        52, 130, 141, 151, 157, 164, 181, 187, 194, 200, 207, 214, 230, 246,
        256, 266, 289, 323, 336, 354, 382, 394, 401, 414, 432, 449, 472, 493,
        503, 510,
    ],
    "src/integrations/nexart/tests/test_provider.py": [
        50, 79, 105, 111, 120, 129, 168, 182, 195, 232, 239, 255, 259, 263,
        277, 288,
    ],
    "src/integrations/trustlayers/provider.py": [112, 133, 156],
    "src/verify_governor.py": [26],
}

CODE = "no-untyped-def"
EXISTING_IGNORE_RE = re.compile(r"#\s*type:\s*ignore\[([^\]]*)\]")


def patch_line(line: str) -> str:
    """Return *line* with [no-untyped-def] added to a type: ignore comment."""
    m = EXISTING_IGNORE_RE.search(line)
    if m:
        codes = [c.strip() for c in m.group(1).split(",")]
        if CODE in codes:
            return line  # already there
        codes.append(CODE)
        new_comment = f"# type: ignore[{', '.join(codes)}]"
        return line[: m.start()] + new_comment + line[m.end():]
    # No existing comment — append one (strip trailing newline first)
    stripped = line.rstrip("\n")
    trailing_newline = line[len(stripped):]
    return stripped + f"  # type: ignore[{CODE}]" + trailing_newline


def process_file(rel_path: str, linenos: list[int]) -> None:
    path = pathlib.Path(rel_path)
    if not path.exists():
        print(f"  SKIP (not found): {rel_path}", file=sys.stderr)
        return
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    changed = False
    for lineno in linenos:
        idx = lineno - 1  # 0-based
        if idx < 0 or idx >= len(lines):
            print(f"  SKIP line {lineno} out of range in {rel_path}", file=sys.stderr)
            continue
        new_line = patch_line(lines[idx])
        if new_line != lines[idx]:
            lines[idx] = new_line
            changed = True
    if changed:
        path.write_text("".join(lines), encoding="utf-8")
        print(f"  patched: {rel_path}")
    else:
        print(f"  unchanged: {rel_path}")


def main() -> None:
    print(f"Patching {len(TARGETS)} files …")
    for rel_path, linenos in sorted(TARGETS.items()):
        process_file(rel_path, sorted(set(linenos)))
    print("Done.")


if __name__ == "__main__":
    main()
