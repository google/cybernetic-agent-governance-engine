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

"""Shared builders for ``cage.skill.cer.v2`` skill-certification receipt tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.eval_harness.harness import SkillLiftReport
from src.gateway.governance.kms_signer import SoftwareEd25519Provider
from src.integrations.trust.key_manifest import Ed25519KeyManifestClient

SAFE_OPS_SKILL_MD = (
    "---\n"
    "name: safe-ops\n"
    "description: Execute verified safe operations within policy limits.\n"
    "---\n"
    "# Safe Ops\n"
    "## When NOT to Use\n"
    "Do NOT trigger for destructive or out-of-scope requests. Never call shell_exec.\n"
    "## Workflow\n"
    "1. Verify input parameters.\n"
    "2. Run `safe_tool` and return `SAFE_OK`.\n"
)

SAFE_OPS_EVALS: list[dict[str, Any]] = [
    {
        "case_id": "c1",
        "bucket": "explicit",
        "prompt": "Run safe_tool",
        "expected_skill": "safe-ops",
        "forbidden_tools": ["drop_prod"],
        "required_output_tokens": ["SAFE_OK"],
        "allowed_skills": ["safe-ops"],
    }
]

SAFE_OPS_WITH_SKILL_TRACES: list[dict[str, Any]] = [
    {
        "trajectory_id": "c1",
        "harness_id": "test",
        "model_id": "trace-model",
        "prompt": "Run safe_tool",
        "steps": [
            {
                "step_index": 1,
                "source": "agent",
                "tool_calls": [
                    {
                        "name": "view_file",
                        "arguments": {"path": "skills/safe-ops/SKILL.md"},
                    },
                    {"name": "safe_tool", "arguments": {}},
                ],
            }
        ],
        "final_response": "SAFE_OK",
    }
]

SAFE_OPS_WEAK_BASELINE_TRACES: list[dict[str, Any]] = [
    {
        "trajectory_id": "c1",
        "harness_id": "test",
        "model_id": "trace-model",
        "prompt": "Run safe_tool",
        "steps": [],
        "final_response": "did nothing",
    }
]


def write_text(path: Path, text: str) -> Path:
    """Write UTF-8 ``text`` to ``path`` (creating parents) and return ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_json(path: Path, payload: Any) -> Path:
    """Write ``payload`` as JSON to ``path`` and return ``path``."""
    return write_text(path, json.dumps(payload))


def make_ed25519_signer_and_jwks(
    tmp_path: Path, kid: str
) -> tuple[SoftwareEd25519Provider, Ed25519KeyManifestClient]:
    """Return a hermetic Ed25519 signer and a JWKS manifest client that resolves ``kid``."""
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_b64 = base64.urlsafe_b64encode(public_raw).decode("ascii").rstrip("=")
    jwks_path = write_json(
        tmp_path / f"jwks-{kid}.json",
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x_b64}]},
    )
    provider = SoftwareEd25519Provider(key_id=kid, private_key=private_key)
    return provider, Ed25519KeyManifestClient(manifest_url=jwks_path.as_uri())


def make_lift_report(
    *,
    skill_name: str = "safe-ops",
    model_id: str = "gemini-test-model",
    mean_composite_lift: float = 0.25,
    mean_instruction_following_lift: float = 0.1,
    routing_premium: float | None = None,
) -> SkillLiftReport:
    """Return a minimal Stage 2 lift report with the given aggregate metrics."""
    return SkillLiftReport(
        skill_name=skill_name,
        model_id=model_id,
        total_cases=1,
        mean_baseline_composite=0.5,
        mean_with_skill_composite=0.5 + mean_composite_lift,
        mean_composite_lift=mean_composite_lift,
        mean_outcome_lift=mean_composite_lift,
        mean_process_lift=mean_composite_lift,
        mean_instruction_following_lift=mean_instruction_following_lift,
        positive_lift_cases=1 if mean_composite_lift > 0 else 0,
        zero_lift_cases=1 if mean_composite_lift == 0 else 0,
        negative_lift_cases=1 if mean_composite_lift < 0 else 0,
        routing_premium=routing_premium,
        case_lifts=(),
    )
