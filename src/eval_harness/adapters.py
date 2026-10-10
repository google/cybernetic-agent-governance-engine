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

"""Cross-Harness Trace Adapters to ATIF (`src/eval_harness/adapters.py`).

Normalizes native execution transcripts from:
* **Google ADK (Agent Development Kit)** session/event payloads, and
* **Gemini CLI / Antigravity** JSONL conversation transcripts
into canonical :class:`~src.eval_harness.harness.ATIFTrajectory` objects (ACES §3.3).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from src.eval_harness.harness import ATIFStep, ATIFTrajectory


def adk_session_to_atif(
    session_payload: Mapping[str, Any],
    *,
    default_model_id: str = "gemini-3.5-flash",
) -> ATIFTrajectory:
    """Convert a Google ADK session dictionary into a canonical :class:`ATIFTrajectory`.

    Supports ADK ``events`` arrays where each event may contain ``author``,
    ``content.parts`` (with ``text``, ``function_call``, and ``function_response``),
    plus optional ``state`` / ``artifacts`` maps.
    """
    traj_id = str(
        session_payload.get("id")
        or session_payload.get("session_id")
        or session_payload.get("trajectory_id")
        or "adk-session-0"
    )
    model_id = str(
        session_payload.get("model")
        or session_payload.get("model_id")
        or default_model_id
    )
    events = session_payload.get("events") or ()

    prompt = str(session_payload.get("prompt") or "")
    final_response = str(session_payload.get("final_response") or "")
    steps: list[ATIFStep] = []
    step_idx = 1

    for ev in events:
        if not isinstance(ev, Mapping):
            continue
        author = str(ev.get("author") or ev.get("role") or "agent")
        content = ev.get("content")
        parts = (
            content.get("parts", ())
            if isinstance(content, Mapping)
            else (ev.get("parts") or ())
        )

        texts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        observations: list[str] = []

        for part in parts:
            if not isinstance(part, Mapping):
                continue
            if part.get("text"):
                texts.append(str(part["text"]))
            fc = part.get("function_call") or part.get("functionCall")
            if isinstance(fc, Mapping):
                tool_calls.append(
                    {
                        "name": str(fc.get("name") or ""),
                        "arguments": dict(fc.get("args") or fc.get("arguments") or {}),
                    }
                )
            fr = part.get("function_response") or part.get("functionResponse")
            if isinstance(fr, Mapping):
                resp_val = fr.get("response")
                observations.append(
                    json.dumps(resp_val)
                    if isinstance(resp_val, Mapping)
                    else str(resp_val or "")
                )

        msg = "\n".join(texts).strip()
        obs = "\n".join(observations).strip()

        if author.lower() == "user" and not prompt and msg:
            prompt = msg
            continue

        if msg and not tool_calls and author.lower() != "user":
            final_response = msg

        steps.append(
            ATIFStep(
                step_index=step_idx,
                source=author,
                message=msg,
                tool_calls=tuple(tool_calls),
                observation=obs,
                metadata=(
                    dict(ev["metadata"])
                    if isinstance(ev.get("metadata"), Mapping)
                    else {}
                ),
            )
        )
        step_idx += 1

    raw_artifacts = session_payload.get("artifacts") or session_payload.get(
        "intermediate_artifacts"
    )
    artifacts = (
        {str(k): str(v) for k, v in raw_artifacts.items()}
        if isinstance(raw_artifacts, Mapping)
        else {}
    )
    visible_skills = tuple(
        str(s) for s in (session_payload.get("visible_skills") or ())
    )

    return ATIFTrajectory(
        trajectory_id=traj_id,
        harness_id="google-adk",
        model_id=model_id,
        prompt=prompt,
        steps=tuple(steps),
        final_response=final_response,
        intermediate_artifacts=artifacts,
        visible_skills=visible_skills,
    )


def gemini_cli_jsonl_to_atif(
    records: Iterable[Mapping[str, Any]],
    *,
    trajectory_id: str = "gemini-cli-0",
    model_id: str = "gemini-3.5-flash",
) -> ATIFTrajectory:
    """Convert Gemini CLI / Antigravity JSONL step records into an :class:`ATIFTrajectory`."""
    prompt = ""
    final_response = ""
    steps: list[ATIFStep] = []
    step_counter = 1

    for rec in records:
        if not isinstance(rec, Mapping):
            continue
        rec_type = str(rec.get("type") or "").upper()
        source = str(rec.get("source") or "agent").lower()
        content = str(rec.get("content") or rec.get("message") or "")

        if rec_type == "USER_INPUT" or source in ("user", "user_explicit"):
            if not prompt and content:
                prompt = content
            continue

        raw_tcalls = rec.get("tool_calls") or ()
        parsed_tcalls: list[dict[str, Any]] = []
        for tc in raw_tcalls:
            if not isinstance(tc, Mapping):
                continue
            parsed_tcalls.append(
                {
                    "name": str(tc.get("name") or tc.get("tool_name") or ""),
                    "arguments": dict(tc.get("arguments") or tc.get("args") or {}),
                }
            )

        obs = str(rec.get("observation") or rec.get("tool_output") or "")
        if content and not parsed_tcalls:
            final_response = content

        steps.append(
            ATIFStep(
                step_index=int(rec.get("step_index", step_counter)),
                source=source,
                message=content,
                tool_calls=tuple(parsed_tcalls),
                observation=obs,
            )
        )
        step_counter += 1

    return ATIFTrajectory(
        trajectory_id=trajectory_id,
        harness_id="gemini-cli",
        model_id=model_id,
        prompt=prompt,
        steps=tuple(steps),
        final_response=final_response,
    )


__all__ = [
    "adk_session_to_atif",
    "gemini_cli_jsonl_to_atif",
]
