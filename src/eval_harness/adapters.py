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
* **Google ADK (Agent Development Kit)** session/event payloads,
* **LangChain / LangGraph** state dictionaries and ``BaseMessage`` sequences, and
* **Gemini CLI / Antigravity** JSONL conversation transcripts
into canonical :class:`~src.eval_harness.harness.ATIFTrajectory` objects (ACES §3.3).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
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


def _extract_lc_message_text(content: Any) -> str:
    """Extract normalized text from a LangChain message ``content`` field."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence) and not isinstance(content, (bytes, bytearray)):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, Mapping) and item.get("text"):
                parts.append(str(item["text"]))
        return "\n".join(parts).strip()
    if isinstance(content, Mapping):
        return json.dumps(dict(content), ensure_ascii=False, default=str)
    return str(content)


def _normalize_lc_message(msg: Any) -> dict[str, Any]:
    """Coerce a LangChain ``BaseMessage``, tuple ``(role, content)``, or dict into a uniform dict."""
    if isinstance(msg, tuple) and len(msg) == 2:
        return {
            "role": str(msg[0]).lower(),
            "content": _extract_lc_message_text(msg[1]),
            "name": None,
            "tool_calls": [],
            "tool_call_id": None,
            "usage_metadata": {},
            "response_metadata": {},
            "additional_kwargs": {},
        }

    if isinstance(msg, Mapping):
        role = str(msg.get("type") or msg.get("role") or "ai").lower()
        raw_tcalls = list(msg.get("tool_calls") or ())
        add_kwargs = (
            dict(msg["additional_kwargs"])
            if isinstance(msg.get("additional_kwargs"), Mapping)
            else {}
        )
        if not raw_tcalls and isinstance(add_kwargs.get("tool_calls"), Sequence):
            raw_tcalls = list(add_kwargs["tool_calls"])
        usage = (
            dict(msg["usage_metadata"])
            if isinstance(msg.get("usage_metadata"), Mapping)
            else {}
        )
        resp_meta = (
            dict(msg["response_metadata"])
            if isinstance(msg.get("response_metadata"), Mapping)
            else {}
        )
        return {
            "role": role,
            "content": _extract_lc_message_text(msg.get("content")),
            "name": msg.get("name"),
            "tool_calls": raw_tcalls,
            "tool_call_id": msg.get("tool_call_id"),
            "usage_metadata": usage,
            "response_metadata": resp_meta,
            "additional_kwargs": add_kwargs,
        }

    # Duck-typed LangChain BaseMessage (HumanMessage, AIMessage, ToolMessage, SystemMessage)
    role = str(getattr(msg, "type", None) or getattr(msg, "role", None) or "ai").lower()
    raw_tcalls = list(getattr(msg, "tool_calls", None) or ())
    raw_add_kwargs = getattr(msg, "additional_kwargs", None)
    add_kwargs = dict(raw_add_kwargs) if isinstance(raw_add_kwargs, Mapping) else {}
    if not raw_tcalls and isinstance(add_kwargs.get("tool_calls"), Sequence):
        raw_tcalls = list(add_kwargs["tool_calls"])
    raw_usage = getattr(msg, "usage_metadata", None)
    usage = dict(raw_usage) if isinstance(raw_usage, Mapping) else {}
    raw_resp_meta = getattr(msg, "response_metadata", None)
    resp_meta = dict(raw_resp_meta) if isinstance(raw_resp_meta, Mapping) else {}
    return {
        "role": role,
        "content": _extract_lc_message_text(getattr(msg, "content", "")),
        "name": getattr(msg, "name", None),
        "tool_calls": raw_tcalls,
        "tool_call_id": getattr(msg, "tool_call_id", None),
        "usage_metadata": usage,
        "response_metadata": resp_meta,
        "additional_kwargs": add_kwargs,
    }


def _parse_lc_tool_calls(raw_tool_calls: Sequence[Any]) -> list[dict[str, Any]]:
    """Normalize LangChain ``tool_calls`` or OpenAI-style function tool calls."""
    parsed: list[dict[str, Any]] = []
    for tc in raw_tool_calls:
        if not isinstance(tc, Mapping):
            continue
        if "function" in tc and isinstance(tc["function"], Mapping):
            fn = tc["function"]
            raw_args = fn.get("arguments") or {}
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args)
                except ValueError:
                    args = {"raw": raw_args}
            elif isinstance(raw_args, Mapping):
                args = dict(raw_args)
            else:
                args = {}
            entry: dict[str, Any] = {
                "name": str(fn.get("name") or ""),
                "arguments": args,
            }
            if tc.get("id"):
                entry["id"] = str(tc["id"])
            parsed.append(entry)
        else:
            raw_args = tc.get("args") if "args" in tc else tc.get("arguments")
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args)
                except ValueError:
                    args = {"raw": raw_args}
            elif isinstance(raw_args, Mapping):
                args = dict(raw_args)
            else:
                args = {}
            entry = {
                "name": str(tc.get("name") or tc.get("tool_name") or ""),
                "arguments": args,
            }
            if tc.get("id"):
                entry["id"] = str(tc["id"])
            parsed.append(entry)
    return parsed


def langgraph_state_to_atif(
    state_payload: Mapping[str, Any] | Sequence[Any],
    *,
    default_model_id: str = "gemini-3.5-flash",
    default_trajectory_id: str = "langgraph-0",
) -> ATIFTrajectory:
    """Convert a LangGraph state dictionary (or message list) into a canonical :class:`ATIFTrajectory`.

    Supports both in-memory LangChain ``BaseMessage`` objects (``HumanMessage``,
    ``AIMessage``, ``ToolMessage``, ``SystemMessage``) and serialized message
    dictionaries under ``state_payload["messages"]``. Pairs ``ToolMessage``
    outputs with their originating ``AIMessage`` tool call steps and preserves
    token usage metadata (``input_tokens`` / ``output_tokens``) and multi-agent
    node attribution (``name`` / ``langgraph_node``).
    """
    if isinstance(state_payload, Mapping):
        raw_messages = state_payload.get("messages") or ()
        traj_id = str(
            state_payload.get("trajectory_id")
            or state_payload.get("thread_id")
            or state_payload.get("id")
            or default_trajectory_id
        )
        model_id = str(
            state_payload.get("model_id")
            or state_payload.get("model")
            or default_model_id
        )
        prompt = str(state_payload.get("prompt") or "")
        final_response = str(
            state_payload.get("final_response") or state_payload.get("response") or ""
        )
        raw_artifacts = state_payload.get(
            "intermediate_artifacts"
        ) or state_payload.get("artifacts")
        artifacts = (
            {str(k): str(v) for k, v in raw_artifacts.items()}
            if isinstance(raw_artifacts, Mapping)
            else {}
        )
        visible_skills = tuple(
            str(s) for s in (state_payload.get("visible_skills") or ())
        )
    else:
        raw_messages = state_payload
        traj_id = default_trajectory_id
        model_id = default_model_id
        prompt = ""
        final_response = ""
        artifacts = {}
        visible_skills = ()

    normalized_msgs = [_normalize_lc_message(m) for m in raw_messages]

    # Build a lookup of tool_call_id -> list of ToolMessage observations
    tool_obs_by_id: dict[str, list[str]] = {}
    consumed_tool_msg_indices: set[int] = set()

    for idx, m in enumerate(normalized_msgs):
        if m["role"] in ("tool", "function") and m.get("tool_call_id"):
            tc_id = str(m["tool_call_id"])
            tool_obs_by_id.setdefault(tc_id, []).append(m["content"])
            consumed_tool_msg_indices.add(idx)

    steps: list[ATIFStep] = []
    step_idx = 1

    i = 0
    while i < len(normalized_msgs):
        m = normalized_msgs[i]
        role = m["role"]
        content = m["content"]

        if role == "system":
            i += 1
            continue

        if role in ("human", "user"):
            if not prompt and content:
                prompt = content
            i += 1
            continue

        if role in ("ai", "assistant", "model", "agent"):
            tcalls = _parse_lc_tool_calls(m["tool_calls"])
            obs_parts: list[str] = []

            # Match tool observations by tool_call_id first
            for tc in tcalls:
                call_id = str(tc.get("id") or "")
                if call_id and call_id in tool_obs_by_id:
                    obs_parts.extend(tool_obs_by_id.pop(call_id))

            # Also absorb immediately following un-keyed ToolMessages if tcalls exist
            while (
                tcalls
                and (i + 1) < len(normalized_msgs)
                and normalized_msgs[i + 1]["role"] in ("tool", "function")
                and (i + 1) not in consumed_tool_msg_indices
            ):
                i += 1
                consumed_tool_msg_indices.add(i)
                if normalized_msgs[i]["content"]:
                    obs_parts.append(normalized_msgs[i]["content"])

            clean_tcalls = tuple(
                {"name": tc["name"], "arguments": tc["arguments"]} for tc in tcalls
            )
            obs = "\n".join(p for p in obs_parts if p).strip()

            resp_meta = m["response_metadata"]
            add_kwargs = m["additional_kwargs"]
            usage = m["usage_metadata"]

            explicit_sub_agent = add_kwargs.get("sub_agent") or resp_meta.get(
                "sub_agent"
            )
            source = str(
                explicit_sub_agent
                or m.get("name")
                or resp_meta.get("langgraph_node")
                or "agent"
            )

            step_meta: dict[str, Any] = {}
            if explicit_sub_agent:
                step_meta["sub_agent"] = str(explicit_sub_agent)
            if resp_meta.get("langgraph_node"):
                step_meta["langgraph_node"] = str(resp_meta["langgraph_node"])
            if isinstance(usage.get("input_tokens"), (int, float)):
                step_meta["prompt_tokens"] = int(usage["input_tokens"])
            if isinstance(usage.get("output_tokens"), (int, float)):
                step_meta["completion_tokens"] = int(usage["output_tokens"])
            if resp_meta.get("model_name") and model_id == default_model_id:
                model_id = str(resp_meta["model_name"])

            if content and not clean_tcalls:
                final_response = content

            steps.append(
                ATIFStep(
                    step_index=step_idx,
                    source=source,
                    message=content,
                    tool_calls=clean_tcalls,
                    observation=obs,
                    metadata=step_meta,
                )
            )
            step_idx += 1
            i += 1
            continue

        if role in ("tool", "function") and i not in consumed_tool_msg_indices:
            tool_name = str(m.get("name") or "tool")
            steps.append(
                ATIFStep(
                    step_index=step_idx,
                    source="tool",
                    message="",
                    tool_calls=({"name": tool_name, "arguments": {}},),
                    observation=content,
                )
            )
            step_idx += 1

        i += 1

    return ATIFTrajectory(
        trajectory_id=traj_id,
        harness_id="langgraph",
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
    "langgraph_state_to_atif",
]
