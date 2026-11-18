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

"""Egress allowlist for chat completions leaving the inference proxy.

The proxy never forwards an upstream completion as received. It builds a new
body from the fields listed here, masks every text-bearing value on the way,
and drops every key that is not listed. A field that an OpenAI-compatible
server adds later is withheld until someone decides how to handle it, instead
of shipping unmasked by default (the failure mode of masking a fixed set of
known text fields and passing everything else through).

Streaming uses the same projection. :class:`StreamAssembler` accumulates the
allowlisted delta fields of every parsed ``chat.completion.chunk`` per choice,
:func:`sanitize_stream` sanitizes the assembled completion exactly as
:func:`sanitize_completion` sanitizes a non-streaming one, and
:func:`encode_sse_frames` re-serializes the result. Upstream bytes never reach
the client.

Field dispositions
------------------

Top level:

- ``id``, ``model``: identifiers (below). A missing or unusable value is
  replaced by a proxy-minted id or by the model the caller requested.
- ``object``: written by the proxy, never copied.
- ``created``: non-negative integer, else the proxy's clock.
- ``choices``: projected per choice.
- ``usage``: integer token counts only (``prompt_tokens``,
  ``completion_tokens``, ``total_tokens`` and the ``*_tokens_details``
  counters).
- Dropped: ``system_fingerprint`` and ``service_tier`` (they describe the
  upstream deployment, not the completion), vLLM's ``prompt_logprobs`` and
  ``prompt_token_ids`` (the prompt again, token by token) and every other key.

Choice:

- ``index``: non-negative integer, else the choice's position.
- ``finish_reason``: one of ``_FINISH_REASONS``, else null.
- ``message`` (``delta`` in a chunk): projected as below.
- Dropped: ``logprobs`` (table below), vLLM's ``stop_reason`` and
  ``token_ids`` (the completion as raw token ids) and every other key.

Message:

- ``role``: always ``assistant``.
- ``content``, ``refusal``, ``reasoning_content``, ``reasoning``: text,
  masked. A list of content parts keeps only ``text`` and ``refusal`` parts.
- ``tool_calls``: ``function`` tool calls only, as
  ``{id, type, function: {name, arguments}}``. The name is masked as text;
  the arguments are masked as JSON, string leaves only, so numbers survive.
- ``function_call`` (legacy): ``{name, arguments}``, masked like a tool call.
- Dropped: ``audio``, ``annotations`` and every other key.

Contested fields:

=============  ============  =================================================
Field          Disposition   Rationale
=============  ============  =================================================
logprobs       dropped       ``content[].token``, ``bytes`` and
                             ``top_logprobs`` spell out the unmasked
                             completion one token at a time. A value split
                             over several tokens is invisible to a masker
                             that sees one token, and ``bytes`` re-encodes
                             the same text as integers, so no per-token
                             masking is sound. The caller chooses
                             ``logprobs`` in its own request.
audio          dropped       ``audio.data`` is the spoken completion, and
                             speech cannot be masked. Returning only the
                             masked transcript would hand back a partial
                             object that claims to be audio.
annotations    dropped       ``start_index`` and ``end_index`` locate each
                             citation in the *unmasked* content, so they are
                             wrong once the content is masked; ``url`` and
                             ``title`` are retrieved text the masker has no
                             context for.
function_call  masked, kept  Same shape as a tool call, so masking it is as
                             sound as masking ``tool_calls``; legacy clients
                             still read it.
reasoning      masked, kept  The name newer vLLM releases and other
                             OpenAI-compatible servers use for
                             ``reasoning_content``; same treatment.
=============  ============  =================================================

Identifiers (``id``, ``model``, ``tool_calls[].id``) are set by the serving
stack, not generated by the model, and clients echo tool-call ids back on the
next turn. They get the deterministic ``scrub_pii()`` pass through
:meth:`EgressMasker.identifier`, never the LLM output rail, which could
rewrite them. A value that is not a short printable token without spaces is
replaced rather than returned.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "CHUNK_OBJECT",
    "COMPLETION_OBJECT",
    "EgressMasker",
    "EgressReport",
    "StreamAssembler",
    "completion_text_length",
    "encode_sse_frames",
    "sanitize_completion",
    "sanitize_stream",
]

COMPLETION_OBJECT = "chat.completion"
CHUNK_OBJECT = "chat.completion.chunk"

# Any other value (vLLM adds "abort" to the standard five) is returned as null.
_FINISH_REASONS = frozenset(
    {"stop", "length", "tool_calls", "content_filter", "function_call", "abort"}
)

_TOP_LEVEL_FIELDS = frozenset({"id", "object", "created", "model", "choices", "usage"})
_CHOICE_FIELDS = frozenset({"index", "message", "finish_reason"})
_CHUNK_CHOICE_FIELDS = frozenset({"index", "delta", "finish_reason"})
# Text-bearing message fields, in the order an encoded delta carries them.
_TEXT_FIELDS = ("reasoning_content", "reasoning", "content", "refusal")
_MESSAGE_FIELDS = frozenset({"role", *_TEXT_FIELDS, "tool_calls", "function_call"})
_TOOL_CALL_FIELDS = frozenset({"id", "type", "function"})
_CHUNK_TOOL_CALL_FIELDS = frozenset({"index", "id", "type", "function"})
_FUNCTION_FIELDS = frozenset({"name", "arguments"})
# Content-part type -> the key that carries its text.
_CONTENT_PART_TEXT_KEYS = {"text": "text", "refusal": "refusal"}
_USAGE_COUNTS = ("prompt_tokens", "completion_tokens", "total_tokens")
_USAGE_DETAIL_COUNTS = {
    "prompt_tokens_details": ("cached_tokens", "audio_tokens"),
    "completion_tokens_details": (
        "reasoning_tokens",
        "audio_tokens",
        "accepted_prediction_tokens",
        "rejected_prediction_tokens",
    ),
}
_USAGE_FIELDS = frozenset({*_USAGE_COUNTS, *_USAGE_DETAIL_COUNTS})
_IDENTIFIER_MAX_LEN = 256


class EgressMasker(Protocol):
    """Masking primitives the projection applies, bound to one request."""

    async def text(self, value: str) -> str:
        """Mask model-generated text: the output rail, or ``scrub_pii()`` alone."""
        ...

    async def arguments(self, value: str) -> str:
        """Mask a JSON arguments string, string leaves only."""
        ...

    def identifier(self, value: str) -> str:
        """Deterministically scrub a serving-stack identifier."""
        ...


@dataclass
class EgressReport:
    """What the projection changed relative to the upstream completion.

    ``pii_redacted`` is True when a masker changed a value that is returned.
    ``dropped`` holds the distinct paths of upstream fields whose value was
    withheld because the field is not allowlisted or the value has the wrong
    type. An explicit ``null`` carries nothing and is not counted (servers
    routinely send ``"logprobs": null``). Paths can embed upstream-chosen key
    names, so only their count may leave the process.
    """

    pii_redacted: bool = False
    dropped: set[str] = field(default_factory=set)

    @property
    def fields_dropped(self) -> int:
        """Number of distinct upstream field paths the projection withheld."""
        return len(self.dropped)


def _count(value: Any) -> int | None:
    """Return *value* if it is a non-negative ``int`` (never ``bool``), else None."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _is_finish_reason(value: Any) -> bool:
    return isinstance(value, str) and value in _FINISH_REASONS


def _is_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _IDENTIFIER_MAX_LEN
        and value.isprintable()
        and " " not in value
    )


def _child(path: str, key: Any) -> str:
    return f"{path}.{key}" if path else str(key)


def _unlisted(obj: Mapping[str, Any], allowed: frozenset[str]) -> list[str]:
    """Keys of *obj* outside *allowed* that carry a value (``null`` is not data)."""
    return [
        str(key)
        for key, value in obj.items()
        if key not in allowed and value is not None
    ]


class _Projection:
    """Builds the egress body for one completion and records what it changed."""

    def __init__(self, masker: EgressMasker, report: EgressReport) -> None:
        self._masker = masker
        self._report = report

    def drop(self, path: str) -> None:
        self._report.dropped.add(path)

    def drop_unlisted(
        self, obj: Mapping[str, Any], allowed: frozenset[str], path: str
    ) -> None:
        for key in _unlisted(obj, allowed):
            self.drop(_child(path, key))

    async def text(self, value: str) -> str:
        if not value:
            return value
        masked = await self._masker.text(value)
        if masked != value:
            self._report.pii_redacted = True
        return masked

    async def arguments(self, value: str) -> str:
        if not value:
            return value
        masked = await self._masker.arguments(value)
        if masked != value:
            self._report.pii_redacted = True
        return masked

    def identifier(self, value: Any, path: str) -> str | None:
        if not _is_identifier(value):
            if value is not None:
                self.drop(path)
            return None
        scrubbed = self._masker.identifier(value)
        if scrubbed != value:
            self._report.pii_redacted = True
        return scrubbed

    def count(self, value: Any, path: str) -> int | None:
        counted = _count(value)
        if counted is None and value is not None:
            self.drop(path)
        return counted

    async def completion(
        self, upstream: Mapping[str, Any], *, fallback_model: str, now: int
    ) -> dict[str, Any]:
        self.drop_unlisted(upstream, _TOP_LEVEL_FIELDS, "")
        choices: list[dict[str, Any]] = []
        raw_choices = upstream.get("choices")
        if isinstance(raw_choices, list):
            for pos, raw_choice in enumerate(raw_choices):
                if isinstance(raw_choice, Mapping):
                    choices.append(await self.choice(raw_choice, pos))
                else:
                    self.drop("choices[]")
        elif raw_choices is not None:
            self.drop("choices")

        created = self.count(upstream.get("created"), "created")
        body: dict[str, Any] = {
            "id": self.identifier(upstream.get("id"), "id")
            or f"chatcmpl-{uuid.uuid4().hex}",
            "object": COMPLETION_OBJECT,
            "created": now if created is None else created,
            "model": self.identifier(upstream.get("model"), "model") or fallback_model,
            "choices": choices,
        }
        usage = self.usage(upstream.get("usage"))
        if usage is not None:
            body["usage"] = usage
        return body

    async def choice(self, raw: Mapping[str, Any], pos: int) -> dict[str, Any]:
        path = "choices[]"
        self.drop_unlisted(raw, _CHOICE_FIELDS, path)
        index = self.count(raw.get("index"), f"{path}.index")
        message = raw.get("message")
        if message is not None and not isinstance(message, Mapping):
            self.drop(f"{path}.message")
            message = None
        finish_reason = raw.get("finish_reason")
        if finish_reason is not None and not _is_finish_reason(finish_reason):
            self.drop(f"{path}.finish_reason")
            finish_reason = None
        return {
            "index": pos if index is None else index,
            "message": await self.message(message or {}, f"{path}.message"),
            "finish_reason": finish_reason,
        }

    async def message(self, raw: Mapping[str, Any], path: str) -> dict[str, Any]:
        """Project a message onto the message allowlist.

        ``content`` is always present (``null`` when absent upstream); every
        other kept field appears only when its upstream value is non-null.
        """
        self.drop_unlisted(raw, _MESSAGE_FIELDS, path)
        out: dict[str, Any] = {"role": "assistant", "content": None}
        for key in _TEXT_FIELDS:
            value = raw.get(key)
            if value is not None:
                sanitized = await self.text_or_parts(value, f"{path}.{key}")
                if sanitized is not None:
                    out[key] = sanitized

        tool_calls = raw.get("tool_calls")
        if isinstance(tool_calls, list):
            calls: list[dict[str, Any]] = []
            for pos, raw_call in enumerate(tool_calls):
                call = await self.tool_call(raw_call, pos, f"{path}.tool_calls[]")
                if call is not None:
                    calls.append(call)
            out["tool_calls"] = calls
        elif tool_calls is not None:
            self.drop(f"{path}.tool_calls")

        function_call = raw.get("function_call")
        if isinstance(function_call, Mapping):
            out["function_call"] = await self.function(
                function_call, f"{path}.function_call"
            )
        elif function_call is not None:
            self.drop(f"{path}.function_call")
        return out

    async def text_or_parts(self, value: Any, path: str) -> str | list[Any] | None:
        if isinstance(value, str):
            return await self.text(value)
        if isinstance(value, list):
            parts: list[Any] = []
            for part in value:
                kept = await self.content_part(part, f"{path}[]")
                if kept is not None:
                    parts.append(kept)
            return parts
        self.drop(path)
        return None

    async def content_part(self, part: Any, path: str) -> str | dict[str, Any] | None:
        if isinstance(part, str):
            return await self.text(part)
        if isinstance(part, Mapping):
            part_type = part.get("type")
            text_key = (
                _CONTENT_PART_TEXT_KEYS.get(part_type)
                if isinstance(part_type, str)
                else None
            )
            if text_key is not None and isinstance(part.get(text_key), str):
                self.drop_unlisted(part, frozenset({"type", text_key}), path)
                return {"type": part_type, text_key: await self.text(part[text_key])}
        self.drop(path)
        return None

    async def tool_call(self, raw: Any, pos: int, path: str) -> dict[str, Any] | None:
        if (
            not isinstance(raw, Mapping)
            or raw.get("type") not in (None, "function")
            or not isinstance(raw.get("function"), Mapping)
        ):
            self.drop(path)
            return None
        self.drop_unlisted(raw, _TOOL_CALL_FIELDS, path)
        return {
            "id": self.identifier(raw.get("id"), f"{path}.id") or f"call-{pos}",
            "type": "function",
            "function": await self.function(raw["function"], f"{path}.function"),
        }

    async def function(self, raw: Mapping[str, Any], path: str) -> dict[str, str]:
        self.drop_unlisted(raw, _FUNCTION_FIELDS, path)
        name = raw.get("name")
        arguments = raw.get("arguments")
        if name is not None and not isinstance(name, str):
            self.drop(f"{path}.name")
        if arguments is not None and not isinstance(arguments, str):
            self.drop(f"{path}.arguments")
        return {
            "name": await self.text(name) if isinstance(name, str) else "",
            "arguments": (
                await self.arguments(arguments) if isinstance(arguments, str) else ""
            ),
        }

    def usage(self, raw: Any) -> dict[str, Any] | None:
        if raw is None:
            return None
        if not isinstance(raw, Mapping):
            self.drop("usage")
            return None
        self.drop_unlisted(raw, _USAGE_FIELDS, "usage")
        out: dict[str, Any] = {}
        for key in _USAGE_COUNTS:
            counted = self.count(raw.get(key), f"usage.{key}")
            if counted is not None:
                out[key] = counted
        for key, counters in _USAGE_DETAIL_COUNTS.items():
            details = raw.get(key)
            if details is None:
                continue
            if not isinstance(details, Mapping):
                self.drop(f"usage.{key}")
                continue
            self.drop_unlisted(details, frozenset(counters), f"usage.{key}")
            kept: dict[str, int] = {}
            for counter in counters:
                counted = self.count(details.get(counter), f"usage.{key}.{counter}")
                if counted is not None:
                    kept[counter] = counted
            out[key] = kept
        return out


async def sanitize_completion(
    upstream: Mapping[str, Any],
    masker: EgressMasker,
    *,
    fallback_model: str,
    now: int,
) -> tuple[dict[str, Any], EgressReport]:
    """Project an upstream ``chat.completion`` onto the egress allowlist.

    Returns a new body (``upstream`` is never mutated) holding only
    allowlisted fields with every text value masked through *masker*, and
    the :class:`EgressReport` for the evidence record.
    """
    report = EgressReport()
    body = await _Projection(masker, report).completion(
        upstream, fallback_model=fallback_model, now=now
    )
    return body, report


@dataclass
class _ToolCallParts:
    call_id: str = ""
    is_function: bool = True
    function: dict[str, str] = field(
        default_factory=lambda: {"name": "", "arguments": ""}
    )


@dataclass
class _ChoiceParts:
    text: dict[str, str] = field(default_factory=dict)
    tool_calls: dict[int, _ToolCallParts] = field(default_factory=dict)
    function_call: dict[str, str] | None = None
    finish_reason: str | None = None


class StreamAssembler:
    """Accumulate the allowlisted fields of parsed ``chat.completion.chunk`` objects.

    Text, tool-call and legacy ``function_call`` fragments are concatenated
    per choice (and per tool-call index), so a value split across frames is
    masked whole. Everything else is recorded in :attr:`dropped` and
    discarded: nothing an upstream frame carries is kept for re-emission.
    """

    def __init__(self) -> None:
        self._id: str | None = None
        self._created: int | None = None
        self._model: str | None = None
        self._usage: Mapping[str, Any] | None = None
        self._choices: dict[int, _ChoiceParts] = {}
        self.dropped: set[str] = set()

    def absorb(self, chunk: Mapping[str, Any]) -> None:
        """Merge one parsed chunk into the per-choice accumulators."""
        self.dropped.update(_unlisted(chunk, _TOP_LEVEL_FIELDS))
        chunk_id = chunk.get("id")
        if isinstance(chunk_id, str):
            if self._id is None:
                self._id = chunk_id
        elif chunk_id is not None:
            self.dropped.add("id")
        created = _count(chunk.get("created"))
        if created is not None:
            if self._created is None:
                self._created = created
        elif chunk.get("created") is not None:
            self.dropped.add("created")
        model = chunk.get("model")
        if isinstance(model, str):
            self._model = model or self._model
        elif model is not None:
            self.dropped.add("model")
        usage = chunk.get("usage")
        if isinstance(usage, Mapping):
            self._usage = usage
        elif usage is not None:
            self.dropped.add("usage")

        choices = chunk.get("choices")
        if isinstance(choices, list):
            for pos, choice in enumerate(choices):
                if isinstance(choice, Mapping):
                    self._absorb_choice(choice, pos)
                else:
                    self.dropped.add("choices[]")
        elif choices is not None:
            self.dropped.add("choices")

    def _absorb_choice(self, choice: Mapping[str, Any], pos: int) -> None:
        path = "choices[]"
        for key in _unlisted(choice, _CHUNK_CHOICE_FIELDS):
            self.dropped.add(f"{path}.{key}")
        index = _count(choice.get("index"))
        parts = self._choices.setdefault(
            pos if index is None else index, _ChoiceParts()
        )
        finish_reason = choice.get("finish_reason")
        if _is_finish_reason(finish_reason):
            parts.finish_reason = finish_reason
        elif finish_reason is not None:
            self.dropped.add(f"{path}.finish_reason")
        delta = choice.get("delta")
        if isinstance(delta, Mapping):
            self._absorb_delta(parts, delta, f"{path}.delta")
        elif delta is not None:
            self.dropped.add(f"{path}.delta")

    def _absorb_delta(
        self, parts: _ChoiceParts, delta: Mapping[str, Any], path: str
    ) -> None:
        for key, value in delta.items():
            if value is None or key == "role":
                continue
            if key in _TEXT_FIELDS and isinstance(value, str):
                if value:
                    parts.text[key] = parts.text.get(key, "") + value
            elif key == "tool_calls":
                self._absorb_tool_calls(parts, value, f"{path}.tool_calls")
            elif key == "function_call" and isinstance(value, Mapping):
                if parts.function_call is None:
                    parts.function_call = {"name": "", "arguments": ""}
                self._absorb_function(parts.function_call, value, f"{path}.{key}")
            else:
                self.dropped.add(_child(path, key))

    def _absorb_tool_calls(self, parts: _ChoiceParts, value: Any, path: str) -> None:
        if not isinstance(value, list):
            self.dropped.add(path)
            return
        for pos, raw in enumerate(value):
            if not isinstance(raw, Mapping):
                self.dropped.add(f"{path}[]")
                continue
            for key in _unlisted(raw, _CHUNK_TOOL_CALL_FIELDS):
                self.dropped.add(f"{path}[].{key}")
            index = _count(raw.get("index"))
            call = parts.tool_calls.setdefault(
                pos if index is None else index, _ToolCallParts()
            )
            call_id = raw.get("id")
            if isinstance(call_id, str):
                call.call_id = call_id or call.call_id
            elif call_id is not None:
                self.dropped.add(f"{path}[].id")
            call_type = raw.get("type")
            if call_type is not None and call_type != "function":
                call.is_function = False
            function = raw.get("function")
            if isinstance(function, Mapping):
                self._absorb_function(call.function, function, f"{path}[].function")
            elif function is not None:
                self.dropped.add(f"{path}[].function")

    def _absorb_function(
        self, target: dict[str, str], fragment: Mapping[str, Any], path: str
    ) -> None:
        for key, value in fragment.items():
            if value is None:
                continue
            if key in _FUNCTION_FIELDS and isinstance(value, str):
                target[key] += value
            else:
                self.dropped.add(f"{path}.{key}")

    def assemble(self) -> dict[str, Any]:
        """Return the accumulated stream as one ``chat.completion``-shaped body."""
        choices: list[dict[str, Any]] = []
        for index in sorted(self._choices):
            parts = self._choices[index]
            message: dict[str, Any] = {"role": "assistant", **parts.text}
            calls: list[dict[str, Any]] = []
            for _, call in sorted(parts.tool_calls.items()):
                if not call.is_function:
                    self.dropped.add("choices[].delta.tool_calls[]")
                    continue
                calls.append(
                    {
                        "id": call.call_id or None,
                        "type": "function",
                        "function": dict(call.function),
                    }
                )
            if calls:
                message["tool_calls"] = calls
            if parts.function_call is not None:
                message["function_call"] = dict(parts.function_call)
            choices.append(
                {
                    "index": index,
                    "message": message,
                    "finish_reason": parts.finish_reason,
                }
            )
        completion: dict[str, Any] = {"choices": choices}
        for key, value in (
            ("id", self._id),
            ("created", self._created),
            ("model", self._model),
            ("usage", self._usage),
        ):
            if value is not None:
                completion[key] = value
        return completion


async def sanitize_stream(
    assembler: StreamAssembler,
    masker: EgressMasker,
    *,
    fallback_model: str,
    now: int,
) -> tuple[dict[str, Any], EgressReport]:
    """Sanitize an assembled stream exactly as a non-streaming completion.

    The returned report also counts the fields the assembler dropped from the
    upstream frames. Encode the returned body with :func:`encode_sse_frames`.
    """
    completion, report = await sanitize_completion(
        assembler.assemble(), masker, fallback_model=fallback_model, now=now
    )
    report.dropped |= assembler.dropped
    return completion, report


def _sse_frame(payload: Mapping[str, Any]) -> bytes:
    return f"data: {json.dumps(payload)}\n\n".encode()


def _default_finish_reason(message: Mapping[str, Any]) -> str:
    if message.get("tool_calls"):
        return "tool_calls"
    if message.get("function_call") is not None:
        return "function_call"
    return "stop"


def encode_sse_frames(completion: Mapping[str, Any]) -> list[bytes]:
    """Encode a sanitized completion as ``chat.completion.chunk`` SSE frames.

    Emits one frame carrying every choice's whole delta, one frame carrying
    each choice's ``finish_reason`` (and ``usage``, when present), then
    ``[DONE]``. Only fields of *completion* are written, so the frames are
    exactly as allowlisted as the body :func:`sanitize_completion` built.
    """
    envelope = {
        "id": completion["id"],
        "object": CHUNK_OBJECT,
        "created": completion["created"],
        "model": completion["model"],
    }
    delta_choices: list[dict[str, Any]] = []
    finish_choices: list[dict[str, Any]] = []
    for choice in completion["choices"]:
        message = choice["message"]
        delta: dict[str, Any] = {"role": "assistant"}
        for key in _TEXT_FIELDS:
            if message.get(key) is not None:
                delta[key] = message[key]
        if message.get("tool_calls"):
            delta["tool_calls"] = [
                {"index": pos, **call} for pos, call in enumerate(message["tool_calls"])
            ]
        if message.get("function_call") is not None:
            delta["function_call"] = message["function_call"]
        delta_choices.append(
            {"index": choice["index"], "delta": delta, "finish_reason": None}
        )
        finish_choices.append(
            {
                "index": choice["index"],
                "delta": {},
                "finish_reason": choice.get("finish_reason")
                or _default_finish_reason(message),
            }
        )
    final_chunk: dict[str, Any] = {**envelope, "choices": finish_choices}
    if "usage" in completion:
        final_chunk["usage"] = completion["usage"]
    return [
        _sse_frame({**envelope, "choices": delta_choices}),
        _sse_frame(final_chunk),
        b"data: [DONE]\n\n",
    ]


def _text_length(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, list):
        return sum(_text_length(part) for part in value)
    if isinstance(value, Mapping):
        return sum(_text_length(v) for k, v in value.items() if k != "type")
    return 0


def completion_text_length(completion: Mapping[str, Any]) -> int:
    """Total characters of returned message text, for length-only telemetry."""
    return sum(
        _text_length(choice["message"].get(key))
        for choice in completion["choices"]
        for key in _TEXT_FIELDS
    )
