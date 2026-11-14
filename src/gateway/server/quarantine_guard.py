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

"""Gateway ingress out-of-band workload quarantine enforcement (SC-7 / AC-3)."""

from __future__ import annotations

import collections
import hashlib
import inspect
import json
import logging
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.propagate import extract as otel_extract

from src.gateway.governance.evidence.stream import (
    EvidenceChainUnavailableError,
    commit_decision_evidence,
    get_evidence_sink,
    is_evidence_chain_blocking,
)
from src.gateway.governance.governor.metrics import governor_metrics
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import get_governance_signer
from src.gateway.governance.quarantine_actuator import is_workload_quarantined
from src.gateway.infrastructure.privacy import scrub_pii
from src.gateway.observability.mcp_tracing import sanitize_trace_carrier
from src.gateway.server.workload_identity import (
    current_client_identity,
    extract_client_identity,
)

logger = logging.getLogger("Gateway.QuarantineGuard")
tracer = trace.get_tracer("gateway.quarantine_guard")

_QUARANTINE_REASON = "Workload SVID or thread is quarantined"
_QUARANTINE_MESSAGE = (
    "Workload SVID or thread is quarantined by CAGE out-of-band governance"
)
_MAX_MCP_INSPECT_BYTES = 65536


def _state_attr(app: Any, name: str) -> Any:
    if (s := getattr(app, "state", None)) is None:
        return None
    d = getattr(s, "_state", None)
    return d.get(name) if isinstance(d, dict) else getattr(s, "__dict__", {}).get(name)


def _resolve_backend(name: str, *apps: Any) -> Any:
    for a in apps:
        if (v := _state_attr(a, name)) is not None:
            return v
    try:
        from src.gateway.server.inference_proxy import inference_app

        return _state_attr(inference_app, name)
    except Exception:
        return None


def resolve_verified_workload_identity(scope: Mapping[str, Any]) -> str | None:
    """Return verified Linkerd caller identity from ``workload_identity.py`` only."""
    if (ident := current_client_identity()) is not None:
        return ident
    try:
        return extract_client_identity(scope)
    except Exception:
        return None


def extract_candidate_thread_ids(
    scope: Mapping[str, Any], body_params: Mapping[str, Any] | None = None
) -> tuple[str, ...]:
    """Return candidate thread_ids from body params and x-cage-thread-id header."""
    found: list[str] = []
    if isinstance(body_params, Mapping) and (
        p := str(body_params.get("thread_id", "")).strip()
    ):
        found.append(p)
    for k, v in scope.get("headers") or ():
        if (
            isinstance(k, bytes)
            and k.lower() == b"x-cage-thread-id"
            and isinstance(v, bytes)
        ):
            if (s := v.decode("latin-1", "ignore").strip()) and s not in found:
                found.append(s)
    return tuple(found)


async def _emit_quarantine_refusal(
    *,
    action_id: str,
    surface: str,
    agent_id: str | None,
    thread_id: str | None,
    sink: Any,
) -> str:
    receipt_id = str(uuid.uuid4())
    ts = datetime.now(tz=timezone.utc).isoformat()
    reason = scrub_pii(_QUARANTINE_REASON)
    proof_hash = hashlib.sha256(
        jcs_canonicalize_plan(
            {
                "action_id": action_id,
                "agent_id": agent_id or "",
                "oscal_control_ref": "SC-7",
                "receipt_id": receipt_id,
                "refusal_reason": reason,
                "surface": surface,
                "thread_id": thread_id or "",
                "timestamp_utc": ts,
            }
        )
    ).hexdigest()
    governor_metrics().refusal_decided("MIDDLEWARE")
    event: dict[str, Any] = {
        "type": "GOVERNANCE_REFUSAL_RECEIPT",
        "receipt_id": receipt_id,
        "action_id": action_id,
        "control_id": "SC-7",
        "oscal_control_ref": "SC-7",
        "decision": "DENY",
        "surface": surface,
        "status_code": 403,
        "refusal_reason": reason,
        "proof_hash": proof_hash,
        "kms_signature": "",
        "timestamp_utc": ts,
        **({"agent_id": agent_id} if agent_id else {}),
        **({"thread_id": thread_id} if thread_id else {}),
    }
    try:
        event["kms_signature"] = await get_governance_signer().sign_async(
            {k: v for k, v in event.items() if k != "kms_signature"}
        )
    except Exception as exc:
        logger.error("Failed to KMS-sign SC-7 refusal %s: %s", receipt_id, exc)

    blocking = is_evidence_chain_blocking()
    if not blocking and (sink is None or not getattr(sink, "_running", False)):
        return proof_hash
    try:
        if blocking:
            await commit_decision_evidence(
                event,
                label="GOVERNANCE_REFUSAL_RECEIPT",
                sink=sink,
                sentinel_unset=False,
            )
        elif inspect.isawaitable(res := sink.ingest(event)):
            await res
    except Exception as exc:
        governor_metrics().evidence_publish_failure("refusal_receipt")
        if blocking:
            if isinstance(exc, EvidenceChainUnavailableError):
                raise
            raise EvidenceChainUnavailableError(
                f"Evidence sink failed to commit GOVERNANCE_REFUSAL_RECEIPT: {exc}",
                exc,
            ) from exc
    return proof_hash


async def check_and_refuse_quarantined_workload(
    scope: Mapping[str, Any],
    *,
    action_id: str,
    surface: str,
    app_obj: Any = None,
    fallback_app_obj: Any = None,
    body_params: Mapping[str, Any] | None = None,
    explicit_thread_id: str | None = None,
) -> tuple[int, dict[str, Any]] | None:
    """Return ``(status_code, json_payload)`` when caller SVID or thread is quarantined."""
    agent_id = resolve_verified_workload_identity(scope)
    candidates = (
        (explicit_thread_id,)
        if explicit_thread_id is not None
        else extract_candidate_thread_ids(scope, body_params)
    )
    if agent_id is None and not candidates:
        return None

    redis = _resolve_backend("redis", app_obj, fallback_app_obj)
    matched_thread: str | None = candidates[0] if candidates else None
    quarantined = False
    for idx, candidate in enumerate(candidates or (None,)):
        if await is_workload_quarantined(
            thread_id=candidate,
            agent_svid=agent_id if idx == 0 else None,
            redis_client=redis,
        ):
            matched_thread = candidate
            quarantined = True
            break
    if not quarantined:
        return None

    sink = (
        _resolve_backend("evidence_sink", app_obj, fallback_app_obj)
        or get_evidence_sink()
    )
    hdrs = {
        k.decode("latin-1", "ignore"): v.decode("latin-1", "ignore")
        for k, v in (scope.get("headers") or ())
        if isinstance(k, bytes) and isinstance(v, bytes)
    }
    with tracer.start_as_current_span(
        "cage.quarantine_guard",
        context=otel_extract(sanitize_trace_carrier(hdrs)),
    ) as span:
        stamp_iso_control(span, ingress_stage=1, control="SC-7", outcome="BLOCK")
        try:
            proof_hash = await _emit_quarantine_refusal(
                action_id=action_id,
                surface=surface,
                agent_id=agent_id,
                thread_id=matched_thread,
                sink=sink,
            )
        except EvidenceChainUnavailableError as exc:
            return 503, {"error": "evidence_chain_unavailable", "detail": str(exc)}

    logger.warning(
        "Quarantined workload refused on %s (action=%s, agent=%s)",
        surface,
        action_id,
        agent_id,
    )
    return 403, {
        "error": "workload_quarantined",
        "message": _QUARANTINE_MESSAGE,
        "agent_id": agent_id,
        "thread_id": matched_thread,
        "proof_hash": proof_hash,
    }


async def refuse_if_quarantined(
    request: Any,
    *,
    action_id: str,
    surface: str,
    body_params: Mapping[str, Any] | None = None,
    fallback_app_obj: Any = None,
) -> JSONResponse | None:
    """FastAPI helper returning a 403/503 ``JSONResponse`` when caller is quarantined."""
    scope = getattr(request, "scope", None)
    if not isinstance(scope, Mapping):
        hdrs_list: list[tuple[bytes, bytes]] = []
        if isinstance(raw_hdrs := getattr(request, "headers", None), Mapping):
            for k, v in raw_hdrs.items():
                hdrs_list.append(
                    (str(k).lower().encode("latin-1"), str(v).encode("latin-1"))
                )
        scope = {"type": "http", "headers": hdrs_list}
    if ref := await check_and_refuse_quarantined_workload(
        scope,
        action_id=action_id,
        surface=surface,
        app_obj=getattr(request, "app", None),
        fallback_app_obj=fallback_app_obj,
        body_params=body_params,
    ):
        return JSONResponse(status_code=ref[0], content=ref[1])
    return None


class McpQuarantineMiddleware:
    """ASGI middleware enforcing out-of-band SC-7 workload quarantine on ``/mcp``."""

    def __init__(self, inner_app: Any, *, state_owner: Any = None) -> None:
        self.app, self.state_owner = inner_app, state_owner

    @staticmethod
    async def _send_json(send: Any, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": raw})

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if not isinstance(scope, dict) or scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        scope_app = scope.get("app")
        if refusal := await check_and_refuse_quarantined_workload(
            scope,
            action_id="mcp_streamable_http",
            surface="mcp_tool_server",
            app_obj=scope_app,
            fallback_app_obj=self.state_owner,
        ):
            await self._send_json(send, refusal[0], refusal[1])
            return
        if str(scope.get("method", "")).upper() != "POST":
            await self.app(scope, receive, send)
            return

        buffered: collections.deque[dict[str, Any]] = collections.deque()
        chunks: list[bytes] = []
        total = 0
        while total <= _MAX_MCP_INSPECT_BYTES:
            msg = await receive()
            buffered.append(msg)
            if msg.get("type") != "http.request":
                break
            if isinstance(chunk := msg.get("body", b""), bytes) and chunk:
                chunks.append(chunk)
                total += len(chunk)
            if not msg.get("more_body", False):
                break

        if total > _MAX_MCP_INSPECT_BYTES:
            await self._send_json(
                send,
                413,
                {
                    "error": "payload_too_large",
                    "message": (
                        f"MCP request body exceeds {_MAX_MCP_INSPECT_BYTES} "
                        "bytes inspection limit"
                    ),
                },
            )
            return

        if chunks and total <= _MAX_MCP_INSPECT_BYTES:
            try:
                parsed = json.loads(b"".join(chunks))
            except Exception:
                parsed = None
            items = (
                parsed
                if isinstance(parsed, list)
                else ([parsed] if isinstance(parsed, dict) else [])
            )
            seen = set(extract_candidate_thread_ids(scope))
            for item in items:
                params = item.get("params") if isinstance(item, dict) else None
                args = params.get("arguments") if isinstance(params, dict) else None
                raw_tid = args.get("thread_id") if isinstance(args, dict) else None
                if (
                    isinstance(raw_tid, str)
                    and (tid := raw_tid.strip())
                    and tid not in seen
                ):
                    seen.add(tid)
                    tool_val = params.get("name") if isinstance(params, dict) else None
                    tool = tool_val if isinstance(tool_val, str) else "mcp_streamable_http"
                    if rpc_ref := await check_and_refuse_quarantined_workload(
                        scope,
                        action_id=tool,
                        surface="mcp_tool_server",
                        app_obj=scope_app,
                        fallback_app_obj=self.state_owner,
                        explicit_thread_id=tid,
                    ):
                        await self._send_json(send, rpc_ref[0], rpc_ref[1])
                        return

        async def _replay() -> dict[str, Any]:
            return buffered.popleft() if buffered else await receive()  # type: ignore[no-any-return]

        await self.app(scope, _replay, send)
