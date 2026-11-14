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

"""Gateway ingress out-of-band workload quarantine enforcement (SC-7 / AC-3).

Shared across ``governance_middleware.py`` (``/governance/validate-action``,
``/governance/policy-precheck``) and ``mcp_tool_server.py`` (``/mcp``,
``/tools/execute``), matching the verified ``l5d-client-id`` workload identity
extraction and blocking ``EvidenceStreamSink`` SC-7 refusal behavior of
``inference_proxy.py``.
"""

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

from opentelemetry import trace

from src.gateway.governance.evidence.stream import (
    EvidenceChainUnavailableError,
    commit_decision_evidence,
    get_evidence_sink,
    is_evidence_chain_blocking,
)
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import get_governance_signer
from src.gateway.governance.quarantine_actuator import is_workload_quarantined
from src.gateway.infrastructure.privacy import scrub_pii
from src.gateway.server.workload_identity import (
    current_client_identity,
    extract_client_identity,
)

logger = logging.getLogger("Gateway.QuarantineGuard")

_QUARANTINE_REASON = "Workload SVID or thread is quarantined"
_QUARANTINE_MESSAGE = (
    "Workload SVID or thread is quarantined by CAGE out-of-band governance"
)
_MAX_MCP_INSPECT_BYTES = 65536


def _state_attr(app_obj: Any, name: str) -> Any:
    """Read an explicitly configured attribute from a Starlette ``State`` or namespace."""
    state = getattr(app_obj, "state", None)
    if state is None:
        return None
    state_dict = getattr(state, "_state", None)
    if isinstance(state_dict, dict):
        return state_dict.get(name)
    try:
        return vars(state).get(name)
    except TypeError:
        return None


def resolve_verified_workload_identity(scope: Mapping[str, Any]) -> str | None:
    """Return verified Linkerd caller identity from ``workload_identity.py`` only."""
    identity = current_client_identity()
    if identity is not None:
        return identity
    try:
        return extract_client_identity(scope)
    except Exception:
        return None


def extract_candidate_thread_ids(
    scope: Mapping[str, Any],
    body_params: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return distinct non-empty ``thread_id`` values from body params and headers."""
    found: list[str] = []
    if isinstance(body_params, Mapping):
        raw_param = body_params.get("thread_id")
        if isinstance(raw_param, str) and raw_param.strip():
            found.append(raw_param.strip())
    raw_headers = scope.get("headers")
    if isinstance(raw_headers, (list, tuple)):
        for k, v in raw_headers:
            if (
                isinstance(k, bytes)
                and k.lower() == b"x-cage-thread-id"
                and isinstance(v, bytes)
            ):
                decoded = v.decode("latin-1", errors="ignore").strip()
                if decoded and decoded not in found:
                    found.append(decoded)
    return tuple(found)


async def _emit_quarantine_refusal(
    *,
    action_id: str,
    surface: str,
    agent_id: str | None,
    thread_id: str | None,
    app_obj: Any = None,
) -> str:
    """Commit a KMS-signed SC-7 ``GOVERNANCE_REFUSAL_RECEIPT`` to ``EvidenceStreamSink``."""
    receipt_id = str(uuid.uuid4())
    timestamp_utc = datetime.now(tz=timezone.utc).isoformat()
    clean_reason = scrub_pii(_QUARANTINE_REASON)
    proof_hash = hashlib.sha256(
        jcs_canonicalize_plan(
            {
                "action_id": action_id,
                "agent_id": agent_id or "",
                "oscal_control_ref": "SC-7",
                "receipt_id": receipt_id,
                "refusal_reason": clean_reason,
                "surface": surface,
                "thread_id": thread_id or "",
                "timestamp_utc": timestamp_utc,
            }
        )
    ).hexdigest()

    event: dict[str, Any] = {
        "type": "GOVERNANCE_REFUSAL_RECEIPT",
        "receipt_id": receipt_id,
        "action_id": action_id,
        "control_id": "SC-7",
        "oscal_control_ref": "SC-7",
        "decision": "DENY",
        "surface": surface,
        "status_code": 403,
        "refusal_reason": clean_reason,
        "proof_hash": proof_hash,
        "kms_signature": "",
        "timestamp_utc": timestamp_utc,
    }
    if agent_id:
        event["agent_id"] = agent_id
    if thread_id:
        event["thread_id"] = thread_id

    try:
        signer = get_governance_signer()
        signable = {k: v for k, v in event.items() if k != "kms_signature"}
        event["kms_signature"] = await signer.sign_async(signable)
    except Exception as sign_exc:
        logger.error(
            "Failed to KMS-sign SC-7 quarantine refusal receipt (receipt_id=%s): %s",
            receipt_id,
            sign_exc,
        )

    blocking = is_evidence_chain_blocking()
    sink = _state_attr(app_obj, "evidence_sink") or get_evidence_sink()
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
        else:
            ingest_res = sink.ingest(event)
            if inspect.isawaitable(ingest_res):
                await ingest_res
    except EvidenceChainUnavailableError:
        logger.error(
            "Quarantine refusal evidence emission failed closed (surface=%s, control=SC-7)",
            surface,
        )
        if blocking:
            raise
    except Exception as exc:
        logger.error(
            "Quarantine refusal evidence emission failed (surface=%s, control=SC-7): %s",
            surface,
            exc,
        )
        if blocking:
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
    shared_redis = _state_attr(app_obj, "redis") or _state_attr(
        fallback_app_obj, "redis"
    )

    matched_thread: str | None = candidates[0] if candidates else None
    quarantined = False
    if not candidates:
        quarantined = await is_workload_quarantined(
            thread_id=None, agent_svid=agent_id, redis_client=shared_redis
        )
    else:
        for idx, candidate in enumerate(candidates):
            if await is_workload_quarantined(
                thread_id=candidate,
                agent_svid=agent_id if idx == 0 else None,
                redis_client=shared_redis,
            ):
                matched_thread = candidate
                quarantined = True
                break
    if not quarantined:
        return None

    stamp_iso_control(
        trace.get_current_span(), ingress_stage=1, control="SC-7", outcome="BLOCK"
    )
    sink_owner = (
        app_obj
        if _state_attr(app_obj, "evidence_sink") is not None
        else (fallback_app_obj if fallback_app_obj is not None else app_obj)
    )
    try:
        proof_hash = await _emit_quarantine_refusal(
            action_id=action_id,
            surface=surface,
            agent_id=agent_id,
            thread_id=matched_thread,
            app_obj=sink_owner,
        )
    except EvidenceChainUnavailableError as exc:
        return 503, {"error": "evidence_chain_unavailable", "detail": str(exc)}

    logger.warning(
        "Quarantined workload refused on %s (action=%s, agent_id=%s, thread_id=%s)",
        surface,
        action_id,
        agent_id,
        matched_thread,
    )
    return (
        403,
        {
            "error": "workload_quarantined",
            "message": _QUARANTINE_MESSAGE,
            "agent_id": agent_id,
            "thread_id": matched_thread,
            "proof_hash": proof_hash,
        },
    )


class McpQuarantineMiddleware:
    """ASGI middleware enforcing out-of-band SC-7 workload quarantine on ``/mcp``."""

    def __init__(self, inner_app: Any, *, state_owner: Any = None) -> None:
        self.app = inner_app
        self.state_owner = state_owner

    @staticmethod
    async def _send_json(send: Any, status_code: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(encoded)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": encoded})

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if not isinstance(scope, dict) or scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        scope_app = scope.get("app")
        refusal = await check_and_refuse_quarantined_workload(
            scope,
            action_id="mcp_streamable_http",
            surface="mcp_tool_server",
            app_obj=scope_app,
            fallback_app_obj=self.state_owner,
        )
        if refusal is not None:
            await self._send_json(send, refusal[0], refusal[1])
            return

        if str(scope.get("method", "")).upper() != "POST":
            await self.app(scope, receive, send)
            return

        buffered: collections.deque[dict[str, Any]] = collections.deque()
        raw_chunks: list[bytes] = []
        total_bytes = 0
        complete = False
        while total_bytes <= _MAX_MCP_INSPECT_BYTES:
            msg = await receive()
            buffered.append(msg)
            if msg.get("type") != "http.request":
                break
            chunk = msg.get("body", b"")
            if isinstance(chunk, bytes) and chunk:
                raw_chunks.append(chunk)
                total_bytes += len(chunk)
            if not msg.get("more_body", False):
                complete = True
                break

        if complete and raw_chunks and total_bytes <= _MAX_MCP_INSPECT_BYTES:
            try:
                rpc_body = json.loads(b"".join(raw_chunks))
            except Exception:
                rpc_body = None
            rpc_items = (
                rpc_body
                if isinstance(rpc_body, list)
                else ([rpc_body] if isinstance(rpc_body, dict) else [])
            )
            checked_hdrs = set(extract_candidate_thread_ids(scope))
            for item in rpc_items:
                if not isinstance(item, dict):
                    continue
                rpc_params = item.get("params")
                if not isinstance(rpc_params, dict):
                    continue
                rpc_args = rpc_params.get("arguments")
                rpc_thread = (
                    rpc_args.get("thread_id") if isinstance(rpc_args, dict) else None
                )
                if not isinstance(rpc_thread, str) or not rpc_thread.strip():
                    continue
                cleaned_thread = rpc_thread.strip()
                if cleaned_thread in checked_hdrs:
                    continue
                checked_hdrs.add(cleaned_thread)
                rpc_tool = (
                    rpc_params["name"]
                    if isinstance(rpc_params.get("name"), str)
                    else "mcp_streamable_http"
                )
                rpc_refusal = await check_and_refuse_quarantined_workload(
                    scope,
                    action_id=rpc_tool,
                    surface="mcp_tool_server",
                    app_obj=scope_app,
                    fallback_app_obj=self.state_owner,
                    explicit_thread_id=cleaned_thread,
                )
                if rpc_refusal is not None:
                    await self._send_json(send, rpc_refusal[0], rpc_refusal[1])
                    return

        async def _replay_receive() -> dict[str, Any]:
            if buffered:
                return buffered.popleft()
            return await receive()  # type: ignore[no-any-return]

        await self.app(scope, _replay_receive, send)
