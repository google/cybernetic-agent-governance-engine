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
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.propagate import extract as otel_extract
from opentelemetry.trace import Status, StatusCode

from src.gateway.governance import env_posture as _env_posture
from src.gateway.governance.evidence.stream import (
    EvidenceChainUnavailableError,
    commit_decision_evidence,
    get_evidence_sink,
    is_evidence_chain_blocking,
)
from src.gateway.governance.governor.metrics import (
    governor_metrics,
    mark_request_evidenced,
)
from src.gateway.governance.governor.verdicts import publish_infrastructure_block
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import get_governance_signer
from src.gateway.governance.quarantine_actuator import probe_workload_quarantine
from src.gateway.infrastructure.privacy import scrub_pii
from src.gateway.observability.mcp_tracing import sanitize_trace_carrier
from src.gateway.server import workload_identity as _workload_identity

logger = logging.getLogger("Gateway.QuarantineGuard")
tracer = trace.get_tracer("gateway.quarantine_guard")

_QUARANTINE_REASON = "Workload SVID or thread is quarantined"
_QUARANTINE_MESSAGE = (
    "Workload SVID or thread is quarantined by CAGE out-of-band governance"
)
_MAX_MCP_INSPECT_BYTES = 65536


def _state_dict_of(app: Any) -> dict[str, Any] | None:
    s = getattr(app, "state", None)
    if s is None:
        return None
    d = getattr(s, "_state", None)
    if isinstance(d, dict):
        return d
    raw = getattr(s, "__dict__", None)
    return raw if isinstance(raw, dict) else None


def _resolve_redis(*apps: Any) -> Any:
    for app in apps:
        d = _state_dict_of(app)
        if d is not None and (v := d.get("redis")) is not None:
            return v
    return None


def resolve_verified_workload_identity(scope: Mapping[str, Any]) -> str | None:
    """Return verified Linkerd caller identity from ``workload_identity.py`` only."""
    if (ident := _workload_identity.current_client_identity()) is not None:
        return ident
    try:
        return _workload_identity.extract_client_identity(scope)
    except Exception:
        return None


def _extract_thread_id(val: Any) -> str | None:
    """Safely extract a non-empty string thread ID from scalar values.

    Rejects None, collections (dict, list, set, tuple), booleans, empty strings,
    and literal 'none'/'null' sentinels.
    """
    if val is None or isinstance(val, (dict, list, set, tuple, bool)):
        return None
    s = str(val).strip()
    if not s or s.lower() in ("none", "null"):
        return None
    return s


def _append_mapping_threads(mapping: Mapping[str, Any], found: list[str]) -> None:
    for key in ("thread_id", "threadId"):
        if (tid := _extract_thread_id(mapping.get(key))) and tid not in found:
            found.append(tid)


def extract_candidate_thread_ids(
    scope: Mapping[str, Any], body_params: Mapping[str, Any] | None = None
) -> tuple[str, ...]:
    """Return candidate thread_ids from body/linkage/arguments/params and x-cage-thread-id headers."""
    found: list[str] = []
    if isinstance(body_params, Mapping):
        _append_mapping_threads(body_params, found)
        for nested_key in ("arguments", "params", "linkage"):
            if isinstance(nested := body_params.get(nested_key), Mapping):
                _append_mapping_threads(nested, found)
    for k, v in scope.get("headers") or ():
        if (
            isinstance(k, bytes)
            and k.lower() == b"x-cage-thread-id"
            and isinstance(v, bytes)
        ):
            decoded = v.decode("latin-1", "ignore").strip()
            if (s := _extract_thread_id(decoded)) and s not in found:
                found.append(s)
    return tuple(found)


class _QuarantineKmsSigningError(Exception):
    """Raised when KMS signing fails on a confirmed quarantine refusal."""


async def _emit_quarantine_infrastructure_block(
    *,
    span: Any,
    action_id: str,
    dependency: str,
    failure_code: str,
    detail: str,
    body_params: Mapping[str, Any] | None,
    thread_id: str | None,
    sink: Any,
) -> tuple[int, dict[str, Any]]:
    """Fail closed with HTTP 503 and an unsigned ``GOVERNANCE_INFRASTRUCTURE_BLOCK``."""
    clean_detail = scrub_pii(detail)
    span.set_attribute("cage.verdict", "INFRASTRUCTURE_BLOCK")
    span.set_attribute("cage.infrastructure.dependency", dependency)
    span.set_attribute("cage.infrastructure.failure_code", failure_code)
    span.set_status(Status(StatusCode.ERROR))

    mark_request_evidenced()
    governor_metrics().infrastructure_block_decided(dependency, failure_code)

    infra_params: dict[str, Any] = (
        dict(body_params) if isinstance(body_params, Mapping) else {}
    )
    if thread_id and "thread_id" not in infra_params:
        infra_params["thread_id"] = thread_id

    if is_evidence_chain_blocking() or sink is not None:
        try:
            await publish_infrastructure_block(
                action=action_id,
                params=infra_params,
                dependency=dependency,
                failure_code=failure_code,
                detail=clean_detail,
                control_id="SC-7",
            )
        except EvidenceChainUnavailableError as exc:
            return 503, {
                "error": "evidence_chain_unavailable",
                "detail": scrub_pii(str(exc)),
            }
        except Exception as exc:
            logger.error(
                "Failed to publish quarantine infrastructure block (%s/%s): %s",
                dependency,
                failure_code,
                exc,
            )

    return 503, {
        "error": "governance_dependency_unavailable",
        "dependency": dependency,
        "failure_code": failure_code,
        "detail": clean_detail,
    }


async def _sign_quarantine_event(
    signable: dict[str, Any],
    *,
    receipt_id: str,
    action_id: str,
) -> str:
    """Sign an SC-7 refusal receipt, matching ``_sign_refusal_receipt()`` (#840)."""
    signer = get_governance_signer()
    active = bool(
        getattr(signer, "is_kms_active", True)
        and getattr(signer, "kms_active", True) is not False
    )
    if not active:
        if not _env_posture.is_enforcing(_env_posture.resolve_posture()):
            logger.warning(
                "No active refusal-receipt signer in a non-enforcing posture: "
                "SC-7 quarantine receipt %s for action %r is emitted unsigned "
                "and is not evidence.",
                receipt_id,
                action_id,
            )
            return ""
        raise RuntimeError("no active refusal-receipt signer in an enforcing posture")
    signature = await signer.sign_async(signable)
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("KMS signer returned an empty signature")
    return signature


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
        event["kms_signature"] = await _sign_quarantine_event(
            {k: v for k, v in event.items() if k != "kms_signature"},
            receipt_id=receipt_id,
            action_id=action_id,
        )
    except Exception as exc:
        logger.error(
            "Failed to KMS-sign SC-7 refusal %s; failing closed as 503 infrastructure block: %s",
            receipt_id,
            exc,
        )
        raise _QuarantineKmsSigningError(f"{type(exc).__name__}: {exc}") from exc

    mark_request_evidenced()
    governor_metrics().refusal_decided("MIDDLEWARE")

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


def _quarantine_span_context(scope: Mapping[str, Any], parent_span: Any) -> Any:
    if parent_span is not None:
        return nullcontext(parent_span)
    hdrs = {
        k.decode("latin-1", "ignore"): v.decode("latin-1", "ignore")
        for k, v in (scope.get("headers") or ())
        if isinstance(k, bytes) and isinstance(v, bytes)
    }
    return tracer.start_as_current_span(
        "cage.quarantine_guard",
        context=otel_extract(sanitize_trace_carrier(hdrs)),
    )


async def check_and_refuse_quarantined_workload(
    scope: Mapping[str, Any],
    *,
    action_id: str,
    surface: str,
    app_obj: Any = None,
    fallback_app_obj: Any = None,
    body_params: Mapping[str, Any] | None = None,
    explicit_thread_id: str | None = None,
    verified_agent_id: str | None = None,
    span: Any = None,
) -> tuple[int, dict[str, Any]] | None:
    """Return ``(status_code, json_payload)`` when caller SVID/thread is quarantined or backend fails."""
    agent_id = (
        verified_agent_id
        if verified_agent_id is not None
        else resolve_verified_workload_identity(scope)
    )
    candidates: tuple[str, ...]
    if explicit_thread_id is not None:
        clean_exp = _extract_thread_id(explicit_thread_id)
        candidates = (clean_exp,) if clean_exp is not None else ()
    else:
        candidates = extract_candidate_thread_ids(scope, body_params)
    if agent_id is None and not candidates:
        return None

    redis = _resolve_redis(app_obj, fallback_app_obj)
    matched_thread: str | None = candidates[0] if candidates else None
    quarantined = False
    infra_failure: tuple[str, str, str] | None = None
    for idx, candidate in enumerate(candidates or (None,)):
        probe = await probe_workload_quarantine(
            thread_id=candidate,
            agent_svid=agent_id if idx == 0 else None,
            redis_client=redis,
        )
        if probe.unavailable_code is not None:
            matched_thread = candidate
            infra_failure = ("redis", probe.unavailable_code, probe.unavailable_detail)
            break
        if probe.quarantined:
            matched_thread = candidate
            quarantined = True
            break
    if not quarantined and infra_failure is None:
        return None

    sink = get_evidence_sink()
    with _quarantine_span_context(scope, span) as active_span:
        if infra_failure is not None:
            return await _emit_quarantine_infrastructure_block(
                span=active_span,
                action_id=action_id,
                dependency=infra_failure[0],
                failure_code=infra_failure[1],
                detail=infra_failure[2],
                body_params=body_params,
                thread_id=matched_thread,
                sink=sink,
            )
        try:
            proof_hash = await _emit_quarantine_refusal(
                action_id=action_id,
                surface=surface,
                agent_id=agent_id,
                thread_id=matched_thread,
                sink=sink,
            )
        except _QuarantineKmsSigningError as exc:
            return await _emit_quarantine_infrastructure_block(
                span=active_span,
                action_id=action_id,
                dependency="kms",
                failure_code="KMS_SIGNING_UNAVAILABLE",
                detail=str(exc),
                body_params=body_params,
                thread_id=matched_thread,
                sink=sink,
            )
        except EvidenceChainUnavailableError as exc:
            return 503, {
                "error": "evidence_chain_unavailable",
                "detail": scrub_pii(str(exc)),
            }
        stamp_iso_control(active_span, ingress_stage=1, control="SC-7", outcome="BLOCK")

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
    verified_agent_id: str | None = None,
    span: Any = None,
) -> JSONResponse | None:
    """FastAPI helper returning a 403/503 ``JSONResponse`` when caller is quarantined."""
    scope = getattr(request, "scope", None)
    if not isinstance(scope, Mapping):
        return None
    if ref := await check_and_refuse_quarantined_workload(
        scope,
        action_id=action_id,
        surface=surface,
        app_obj=scope.get("app"),
        fallback_app_obj=fallback_app_obj,
        body_params=body_params,
        verified_agent_id=verified_agent_id,
        span=span,
    ):
        return JSONResponse(status_code=ref[0], content=ref[1])
    return None


_PAYLOAD_TOO_LARGE_BODY: dict[str, Any] = {
    "error": "payload_too_large",
    "message": (
        f"MCP request body exceeds {_MAX_MCP_INSPECT_BYTES} bytes inspection limit"
    ),
}


def _exceeds_declared_content_length(scope: Mapping[str, Any]) -> bool:
    """Return True if any Content-Length header declares > ``_MAX_MCP_INSPECT_BYTES``."""
    for k, v in scope.get("headers") or ():
        if (
            isinstance(k, bytes)
            and k.lower() == b"content-length"
            and isinstance(v, bytes)
        ):
            try:
                if int(v.decode("latin-1", "ignore").strip()) > _MAX_MCP_INSPECT_BYTES:
                    return True
            except ValueError:
                continue
    return False


async def _read_bounded_mcp_body(
    receive: Any,
) -> tuple[collections.deque[dict[str, Any]], bytes, int, bool]:
    """Buffer ASGI ``http.request`` frames up to ``_MAX_MCP_INSPECT_BYTES``."""
    buffered: collections.deque[dict[str, Any]] = collections.deque()
    chunks: list[bytes] = []
    total = 0
    disconnected = False
    while total <= _MAX_MCP_INSPECT_BYTES:
        msg = await receive()
        msg_type = msg.get("type")
        if msg_type == "http.disconnect":
            disconnected = True
            break
        buffered.append(msg)
        if msg_type != "http.request":
            break
        if isinstance(chunk := msg.get("body", b""), bytes) and chunk:
            chunks.append(chunk)
            total += len(chunk)
        if not msg.get("more_body", False):
            break
    raw_body = b"".join(chunks) if (chunks and total <= _MAX_MCP_INSPECT_BYTES) else b""
    return buffered, raw_body, total, disconnected


def _extract_rpc_item_threads(item: dict[str, Any]) -> tuple[str, list[str]]:
    """Extract ``(tool_name, candidate_thread_ids)`` from a JSON-RPC request item."""
    params = item.get("params") if isinstance(item.get("params"), dict) else None
    args = (
        params.get("arguments")
        if params and isinstance(params.get("arguments"), dict)
        else None
    )
    tool_val = params.get("name") if params else None
    tool = tool_val if isinstance(tool_val, str) else "mcp_streamable_http"
    candidate_tids: list[str] = []
    for source in (args, params, item):
        if (
            isinstance(source, dict)
            and (t := _extract_thread_id(source.get("thread_id")))
            and t not in candidate_tids
        ):
            candidate_tids.append(t)
    return tool, candidate_tids


async def _inspect_mcp_jsonrpc_threads(
    scope: Mapping[str, Any],
    raw_body: bytes,
    *,
    app_obj: Any,
    fallback_app_obj: Any,
) -> tuple[int, dict[str, Any]] | None:
    """Inspect single or batch JSON-RPC payloads for quarantined ``thread_id`` values."""
    try:
        parsed = json.loads(raw_body)
    except Exception:
        return None
    items = (
        parsed
        if isinstance(parsed, list)
        else ([parsed] if isinstance(parsed, dict) else [])
    )
    seen = set(extract_candidate_thread_ids(scope))
    for item in items:
        if not isinstance(item, dict):
            continue
        tool, candidate_tids = _extract_rpc_item_threads(item)
        raw_p = item.get("params") if isinstance(item.get("params"), Mapping) else None
        rpc_params = (
            raw_p.get("arguments")
            if raw_p is not None and isinstance(raw_p.get("arguments"), Mapping)
            else raw_p
        )
        for tid in candidate_tids:
            if tid not in seen:
                seen.add(tid)
                if rpc_ref := await check_and_refuse_quarantined_workload(
                    scope,
                    action_id=tool,
                    surface="mcp_tool_server",
                    app_obj=app_obj,
                    fallback_app_obj=fallback_app_obj,
                    body_params=rpc_params,
                    explicit_thread_id=tid,
                ):
                    return rpc_ref
    return None


class McpQuarantineMiddleware:
    """ASGI middleware enforcing out-of-band SC-7 workload quarantine on ``/mcp``."""

    def __init__(self, inner_app: Any, *, state_owner: Any = None) -> None:
        self.app = inner_app
        self.state_owner = state_owner

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
        if _exceeds_declared_content_length(scope):
            await self._send_json(send, 413, _PAYLOAD_TOO_LARGE_BODY)
            return

        buffered, raw_body, total, disconnected = await _read_bounded_mcp_body(receive)
        if disconnected:
            return
        if total > _MAX_MCP_INSPECT_BYTES:
            await self._send_json(send, 413, _PAYLOAD_TOO_LARGE_BODY)
            return
        if raw_body and (
            rpc_ref := await _inspect_mcp_jsonrpc_threads(
                scope,
                raw_body,
                app_obj=scope_app,
                fallback_app_obj=self.state_owner,
            )
        ):
            await self._send_json(send, rpc_ref[0], rpc_ref[1])
            return

        async def _replay() -> dict[str, Any]:
            return buffered.popleft() if buffered else await receive()  # type: ignore[no-any-return]

        await self.app(scope, _replay, send)
