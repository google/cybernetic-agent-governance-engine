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
GatewayClient — async HTTP client for the governed inference gateway.

Governance previews (``POST /governance/validate-action``) go through the
installed ``cage-client`` wheel. ``CageClient`` resolves the gateway's signing
key out of band by ``kid`` from ``GET /governance/.well-known/jwks.json`` and
verifies each envelope's signature, ``expires_at`` freshness and
``subject.action_hash`` binding before the advisor routes on its verdict.

Uses a lazy singleton pattern so the underlying httpx.AsyncClient is
created only on the first call, not at import time.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import random
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

import httpx
from cage_client import (
    CageClient,
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from opentelemetry.propagate import inject as otel_inject

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.seams.state_commitment import (
    StateCommitmentError,
    StateCommitmentLinkage,
    StateCommitmentReceipt,
)
from src.governed_financial_advisor.graph.annotations import side_effect_node
from src.governed_financial_advisor.models.principal import principal_header_value

logger = logging.getLogger("infrastructure.gateway_client")

_GATEWAY_URL_DEFAULT = "http://localhost:8080"
_MAX_RETRY_ATTEMPTS = 3
_RETRY_BASE_SECONDS = 0.2
_RETRY_CAP_SECONDS = 2.0
_VALIDATE_ACTION_PATH = "/governance/validate-action"
#: ``agent_id`` the SDK sends with each preview. The gateway identifies the
#: caller by its mesh workload identity, never by this field.
_ADVISOR_AGENT_ID = "governed-financial-advisor"

#: Verdicts the advisor may route on. DENY arrives as HTTP 403; anything else
#: (including a missing or legacy verdict string) is refused.
_ROUTABLE_VERDICTS = frozenset(
    {
        GovernanceDecision.ALLOW,
        GovernanceDecision.NARROW,
        GovernanceDecision.REQUIRE_APPROVAL,
        GovernanceDecision.DEFER,
    }
)

#: Canonical advisory decisions returned by ``POST /governance/policy-precheck``.
_POLICY_PRECHECK_DECISIONS = frozenset({"ALLOW", "DENY", "MANUAL_REVIEW"})


def _violations(response: httpx.Response) -> list[str]:
    try:
        body = response.json()
    except ValueError:
        return ["governance denied"]
    violations = body.get("violations") if isinstance(body, dict) else None
    return [str(v) for v in violations] if violations else ["governance denied"]


def _is_policy_drift(response: httpx.Response) -> bool:
    return any("Substrate Policy Drift Detected" in v for v in _violations(response))


def _retry_delay_seconds(response: httpx.Response, attempt: int) -> float:
    """Compute bounded full-jitter backoff delay, honoring Retry-After when present."""
    cap = float(
        os.environ.get("CAGE_GATEWAY_RETRY_CAP_SECONDS", str(_RETRY_CAP_SECONDS))
    )
    base = float(
        os.environ.get("CAGE_GATEWAY_RETRY_BASE_SECONDS", str(_RETRY_BASE_SECONDS))
    )
    jitter_delay = random.uniform(0.0, min(cap, base * (2**attempt)))  # nosec B311  # non-cryptographic retry backoff jitter
    raw_retry_after = response.headers.get("Retry-After")
    if raw_retry_after:
        try:
            parsed = float(raw_retry_after)
            if parsed > 0:
                return min(cap, max(parsed, jitter_delay))
        except ValueError:
            pass
    return jitter_delay


async def _post_with_retries(
    send_fn: Callable[[], Awaitable[httpx.Response]],
    *,
    retry_statuses: frozenset[int],
    max_attempts: int = _MAX_RETRY_ATTEMPTS,
) -> httpx.Response:
    """Execute ``send_fn`` up to ``max_attempts`` times on transient HTTP status codes."""
    response = await send_fn()
    for attempt in range(max_attempts - 1):
        if response.status_code not in retry_statuses:
            return response
        delay = _retry_delay_seconds(response, attempt)
        logger.warning(
            "Gateway returned HTTP %d (attempt %d/%d); retrying in %.3fs",
            response.status_code,
            attempt + 1,
            max_attempts,
            delay,
        )
        await asyncio.sleep(delay)
        response = await send_fn()
    return response


@dataclass
class _Preview:
    """What one ``validate_action`` call shares with :class:`_AdvisorTransport`."""

    policy_version_id: str | None
    timeout: float
    #: The final ``/governance/validate-action`` response the SDK received.
    response: httpx.Response | None = None


_current_preview: contextvars.ContextVar[_Preview | None] = contextvars.ContextVar(
    "advisor_gateway_preview", default=None
)


class _AdvisorTransport(httpx.AsyncBaseTransport):
    """Sends the SDK's requests through the advisor's HTTP client.

    ``CageClient`` builds the governance exchange and verifies its answer.
    Sending it through the advisor's ``httpx.AsyncClient`` keeps the
    advisor's W3C trace context and ``x-cage-principal`` headers, its 429/503
    retry budget, and the policy-drift replay with a refreshed
    ``policy_version_id``.
    """

    def __init__(self, owner: GatewayClient, http: httpx.AsyncClient) -> None:
        self._owner = owner
        self._http = http

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        preview = _current_preview.get()
        timeout = preview.timeout if preview is not None else 60.0
        headers = {
            name.lower(): value
            for name, value in request.headers.items()
            if name.lower() not in {"host", "content-length"}
        }
        for name, value in self._owner._build_headers().items():
            headers[name.lower()] = value
        path = request.url.raw_path.decode("ascii")

        if request.method != "POST":
            return await self._http.request(
                request.method, path, headers=headers, timeout=timeout
            )

        body = json.loads(request.content)
        # Only the preview POST carries the pin and reports back its response.
        current = preview if path == _VALIDATE_ACTION_PATH else None
        if current is not None:
            body["policy_version_id"] = current.policy_version_id

        async def _post() -> httpx.Response:
            return await self._http.post(
                path, json=body, headers=headers, timeout=timeout
            )

        response = await _post_with_retries(_post, retry_statuses=frozenset({429, 503}))
        if (
            current is not None
            and response.status_code == 403
            and _is_policy_drift(response)
        ):
            logger.warning(
                "Substrate drift caught during session. Fetching updated baseline pin and replaying."
            )
            body["policy_version_id"] = await self._owner.get_policy_version(
                timeout=timeout
            )
            response = await _post_with_retries(
                _post, retry_statuses=frozenset({429, 503})
            )
        if current is not None:
            current.response = response
        return response


def _verified_result(response: httpx.Response | None) -> dict[str, Any]:
    """Unwrap the 200 envelope the SDK has verified: its payload plus provenance.

    The SDK verifies an envelope's signature, freshness and subject binding
    before it returns ALLOW or mediates any other verdict, so a mediated 200
    response is a verified one. A deferral or narrowing that did not arrive
    as a 200 envelope carries no signature and is refused.
    """
    if response is None or response.status_code != 200:
        raise PermissionError(
            "Governance answered without a signed envelope; refusing to route on it"
        )
    body = json.loads(response.content)
    nested = body.get("envelope")
    envelope: dict[str, Any] = nested if isinstance(nested, dict) and nested else body
    result = dict(envelope.get("payload") or {})
    for key in (
        "envelope_id",
        "envelope_version",
        "issuer",
        "subject",
        "signature",
        "governance_context",
    ):
        result[key] = envelope.get(key)
    result["external_attestations"] = envelope.get("external_attestations") or []
    return result


def _denial_reasons(
    exc: PolicyViolationException, response: httpx.Response | None
) -> str:
    details = exc.violation_details if isinstance(exc.violation_details, dict) else {}
    violations = details.get("violations")
    if isinstance(violations, list) and violations:
        return "; ".join(str(v) for v in violations)
    if response is not None and response.status_code != 200:
        return "; ".join(_violations(response))
    return exc.reason_code


def _raise_unrouted(
    action: str, exc: CageGatewayError, response: httpx.Response | None
) -> NoReturn:
    """Re-raise an SDK error the way the advisor's callers already handle it."""
    if isinstance(exc.__cause__, httpx.RequestError):
        # Transport failure or timeout: surface the original httpx error.
        raise exc.__cause__ from None
    if response is not None and response.status_code == 403:
        raise PermissionError(
            f"Governance DENIED '{action}': {'; '.join(_violations(response))}"
        ) from exc
    if response is not None and response.status_code >= 400:
        response.raise_for_status()
    raise PermissionError(
        f"Governance returned no routable verdict for '{action}': {exc}"
    ) from exc


class GatewayClient:
    """Singleton async HTTP client that calls the governance gateway."""

    _instance: GatewayClient | None = None
    #: The SDK client and the advisor ``httpx`` client it sends through.
    _sdk: CageClient | None
    _sdk_http: httpx.AsyncClient | None

    def __new__(cls) -> GatewayClient:
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._http: httpx.AsyncClient | None = None  # type: ignore[misc, has-type]  # non-self attribute assignment in __new__; type annotation on non-self attr
            instance._base_url: str = os.environ.get(  # type: ignore[misc, has-type, attr-defined]  # non-self attribute + has-type false positive
                "GATEWAY_URL", _GATEWAY_URL_DEFAULT
            )
            instance._sdk = None
            instance._sdk_http = None
            cls._instance = instance
        return cls._instance

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Lazily create the underlying AsyncClient."""
        if self._http is None or self._http.is_closed:  # type: ignore[has-type]  # _http type is determined by __new__; mypy cannot track non-self attribute types
            self._http = httpx.AsyncClient(
                base_url=self._base_url,  # type: ignore[attr-defined]
                timeout=60.0,
            )
        return self._http

    async def _ensure_sdk(self, http: httpx.AsyncClient, timeout: float) -> CageClient:
        """Return the ``CageClient`` that sends through ``http``.

        Rebuilt when ``http`` changes, so its JWKS cache never outlives the
        connection it was fetched over.
        """
        if self._sdk is not None and self._sdk_http is http:
            return self._sdk
        if self._sdk is not None:
            await self._sdk.aclose()
        base = httpx.URL(self._base_url)  # type: ignore[attr-defined]
        sdk = CageClient(
            gateway_url=f"{base.scheme}://{base.netloc.decode('ascii')}",
            timeout_s=timeout,
        )
        # cage-client 0.3.0 takes no transport argument, so its connection
        # pool is replaced by one that sends through the advisor's client.
        await sdk._client.aclose()
        sdk._client = httpx.AsyncClient(
            transport=_AdvisorTransport(self, http),
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
        )
        self._sdk = sdk
        self._sdk_http = http
        return sdk

    def _build_headers(self) -> dict[str, str]:
        """Construct outbound request headers with W3C trace context and x-cage-principal.

        ``x-cage-principal`` carries the end-user principal, sanitized once by
        :func:`principal_header_value`. ``x-cage-principal-verified`` records
        whether the advisor verified the principal against an out-of-band OIDC
        trust anchor (``"true"``) or accepted a caller assertion in a
        permissive posture (``"false"``).
        """
        from src.governed_financial_advisor.utils.context import (
            principal_verified_context,
            user_context,
        )

        headers: dict[str, str] = {"Content-Type": "application/json"}
        otel_inject(headers)
        principal = principal_header_value(user_context.get())
        verified = principal_verified_context.get()
        if principal:
            headers["x-cage-principal"] = principal
            headers["x-cage-principal-verified"] = "true" if verified else "false"
        return headers

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def chat(
        self,
        message: str,
        model: str = "default",
        **extra: Any,
    ) -> str:
        """Send a chat message to the gateway and return the response text.

        Args:
            message: The user message to send.
            model:   The model identifier to request.
            **extra: Additional JSON fields forwarded in the request body.

        Returns:
            The assistant response as a plain string.

        Raises:
            httpx.HTTPStatusError: on 4xx / 5xx responses.
        """
        client = await self._ensure_client()
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": message}],
            **extra,
        }
        response = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers=self._build_headers(),
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return data.get("response", "")

    async def get_policy_version(self, timeout: float = 10.0) -> str:
        """Queries the Hybrid Gateway's discovery engine for the valid active baseline signature."""
        client = await self._ensure_client()
        response = await client.get(
            "/governance/policy-version",
            headers=self._build_headers(),
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()["active_hash"]

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def evaluate_policy_dry_run(
        self,
        action: str,
        params: Mapping[str, Any] | None = None,
        timeout: float = 5.0,
    ) -> str:
        """Run a side-effect-free OPA policy pre-check via the gateway (D-195-3).

        Calls ``POST /governance/policy-precheck`` so the advisor never holds
        ``OPA_URL`` or opens a direct network connection to OPA; the gateway
        binds server-authoritative inputs, evaluates the active domain's Rego
        policy over its in-pod Unix socket, and returns an unsigned advisory
        decision (``ALLOW``, ``DENY``, or ``MANUAL_REVIEW``). Any transport,
        HTTP, or schema failure fails closed to ``"DENY"``.
        """
        clean_action = action.strip() if isinstance(action, str) else ""
        if not clean_action:
            return "DENY"
        clean_params = (
            {k: v for k, v in params.items() if k != "action"}
            if isinstance(params, Mapping)
            else {}
        )
        try:
            client = await self._ensure_client()
            headers = self._build_headers()
            payload = {"action": clean_action, "params": clean_params}

            async def _post() -> httpx.Response:
                return await client.post(
                    "/governance/policy-precheck",
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                )

            response = await _post_with_retries(
                _post, retry_statuses=frozenset({429, 503})
            )
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or body.get("dry_run") is not True:
                logger.warning(
                    "policy-precheck returned malformed body for action=%s: %r",
                    clean_action,
                    body,
                )
                return "DENY"
            decision = body.get("decision")
            if isinstance(decision, str):
                normalized = decision.strip().upper()
                if normalized in _POLICY_PRECHECK_DECISIONS:
                    return normalized
            logger.warning(
                "policy-precheck returned unknown decision for action=%s: %r",
                clean_action,
                decision,
            )
            return "DENY"
        except Exception as exc:
            logger.error(
                "Gateway policy-precheck failed for action=%s; failing closed: %s",
                clean_action,
                exc,
            )
            return "DENY"

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def validate_action(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Ask the gateway how ``action`` must be routed; nothing is committed.

        Calls ``POST /governance/validate-action`` through the installed
        ``cage-client`` SDK. The gateway runs the non-committing (DRY_RUN)
        profile and never mints a routing seal: the single committing run
        happens inside the gateway when the governed tool (e.g.
        ``execute_trade_action``) executes.

        The SDK resolves the gateway's signing key by ``kid`` from
        ``GET /governance/.well-known/jwks.json`` and verifies the envelope's
        signature, ``expires_at`` freshness and ``subject.action_hash``
        binding to ``action`` and ``params`` before any verdict is routed.
        The returned dictionary is built only from that verified envelope.

        W3C Trace Context Propagation
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        The active OpenTelemetry span context is injected into the outbound
        HTTP headers via ``opentelemetry.propagate.inject(headers)`` so the
        gateway's ``cage.validate_action`` span is a child of the advisor's
        ``cage.tool_execute`` span in Langfuse (one trace tree, not two).

        Args:
            action:            Tool / policy action name (e.g. ``"execute_trade"``).
            params:            Structured execution plan parameters dict.
            policy_version_id: Pinned baseline policy version signature hash (optional).
            timeout:           HTTP timeout in seconds (default 60s; covers OPA
                               cold start after a pod rollout).

        Returns:
            The verified envelope's payload with its provenance metadata.
            ``verdict`` is a :class:`GovernanceDecision` value other than
            ``DENY``: ``ALLOW``, ``NARROW`` (with ``narrowed_params``),
            ``REQUIRE_APPROVAL`` (with the ``deferred_id`` of the
            gateway-held approval token) or ``DEFER``.

        Raises:
            PermissionError: On a refusal (HTTP 403 / ``DENY``) or any answer
                outside the canonical vocabulary — the caller must block.
            cage_client.RoutingSealVerificationError: If the envelope's
                signature, ``kid``, freshness or request binding fails
                verification — the caller must block.
            httpx.HTTPStatusError: On other 4xx / 5xx Gateway errors.
            httpx.TimeoutException: If the Gateway does not respond within timeout.
        """
        sdk = await self._ensure_sdk(await self._ensure_client(), timeout)
        preview = _Preview(policy_version_id=policy_version_id, timeout=timeout)
        token = _current_preview.set(preview)
        try:
            await sdk.validate_action(
                action=action, parameters=params, agent_id=_ADVISOR_AGENT_ID
            )
        except PolicyViolationException as exc:
            narrowed = (
                exc.reason_code == "NARROWED"
                and preview.response is not None
                and preview.response.status_code == 200
            )
            if not narrowed:
                raise PermissionError(
                    f"Governance DENIED '{action}': "
                    f"{_denial_reasons(exc, preview.response)}"
                ) from exc
        except DeferralPending:
            pass  # routed below on the verified envelope, if there is one
        except RoutingSealVerificationError:
            raise  # an unverifiable envelope is neither routed nor relabelled
        except CageGatewayError as exc:
            _raise_unrouted(action, exc, preview.response)
        finally:
            _current_preview.reset(token)

        result = _verified_result(preview.response)
        verdict = result.get("verdict")
        if verdict not in _ROUTABLE_VERDICTS:
            violations = [str(v) for v in result.get("violations") or []]
            logger.warning(
                "🚫 validate_action refused: action=%s verdict=%s violations=%s",
                action,
                verdict,
                violations,
            )
            raise PermissionError(
                f"Governance returned no routable verdict for '{action}' "
                f"(verdict={verdict!r}): {'; '.join(violations)}"
            )
        if verdict == GovernanceDecision.REQUIRE_APPROVAL and not result.get(
            "deferred_id"
        ):
            # No approval token was parked, so no human can ever approve it.
            raise PermissionError(
                f"Governance requires approval for '{action}' but parked no deferred_id"
            )
        logger.info(
            "validate_action: action=%s verdict=%s latency=%.1fms",
            action,
            verdict,
            result.get("latency_ms", 0),
        )
        return result

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def execute_tool(
        self,
        tool_name: str,
        params: dict[str, Any],
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Run a gateway-hosted tool via ``POST /tools/execute``.

        Governed tools (``simulate_governance_check``, ``evaluate_policy``,
        ``execute_trade_action``, ...) execute in the gateway process, where the
        governor, OPA client and ``ActuatorRegistry`` live.

        Returns:
            The gateway's ``{"status": ..., "output"|"error": ...}`` body.
        """
        client = await self._ensure_client()
        headers = self._build_headers()

        async def _post() -> httpx.Response:
            return await client.post(
                "/tools/execute",
                json={"tool_name": tool_name, "params": params},
                headers=headers,
                timeout=timeout,
            )

        # HTTP 429 is rejected by the gateway rate limiter before any tool
        # execution occurs, so retrying on 429 is side-effect free.
        response = await _post_with_retries(_post, retry_statuses=frozenset({429}))
        response.raise_for_status()
        body: dict[str, Any] = response.json()
        return body

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def commit_state(
        self,
        snapshot: Mapping[str, Any],
        *,
        linkage: StateCommitmentLinkage,
        timeout: float = 10.0,
    ) -> StateCommitmentReceipt:
        """Commit a state snapshot via ``POST /governance/state-commitments``.

        Implements :class:`~src.gateway.governance.seams.state_commitment.StateCommitter`.
        The gateway sanitizes, canonicalizes and hashes the snapshot and
        appends the sanitized preimage to its evidence chain; the advisor keeps
        no copy and holds no storage identity. The caller is authenticated by
        its Linkerd mTLS workload identity, injected by the mesh proxy.

        Args:
            snapshot: JSON-native agent-state snapshot.
            linkage: The attestation step the snapshot belongs to.
            timeout: HTTP timeout in seconds.

        Returns:
            The validated gateway receipt (``stateHash`` + evidence linkage).

        Raises:
            StateCommitmentError: On any transport error, non-200 response, or
                malformed receipt. The caller must not emit the step.
        """
        client = await self._ensure_client()
        headers = self._build_headers()
        try:
            response = await client.post(
                "/governance/state-commitments",
                json={"snapshot": dict(snapshot), "linkage": linkage.to_dict()},
                headers=headers,
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise StateCommitmentError(
                f"state commitment transport error: {exc}"
            ) from exc
        if response.status_code != 200:
            raise StateCommitmentError(
                f"gateway refused state commitment: HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise StateCommitmentError("gateway returned a non-JSON receipt") from exc
        if not isinstance(body, dict):
            raise StateCommitmentError("gateway returned a non-object receipt")
        return StateCommitmentReceipt.from_dict(body)

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        if self._sdk is not None:
            await self._sdk.aclose()
            self._sdk = None
            self._sdk_http = None
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            logger.info("GatewayClient: HTTP client closed")
