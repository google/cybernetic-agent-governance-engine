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
GEAP Runtime Guards — FastMCP Seal Verification & ADK Memory Bank Guard (Module M4).

Provides two runtime defense-in-depth guards for Google Enterprise Agent Platform
(GEAP) workloads:

1. ``FastMcpSealVerificationMiddleware``:
   Intercepts Cloud Run FastMCP ``StreamableHTTP`` / ``tools/call`` invocations.
   Enforces ADR-009 tiered actuation:
   - ``READ_ONLY`` tools (e.g., ``tools/list`` or configured read-only tools) may
     execute without a routing seal when ``require_seal_for_read_only=False``.
   - ``MUTATING`` tools fail closed unless a valid ``X-CAGE-Routing-Seal`` header
     is present and passes ``verify_and_consume_seal()`` (cryptographic signature,
     JCS payload hash binding, TTL, and single-use nonce consumption).

2. ``GovernedMemoryBankGuard``:
   Wraps ADK / Vertex AI Agent Engine Memory Bank callbacks
   (``save_memories_callback`` / ``ctx.add_session_to_memory()`` and
   ``PreloadMemoryTool`` / ``before_model_callback``) to:
   - Scrub all session events through ``PIISanitizer`` (ISO 42001 Annex A.6)
     before persistence or prompt injection.
   - Detect and block cross-session memory poisoning via
     ``detect_prompt_injection()`` (AI600-003).
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from src.gateway.governance.pii_sanitizer import PIISanitizer
from src.gateway.governance.prompt_injection_detector import detect_prompt_injection
from src.gateway.governance.routing_seal import (
    SymbolicGovernorViolation,
    verify_and_consume_seal,
    verify_seal,
)

logger = logging.getLogger("Integrations.GcpGeap.RuntimeGuards")

DEFAULT_READ_ONLY_MCP_METHODS: frozenset[str] = frozenset(
    {
        "tools/list",
        "resources/list",
        "prompts/list",
        "ping",
    }
)


@dataclass(frozen=True)
class FastMcpSealVerificationResult:
    """Outcome of FastMCP tool-call seal verification."""

    allowed: bool
    tool_name: str
    tier: str
    seal_verified: bool
    tri_identity_verified: bool = False
    error: str = ""


class FastMcpSealVerificationMiddleware:
    """FastMCP server middleware enforcing CAGE routing seals on mutating tools.

    Designed for Cloud Run FastMCP servers behind GEAP Agent Gateway (AGW).
    Even if a caller bypasses AGW and invokes the Cloud Run endpoint directly,
    mutating tool execution is rejected without a Gateway-minted
    ``X-CAGE-Routing-Seal``.
    """

    def __init__(
        self,
        *,
        read_only_tools: Sequence[str] | frozenset[str] = (),
        require_seal_for_read_only: bool = False,
        require_tri_identity_digest: bool = False,
    ) -> None:
        self.read_only_tools: frozenset[str] = (
            DEFAULT_READ_ONLY_MCP_METHODS | frozenset(read_only_tools)
        )
        self.require_seal_for_read_only = require_seal_for_read_only
        self.require_tri_identity_digest = require_tri_identity_digest

    @staticmethod
    def _get_header(headers: Mapping[str, str], target_name: str) -> str:
        target_lower = target_name.lower()
        for key, value in headers.items():
            if key.lower() == target_lower:
                return str(value).strip()
        return ""

    async def verify_mcp_tool_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        headers: Mapping[str, str],
        *,
        expected_tri_identity_digest: str = "",
        redis_client: Any = None,
        consume_nonce: bool = True,
    ) -> FastMcpSealVerificationResult:
        """Verify ``X-CAGE-Routing-Seal`` for an incoming FastMCP tool invocation."""
        normalized_tool = (tool_name or "").strip()
        if not normalized_tool:
            return FastMcpSealVerificationResult(
                allowed=False,
                tool_name="",
                tier="MUTATING",
                seal_verified=False,
                error="Missing FastMCP tool_name",
            )

        is_read_only = normalized_tool in self.read_only_tools
        tier = "READ_ONLY" if is_read_only else "MUTATING"

        if is_read_only and not self.require_seal_for_read_only:
            return FastMcpSealVerificationResult(
                allowed=True,
                tool_name=normalized_tool,
                tier=tier,
                seal_verified=False,
                tri_identity_verified=False,
            )

        seal = self._get_header(headers, "X-CAGE-Routing-Seal")
        if not seal:
            logger.warning(
                "FastMcpSealVerificationMiddleware: rejected unsealed %s tool call '%s'",
                tier,
                normalized_tool,
            )
            return FastMcpSealVerificationResult(
                allowed=False,
                tool_name=normalized_tool,
                tier=tier,
                seal_verified=False,
                error="Missing required X-CAGE-Routing-Seal header for mutating FastMCP tool call",
            )

        tri_identity_verified = False
        header_digest = self._get_header(headers, "X-CAGE-Tri-Identity-Digest")
        if self.require_tri_identity_digest or expected_tri_identity_digest:
            if not header_digest:
                return FastMcpSealVerificationResult(
                    allowed=False,
                    tool_name=normalized_tool,
                    tier=tier,
                    seal_verified=False,
                    tri_identity_verified=False,
                    error="Missing required X-CAGE-Tri-Identity-Digest header",
                )
            if expected_tri_identity_digest and not hmac.compare_digest(
                header_digest, expected_tri_identity_digest
            ):
                return FastMcpSealVerificationResult(
                    allowed=False,
                    tool_name=normalized_tool,
                    tier=tier,
                    seal_verified=False,
                    tri_identity_verified=False,
                    error="X-CAGE-Tri-Identity-Digest mismatch",
                )
            tri_identity_verified = True

        params_dict = dict(arguments)
        try:
            if consume_nonce:
                await verify_and_consume_seal(
                    seal,
                    normalized_tool,
                    params_dict,
                    redis_client=redis_client,
                )
            else:
                verify_seal(seal, normalized_tool, params_dict)
        except SymbolicGovernorViolation as exc:
            logger.warning(
                "FastMcpSealVerificationMiddleware: seal verification failed for tool '%s': %s",
                normalized_tool,
                exc,
            )
            return FastMcpSealVerificationResult(
                allowed=False,
                tool_name=normalized_tool,
                tier=tier,
                seal_verified=False,
                tri_identity_verified=tri_identity_verified,
                error=f"Routing seal verification failed: {exc}",
            )
        except Exception as exc:
            logger.warning(
                "FastMcpSealVerificationMiddleware: unexpected seal error for tool '%s': %s",
                normalized_tool,
                exc,
            )
            return FastMcpSealVerificationResult(
                allowed=False,
                tool_name=normalized_tool,
                tier=tier,
                seal_verified=False,
                tri_identity_verified=tri_identity_verified,
                error="Routing seal verification error",
            )

        return FastMcpSealVerificationResult(
            allowed=True,
            tool_name=normalized_tool,
            tier=tier,
            seal_verified=True,
            tri_identity_verified=tri_identity_verified,
        )


@dataclass(frozen=True)
class MemoryBankGuardResult:
    """Outcome of ADK Vertex Memory Bank sanitization and injection scan."""

    allowed: bool
    sanitized_events: tuple[dict[str, Any] | str, ...]
    pii_redacted_count: int
    injection_detected: bool
    blocked_reason: str = ""
    matched_pattern: str = ""


class GovernedMemoryBankGuard:
    """PII and prompt-injection guard for GEAP ADK Vertex AI Memory Bank.

    Protects both memory write paths (``save_memories_callback`` calling
    ``ctx.add_session_to_memory()``) and memory read paths
    (``PreloadMemoryTool`` / ``before_model_callback``) from PII leakage and
    cross-session indirect prompt injection (memory poisoning).
    """

    def __init__(self, sanitizer: PIISanitizer | None = None) -> None:
        self._sanitizer = sanitizer or PIISanitizer()

    @classmethod
    def _extract_strings(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, Mapping):
            texts: list[str] = []
            for v in value.values():
                texts.extend(cls._extract_strings(v))
            return texts
        if isinstance(value, (list, tuple)):
            texts = []
            for item in value:
                texts.extend(cls._extract_strings(item))
            return texts
        return []

    def guard_save_session_to_memory(
        self,
        session_events: Sequence[Mapping[str, Any] | str],
        *,
        add_session_callback: Callable[[Sequence[dict[str, Any] | str]], Any] | None = None,
    ) -> MemoryBankGuardResult:
        """Scan and sanitize session events before committing to Vertex Memory Bank.

        If any event triggers ``detect_prompt_injection()``, the entire session
        memory commit is blocked (fail-closed) and ``add_session_callback`` is
        not invoked. Otherwise all PII is scrubbed via ``PIISanitizer`` prior to
        invoking ``add_session_callback``.
        """
        for idx, event in enumerate(session_events):
            for text_fragment in self._extract_strings(event):
                inj = detect_prompt_injection(text_fragment)
                if inj.detected:
                    reason = (
                        f"Blocked Vertex Memory Bank write: prompt injection detected "
                        f"in session event[{idx}] (pattern={inj.pattern_matched})"
                    )
                    logger.warning("GovernedMemoryBankGuard: %s", reason)
                    return MemoryBankGuardResult(
                        allowed=False,
                        sanitized_events=(),
                        pii_redacted_count=0,
                        injection_detected=True,
                        blocked_reason=reason,
                        matched_pattern=inj.pattern_matched or "",
                    )

        sanitized_list: list[dict[str, Any] | str] = []
        redacted_count = 0
        for event in session_events:
            if isinstance(event, str):
                clean = self._sanitizer.sanitize(event)
                if clean != event:
                    redacted_count += 1
                sanitized_list.append(clean)
            elif isinstance(event, Mapping):
                raw_dict = dict(event)
                clean_dict = self._sanitizer.sanitize_dict(raw_dict)
                if clean_dict != raw_dict:
                    redacted_count += 1
                sanitized_list.append(clean_dict)
            else:
                sanitized_list.append(str(event))

        if add_session_callback is not None:
            add_session_callback(sanitized_list)

        return MemoryBankGuardResult(
            allowed=True,
            sanitized_events=tuple(sanitized_list),
            pii_redacted_count=redacted_count,
            injection_detected=False,
        )

    def guard_preloaded_memories(
        self,
        memories: Sequence[str],
        *,
        strict_block_on_injection: bool = False,
    ) -> MemoryBankGuardResult:
        """Sanitize and filter ``PreloadMemoryTool`` memories prior to model prompt injection."""
        sanitized_memories: list[str] = []
        redacted_count = 0
        injection_detected = False
        matched_pattern = ""

        for idx, memory_text in enumerate(memories):
            inj = detect_prompt_injection(memory_text)
            if inj.detected:
                injection_detected = True
                matched_pattern = inj.pattern_matched or ""
                logger.warning(
                    "GovernedMemoryBankGuard: poisoned memory detected in PreloadMemoryTool[%d] (pattern=%s)",
                    idx,
                    matched_pattern,
                )
                if strict_block_on_injection:
                    return MemoryBankGuardResult(
                        allowed=False,
                        sanitized_events=(),
                        pii_redacted_count=0,
                        injection_detected=True,
                        blocked_reason=(
                            f"Poisoned memory detected at index {idx} "
                            f"(pattern={matched_pattern})"
                        ),
                        matched_pattern=matched_pattern,
                    )
                continue

            clean = self._sanitizer.sanitize(memory_text)
            if clean != memory_text:
                redacted_count += 1
            sanitized_memories.append(clean)

        return MemoryBankGuardResult(
            allowed=True,
            sanitized_events=tuple(sanitized_memories),
            pii_redacted_count=redacted_count,
            injection_detected=injection_detected,
            matched_pattern=matched_pattern,
        )
