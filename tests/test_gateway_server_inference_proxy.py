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
Unit tests for src/gateway/server/inference_proxy.py.

Focuses on pure functions and isolated logic that can be tested
without spinning up FastAPI, vLLM, or NeMo.  Heavy framework
dependencies are mocked at import time.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal stub patches so the module can be imported in CI
# ---------------------------------------------------------------------------

def _make_import_patches():
    """Return a dict of module-path → stub suitable for patch.dict(sys.modules)."""
    return {
        "src.gateway.governance.iso_control": MagicMock(),
        "src.gateway.governance.nemo.manager": MagicMock(
            verify_and_mask_output=AsyncMock(side_effect=lambda _r, t: t),
            verify_input=AsyncMock(),
        ),
        "src.gateway.governance.text_filter": MagicMock(ac_keyword_scan=MagicMock(return_value=False)),
        "src.gateway.governance.token_quota_proxy": MagicMock(
            _get_token_quota_proxy=MagicMock(return_value=MagicMock(
                check_and_increment=AsyncMock(return_value=MagicMock(allowed=True)),
                rollback_step=AsyncMock(),
            ))
        ),
        "src.gateway.governance.uca_logger": MagicMock(
            _get_uca_logger=MagicMock(return_value=MagicMock(log_quota_exceeded=AsyncMock()))
        ),
        "src.governed_financial_advisor.infrastructure.config_manager": MagicMock(
            config_manager=MagicMock(get=MagicMock(return_value="http://vllm:8000/v1"))
        ),
        "src.governed_financial_advisor.utils.privacy": MagicMock(scrub_pii=lambda x: x),
    }


# ---------------------------------------------------------------------------
# Tests: _safe_error_response
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestSafeErrorResponse:
    """Tests for inference_proxy._safe_error_response()."""

    def test_returns_dict_with_error_and_correlation_id(self):
        """_safe_error_response returns a dict with 'error' and 'correlation_id'."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _safe_error_response

            result = _safe_error_response(ValueError("test error"))

        assert "error" in result
        assert "correlation_id" in result
        assert isinstance(result["correlation_id"], str)
        assert len(result["correlation_id"]) > 0

    def test_does_not_expose_exception_message(self):
        """The error key does not contain the raw exception message."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _safe_error_response

            result = _safe_error_response(ValueError("super secret internal detail"))

        # The raw exception message must NOT be surfaced to the caller
        assert "super secret internal detail" not in result.get("error", "")

    def test_error_field_is_generic_string(self):
        """'error' field contains a generic safe message."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _safe_error_response

            result = _safe_error_response(RuntimeError("boom"))

        assert result["error"] == "Internal server error"

    def test_unique_correlation_id_per_call(self):
        """Each _safe_error_response call produces a unique correlation_id."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _safe_error_response

            r1 = _safe_error_response(Exception("e1"))
            r2 = _safe_error_response(Exception("e2"))

        assert r1["correlation_id"] != r2["correlation_id"]


# ---------------------------------------------------------------------------
# Tests: _create_blocked_response
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestCreateBlockedResponse:
    """Tests for inference_proxy._create_blocked_response()."""

    def test_returns_openai_compatible_structure(self):
        """_create_blocked_response returns a valid chat.completion-like dict."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _create_blocked_response

            result = _create_blocked_response("Tier-1 keyword match")

        assert "id" in result
        assert "object" in result
        assert result["object"] == "chat.completion"
        assert "choices" in result
        assert len(result["choices"]) == 1

    def test_blocked_response_contains_reason_in_content(self):
        """Content of the blocked response includes the block reason."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _create_blocked_response

            result = _create_blocked_response("dangerous content detected")

        content = result["choices"][0]["message"]["content"]
        assert "dangerous content detected" in content

    def test_blocked_response_has_usage_zeros(self):
        """usage tokens are all zero for a blocked (no-generation) response."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _create_blocked_response

            result = _create_blocked_response("test")

        usage = result["usage"]
        assert usage["prompt_tokens"] == 0
        assert usage["completion_tokens"] == 0
        assert usage["total_tokens"] == 0

    def test_blocked_response_role_is_assistant(self):
        """The blocked message role is 'assistant'."""
        import sys
        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _create_blocked_response

            result = _create_blocked_response("blocked")

        assert result["choices"][0]["message"]["role"] == "assistant"


# ---------------------------------------------------------------------------
# Tests: _resolve_backend_url
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestResolveBackendUrl:
    """Tests for inference_proxy._resolve_backend_url()."""

    def test_deepseek_model_routes_to_reasoning_base(self):
        """Model IDs containing 'deepseek' route to VLLM_REASONING_API_BASE."""
        import sys
        mock_cfg = MagicMock()
        mock_cfg.get.side_effect = lambda key, default=None: {
            "VLLM_REASONING_API_BASE": "http://reasoning:8001/v1",
            "VLLM_FAST_API_BASE": "http://fast:8002/v1",
            "VLLM_BASE_URL": "http://base:8000/v1",
        }.get(key, default)

        patches = _make_import_patches()
        patches["src.governed_financial_advisor.infrastructure.config_manager"] = MagicMock(
            config_manager=mock_cfg
        )

        with patch.dict("sys.modules", patches):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _resolve_backend_url
            result = _resolve_backend_url("deepseek-r1")

        assert "reasoning" in result

    def test_reasoning_model_routes_to_reasoning_base(self):
        """Model IDs containing 'reasoning' route to VLLM_REASONING_API_BASE."""
        import sys
        mock_cfg = MagicMock()
        mock_cfg.get.side_effect = lambda key, default=None: {
            "VLLM_REASONING_API_BASE": "http://reasoning:8001/v1",
            "VLLM_FAST_API_BASE": "http://fast:8002/v1",
            "VLLM_BASE_URL": "http://base:8000/v1",
        }.get(key, default)

        patches = _make_import_patches()
        patches["src.governed_financial_advisor.infrastructure.config_manager"] = MagicMock(
            config_manager=mock_cfg
        )

        with patch.dict("sys.modules", patches):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _resolve_backend_url
            result = _resolve_backend_url("my-reasoning-model")

        assert "reasoning" in result

    def test_default_model_routes_to_fast_base(self):
        """Non-reasoning models route to VLLM_FAST_API_BASE."""
        import sys
        mock_cfg = MagicMock()
        mock_cfg.get.side_effect = lambda key, default=None: {
            "VLLM_REASONING_API_BASE": "http://reasoning:8001/v1",
            "VLLM_FAST_API_BASE": "http://fast:8002/v1",
            "VLLM_BASE_URL": "http://base:8000/v1",
        }.get(key, default)

        patches = _make_import_patches()
        patches["src.governed_financial_advisor.infrastructure.config_manager"] = MagicMock(
            config_manager=mock_cfg
        )

        with patch.dict("sys.modules", patches):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            from src.gateway.server.inference_proxy import _resolve_backend_url
            result = _resolve_backend_url("llama3-8b-instruct")

        assert "fast" in result


# ---------------------------------------------------------------------------
# Tests: _get_http_client (lazy singleton)
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestGetHttpClient:
    """Tests for _get_http_client() lazy singleton."""

    def test_returns_async_client(self):
        """_get_http_client() returns an httpx.AsyncClient instance."""
        import sys

        import httpx

        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            import src.gateway.server.inference_proxy as mod
            mod._http_client = None  # reset singleton

            from src.gateway.server.inference_proxy import _get_http_client
            client = _get_http_client()

        assert isinstance(client, httpx.AsyncClient)

    def test_returns_same_instance_on_repeated_calls(self):
        """_get_http_client() returns the same instance (singleton pattern)."""
        import sys

        with patch.dict("sys.modules", _make_import_patches()):
            sys.modules.pop("src.gateway.server.inference_proxy", None)
            import src.gateway.server.inference_proxy as mod
            mod._http_client = None  # reset

            from src.gateway.server.inference_proxy import _get_http_client
            c1 = _get_http_client()
            c2 = _get_http_client()

        assert c1 is c2
