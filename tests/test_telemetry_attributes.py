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

"""Unit tests for src.gateway.observability.attributes and Gate G7 AST enforcement.

Verifies:
  1. Golden Table: All attribute constants match historical literals when using default namespace.
  2. Dynamic Namespace: Setting CAGE_TELEMETRY_ATTR_NAMESPACE adjusts key prefixes cleanly.
  3. Helpers: metadata() and observation_metadata() correctly format keys.
  4. Span Attributes compatibility: span_attributes re-exports from attributes.
  5. Gate G7: check_telemetry_literals AST visitor detects planted violations.
"""

import importlib
import os
import tempfile
from unittest.mock import patch
import pytest

from src.gateway.observability import attributes, span_attributes


class TestTelemetryAttributesGoldenTable:
    """Wire-format stability test ensuring byte-identical telemetry keys."""

    def test_core_trace_attributes(self):
        assert attributes.TRACE_INPUT == "langfuse.trace.input"
        assert attributes.TRACE_OUTPUT == "langfuse.trace.output"
        assert attributes.TRACE_USER_ID == "langfuse.trace.user_id"
        assert attributes.TRACE_SESSION_ID == "langfuse.trace.session_id"
        assert attributes.TRACE_TAGS == "langfuse.trace.tags"

    def test_observation_attributes(self):
        assert attributes.OBSERVATION_TYPE == "langfuse.observation.type"
        assert attributes.OBSERVATION_NAME == "langfuse.observation.name"
        assert attributes.OBSERVATION_INPUT == "langfuse.observation.input"
        assert attributes.OBSERVATION_OUTPUT == "langfuse.observation.output"
        assert attributes.OBSERVATION_MODEL_NAME == "langfuse.observation.model.name"

    def test_trace_metadata_attributes(self):
        assert attributes.TRACE_METADATA_CURRENT_NODE == "langfuse.trace.metadata.current_node"
        assert attributes.TRACE_METADATA_MCP_SERVER == "langfuse.trace.metadata.mcp_server"
        assert attributes.TRACE_METADATA_POLICY_VERSION == "langfuse.trace.metadata.policy_version"
        assert attributes.TRACE_METADATA_POLICY_DECISION == "langfuse.trace.metadata.policy_decision"
        assert attributes.TRACE_METADATA_FENCE_STATUS == "langfuse.trace.metadata.fence_status"

    def test_observation_metadata_attributes(self):
        assert attributes.OBSERVATION_METADATA_TOOL_NAME == "langfuse.observation.metadata.tool_name"
        assert attributes.OBSERVATION_METADATA_AGENT_NAME == "langfuse.observation.metadata.agent_name"
        assert attributes.OBSERVATION_METADATA_TIER == "langfuse.observation.metadata.tier"

    def test_webhook_attributes(self):
        assert attributes.AI_WEBHOOK_COOLDOWN_ACTIVE == "ai.webhook.langfuse.cooldown_active"
        assert attributes.AI_WEBHOOK_COOLDOWN_SECONDS_REMAINING == "ai.webhook.langfuse.cooldown_seconds_remaining"
        assert attributes.AI_WEBHOOK_SCORE_NAME == "ai.webhook.langfuse.score_name"
        assert attributes.AI_WEBHOOK_SCORE_VALUE == "ai.webhook.langfuse.score_value"
        assert attributes.AI_WEBHOOK_TRACE_ID == "ai.webhook.langfuse.trace_id"
        assert attributes.WEBHOOK_THRESHOLD_BREACH == "langfuse.webhook.threshold_breach"

    def test_metadata_helpers(self):
        assert attributes.metadata("custom_metric") == "langfuse.trace.metadata.custom_metric"
        assert attributes.observation_metadata("sub_action") == "langfuse.observation.metadata.sub_action"

    def test_span_attributes_reexport_compatibility(self):
        """Verify backwards-compatibility of span_attributes re-exports."""
        assert span_attributes.TRACE_INPUT == attributes.TRACE_INPUT
        assert span_attributes.OBSERVATION_INPUT == attributes.OBSERVATION_INPUT
        assert span_attributes.OBSERVATION_OUTPUT == attributes.OBSERVATION_OUTPUT
        assert span_attributes.metadata("test_k") == attributes.metadata("test_k")


class TestDynamicTelemetryNamespace:
    """Test namespace overriding via CAGE_TELEMETRY_ATTR_NAMESPACE."""

    def test_custom_namespace(self):
        with patch.dict(os.environ, {"CAGE_TELEMETRY_ATTR_NAMESPACE": "otel_vendor"}):
            reloaded = importlib.reload(attributes)
            try:
                assert reloaded.NAMESPACE == "otel_vendor"
                assert reloaded.OBSERVATION_INPUT == "otel_vendor.observation.input"
                assert reloaded.OBSERVATION_OUTPUT == "otel_vendor.observation.output"
                assert reloaded.AI_WEBHOOK_COOLDOWN_ACTIVE == "ai.webhook.otel_vendor.cooldown_active"
                assert reloaded.metadata("sample") == "otel_vendor.trace.metadata.sample"
            finally:
                # Always restore default namespace
                with patch.dict(os.environ, {"CAGE_TELEMETRY_ATTR_NAMESPACE": "langfuse"}):
                    importlib.reload(attributes)


class TestGateG7ASTChecker:
    """Test Gate G7 AST visitor script behavior."""

    def test_planted_violation_is_detected(self):
        from scripts.check_telemetry_literals import check_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
            tf.write('def bad_fn():\n    return "langfuse.observation.output"\n')
            temp_path = tf.name

        try:
            violations = check_file(temp_path)
            assert len(violations) == 1
            assert violations[0][1] == "langfuse.observation.output"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_clean_file_passes(self):
        from scripts.check_telemetry_literals import check_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
            tf.write('from src.gateway.observability.attributes import OBSERVATION_OUTPUT\n'
                     'def good_fn(span):\n    span.set_attribute(OBSERVATION_OUTPUT, "val")\n')
            temp_path = tf.name

        try:
            violations = check_file(temp_path)
            assert len(violations) == 0
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_docstring_and_comments_ignored(self):
        from scripts.check_telemetry_literals import check_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
            tf.write('"""\nExample using langfuse.observation.output in docstring.\n"""\n'
                     '# Comment mentioning langfuse.observation.output\ndef fn():\n    pass\n')
            temp_path = tf.name

        try:
            violations = check_file(temp_path)
            assert len(violations) == 0
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

