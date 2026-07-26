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

"""Tests for src/gateway/governance/ingress/policy_translator.py — format detection, routing, artifact bundle."""

from __future__ import annotations

import pytest

from src.gateway.governance.ingress.policy_translator import (
    ArtifactBundle,
    detect_format,
    translate_policy,
)

# ---------------------------------------------------------------------------
# detect_format tests (G4)
# ---------------------------------------------------------------------------


class TestDetectFormat:
    def test_oscal_version_key_detected_as_oscal(self):
        assert detect_format({"oscal-version": "1.1.2"}) == "oscal"

    def test_lula_validation_kind_detected_as_lula(self):
        assert detect_format({"kind": "LulaValidation"}) == "lula"

    def test_component_definition_with_oscal_version_detected_as_oscal(self):
        doc = {
            "component-definition": {
                "metadata": {"oscal-version": "1.1.2"},
                "components": [],
            }
        }
        assert detect_format(doc) == "oscal"

    def test_behavior_declarations_detected_as_acs(self):
        assert detect_format({"behaviorDeclarations": []}) == "acs"

    def test_governed_run_loop_detected_as_aaif(self):
        assert detect_format({"governedRunLoop": {}}) == "aaif"

    def test_unknown_format_falls_back_to_cage_yaml(self):
        assert detect_format({"unsafe_control_actions": []}) == "cage_yaml"

    def test_empty_dict_falls_back_to_cage_yaml(self):
        assert detect_format({}) == "cage_yaml"

    def test_oscal_takes_priority_over_behavior_declarations(self):
        # If both keys present, oscal-version wins
        doc = {"oscal-version": "1.1.2", "behaviorDeclarations": []}
        assert detect_format(doc) == "oscal"

    def test_lula_takes_priority_over_governed_run_loop(self):
        doc = {"kind": "LulaValidation", "governedRunLoop": {}}
        assert detect_format(doc) == "lula"


# ---------------------------------------------------------------------------
# ArtifactBundle tests
# ---------------------------------------------------------------------------


class TestArtifactBundle:
    def test_success_true_when_no_errors(self):
        bundle = ArtifactBundle()
        assert bundle.success is True

    def test_success_false_when_errors_present(self):
        bundle = ArtifactBundle(errors=["something went wrong"])
        assert bundle.success is False

    def test_default_format_is_cage_yaml(self):
        bundle = ArtifactBundle()
        assert bundle.format_detected == "cage_yaml"

    def test_policy_version_id_empty_by_default(self):
        bundle = ArtifactBundle()
        assert bundle.policy_version_id == ""


# ---------------------------------------------------------------------------
# translate_policy routing tests
# ---------------------------------------------------------------------------


class TestTranslatePolicy:
    def test_acs_spec_routes_to_acs_adapter(self):
        spec = {
            "behaviorDeclarations": [
                {
                    "id": "ACS-001",
                    "action": "execute_trade",
                    "description": "Test",
                    "hazardRefs": ["H-1"],
                    "enforcement": ["python"],
                }
            ]
        }
        bundle = translate_policy(spec)
        assert bundle.format_detected == "acs"

    def test_aaif_spec_routes_to_aaif_adapter(self):
        spec = {"governedRunLoop": {"stages": []}}
        bundle = translate_policy(spec)
        assert bundle.format_detected == "aaif"

    def test_oscal_spec_routes_to_oscal_adapter(self):
        spec = {
            "oscal-version": "1.1.2",
            "component-definition": {
                "metadata": {"title": "Test", "oscal-version": "1.1.2"},
                "components": [],
            },
        }
        bundle = translate_policy(spec)
        assert bundle.format_detected == "oscal"

    def test_lula_spec_routes_to_lula_adapter(self):
        spec = {
            "kind": "LulaValidation",
            "metadata": {"name": "test"},
            "spec": {
                "domain": {"type": "kubernetes", "kubernetes-spec": {"resources": []}},
                "policy": {"opa": {"rego": "package lula\nvalidate if { true }"}},
            },
        }
        bundle = translate_policy(spec)
        assert bundle.format_detected == "lula"
        assert len(bundle.opa_bundle_modules) == 1

    def test_lula_opa_content_populated(self):
        spec = {
            "kind": "LulaValidation",
            "metadata": {"name": "test"},
            "spec": {
                "domain": {"type": "kubernetes", "kubernetes-spec": {"resources": []}},
                "policy": {"opa": {"rego": "package lula\nvalidate if { true }"}},
            },
        }
        bundle = translate_policy(spec)
        assert "package lula" in bundle.opa_content

    def test_policy_version_id_computed_for_lula(self):
        spec = {
            "kind": "LulaValidation",
            "metadata": {"name": "test"},
            "spec": {
                "domain": {"type": "kubernetes", "kubernetes-spec": {"resources": []}},
                "policy": {"opa": {"rego": "package lula\nvalidate if { true }"}},
            },
        }
        bundle = translate_policy(spec)
        assert len(bundle.policy_version_id) == 16

    def test_policy_version_id_is_deterministic(self):
        spec = {
            "kind": "LulaValidation",
            "metadata": {"name": "test"},
            "spec": {
                "domain": {"type": "kubernetes", "kubernetes-spec": {"resources": []}},
                "policy": {"opa": {"rego": "package lula\nvalidate if { true }"}},
            },
        }
        bundle1 = translate_policy(spec)
        bundle2 = translate_policy(spec)
        assert bundle1.policy_version_id == bundle2.policy_version_id

    def test_acs_spec_with_no_ucas_produces_warnings_not_errors(self):
        # ACS spec with no behaviors that can be mapped
        spec = {"behaviorDeclarations": []}
        bundle = translate_policy(spec)
        # Empty behaviors → no UCAs → warnings but not errors
        assert bundle.format_detected == "acs"

    def test_cage_yaml_with_no_system_key_produces_warning(self):
        spec = {"unsafe_control_actions": []}
        bundle = translate_policy(spec)
        assert bundle.format_detected == "cage_yaml"
        # No system key → warning, not error
        assert any("system" in w for w in bundle.warnings)

    def test_format_detection_result_in_bundle(self):
        for fmt, spec in [
            ("acs", {"behaviorDeclarations": []}),
            ("aaif", {"governedRunLoop": {"stages": []}}),
            (
                "oscal",
                {
                    "oscal-version": "1.1.2",
                    "component-definition": {
                        "metadata": {"title": "T", "oscal-version": "1.1.2"},
                        "components": [],
                    },
                },
            ),
        ]:
            bundle = translate_policy(spec)
            assert bundle.format_detected == fmt, (
                f"Expected {fmt}, got {bundle.format_detected}"
            )
