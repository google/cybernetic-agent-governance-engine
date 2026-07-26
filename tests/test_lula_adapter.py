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

"""Tests for src/gateway/governance/ingress/lula_adapter.py — Lula manifest → OPA module."""

from __future__ import annotations

import pytest

from src.gateway.governance.ingress.lula_adapter import (
    lula_to_opa_bundle_patch,
    translate_lula,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MINIMAL_LULA_MANIFEST = {
    "kind": "LulaValidation",
    "metadata": {"name": "ac3-validation"},
    "spec": {
        "domain": {
            "type": "kubernetes",
            "kubernetes-spec": {
                "resources": [
                    {
                        "name": "opa-deployment",
                        "resource": "deployments",
                        "namespace": "governance-stack",
                    }
                ]
            },
        },
        "policy": {
            "opa": {
                "rego": (
                    "package lula\n\nimport future.keywords.if\n\n"
                    'validate if {\n  input["opa-deployment"].status.readyReplicas >= 1\n}\n'
                )
            }
        },
    },
}

_LULA_WITH_MODULES = {
    "kind": "LulaValidation",
    "metadata": {"name": "multi-module-validation"},
    "spec": {
        "domain": {"type": "kubernetes", "kubernetes-spec": {"resources": []}},
        "policy": {
            "opa": {
                "rego": "package lula\nvalidate if { true }",
                "modules": [
                    "package helper\nhelper_rule if { true }",
                    {
                        "name": "named_module",
                        "rego": "package named\nnamed_rule if { true }",
                    },
                ],
            }
        },
    },
}

_NOT_LULA_DOC = {
    "kind": "SomeOtherKind",
    "metadata": {"name": "not-lula"},
}

_LULA_NO_REGO = {
    "kind": "LulaValidation",
    "metadata": {"name": "no-rego"},
    "spec": {
        "domain": {"type": "kubernetes", "kubernetes-spec": {"resources": []}},
        "policy": {"opa": {}},
    },
}


# ---------------------------------------------------------------------------
# translate_lula tests
# ---------------------------------------------------------------------------


class TestTranslateLula:
    def test_missing_kind_raises(self):
        with pytest.raises(ValueError, match="LulaValidation"):
            translate_lula(_NOT_LULA_DOC)

    def test_minimal_manifest_produces_policy_name(self):
        result = translate_lula(_MINIMAL_LULA_MANIFEST)
        assert result["policy_name"] == "lula_ac3_validation"

    def test_inline_rego_extracted_as_module(self):
        result = translate_lula(_MINIMAL_LULA_MANIFEST)
        assert len(result["opa_modules"]) == 1
        assert "package lula" in result["opa_modules"][0]["rego"]

    def test_module_name_matches_policy_name(self):
        result = translate_lula(_MINIMAL_LULA_MANIFEST)
        assert result["opa_modules"][0]["name"] == "lula_ac3_validation"

    def test_k8s_resources_extracted(self):
        result = translate_lula(_MINIMAL_LULA_MANIFEST)
        assert len(result["k8s_resources"]) == 1
        assert result["k8s_resources"][0]["name"] == "opa-deployment"

    def test_raw_manifest_preserved(self):
        result = translate_lula(_MINIMAL_LULA_MANIFEST)
        assert result["raw_manifest"] is _MINIMAL_LULA_MANIFEST

    def test_multiple_modules_all_appended(self):
        result = translate_lula(_LULA_WITH_MODULES)
        # Primary rego + 2 modules = 3 total
        assert len(result["opa_modules"]) == 3

    def test_string_module_gets_auto_name(self):
        result = translate_lula(_LULA_WITH_MODULES)
        module_names = [m["name"] for m in result["opa_modules"]]
        assert any("module_0" in n for n in module_names)

    def test_named_module_dict_preserves_name(self):
        result = translate_lula(_LULA_WITH_MODULES)
        module_names = [m["name"] for m in result["opa_modules"]]
        assert "named_module" in module_names

    def test_no_rego_produces_empty_modules_with_warning(self):
        # Should not raise — just produce empty modules list
        result = translate_lula(_LULA_NO_REGO)
        assert result["opa_modules"] == []

    def test_policy_name_sanitized(self):
        manifest = {
            "kind": "LulaValidation",
            "metadata": {"name": "my-validation-with-dashes"},
            "spec": {
                "domain": {"type": "kubernetes", "kubernetes-spec": {"resources": []}},
                "policy": {"opa": {"rego": "package lula\nvalidate if { true }"}},
            },
        }
        result = translate_lula(manifest)
        assert result["policy_name"] == "lula_my_validation_with_dashes"


# ---------------------------------------------------------------------------
# lula_to_opa_bundle_patch tests
# ---------------------------------------------------------------------------


class TestLulaToOPABundlePatch:
    def test_bundle_modules_present(self):
        result = lula_to_opa_bundle_patch(_MINIMAL_LULA_MANIFEST)
        assert "bundle_modules" in result
        assert len(result["bundle_modules"]) == 1

    def test_input_schema_built_from_k8s_resources(self):
        result = lula_to_opa_bundle_patch(_MINIMAL_LULA_MANIFEST)
        assert "input_schema" in result
        assert "opa-deployment" in result["input_schema"]

    def test_input_schema_resource_type(self):
        result = lula_to_opa_bundle_patch(_MINIMAL_LULA_MANIFEST)
        schema = result["input_schema"]["opa-deployment"]
        assert schema["type"] == "kubernetes_resource"

    def test_lula_policy_name_in_result(self):
        result = lula_to_opa_bundle_patch(_MINIMAL_LULA_MANIFEST)
        assert result["lula_policy_name"] == "lula_ac3_validation"
