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

"""Offline Public Suffix List guarantees for Presidio & NeMo ``tldextract`` (POAM-2026-248).

Verifies that:
1. ``configure_offline_tldextract()`` both mutates any pre-bound
   ``TLD_EXTRACTOR`` instance in place and replaces
   ``tldextract.tldextract.TLD_EXTRACTOR`` with
   ``TLDExtract(suffix_list_urls=(), cache_dir=None)``, forcing immediate
   in-memory loading of the wheel's bundled ``.tld_set_snapshot`` with zero
   outbound HTTP calls and zero filesystem writes.
2. Importing ``src.integrations.presidio.redactor`` eagerly neutralizes
   ``TLD_EXTRACTOR`` before ``ensure_presidio_engines()`` or any NeMo SDD
   ``AnalyzerEngine`` runs.
3. ``src.integrations.nemo.manager._get_analyzer_patch`` accepts both
   ``score_threshold=...`` (as called by NeMo's ``detect_sensitive_data``) and
   zero arguments (as called by NeMo's ``mask_sensitive_data``).
4. ``pytest.ini`` ``addopts`` disables ``pytest-randomly`` (``-p no:randomly``)
   so blocking release gates maintain deterministic ``loadscope`` worker
   scheduling.
"""

from __future__ import annotations

import configparser
import importlib
import pkgutil
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
import tldextract
import tldextract.tldextract as tld_mod
from presidio_analyzer.predefined_recognizers import EmailRecognizer

from src.integrations.nemo import manager as nemo_manager
from src.integrations.presidio import redactor as presidio_redactor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_configure_offline_tldextract_mutates_bound_ref_and_replaces_singleton(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both a bound ``TLD_EXTRACTOR`` reference and ``tldextract.extract`` run offline."""
    unwritable = tmp_path / "nonexistent_ro_parent" / "cache"
    bound_ref = tldextract.TLDExtract(
        cache_dir=str(unwritable),
        suffix_list_urls=tld_mod.PUBLIC_SUFFIX_LIST_URLS,
    )
    monkeypatch.setattr(tld_mod, "TLD_EXTRACTOR", bound_ref)
    monkeypatch.setattr(presidio_redactor, "_tldextract_offline_done", False)

    extractor = presidio_redactor.configure_offline_tldextract()

    assert tld_mod.TLD_EXTRACTOR is extractor
    for candidate in (extractor, bound_ref):
        assert candidate.suffix_list_urls == ()
        assert candidate.fallback_to_snapshot is True
        assert candidate._cache.enabled is False

    with patch.object(
        requests.Session,
        "get",
        side_effect=AssertionError("unexpected outbound PSL HTTP fetch"),
    ):
        recognizer = EmailRecognizer()
        assert recognizer.validate_result("alice@example.co.uk") is True
        assert tldextract.extract("bob@sub.corp.org").fqdn == "sub.corp.org"
        assert bound_ref("carol@payments.example.co.uk").subdomain == "payments"

    assert not unwritable.exists(), (
        "offline extractor must not create cache directories"
    )


def test_redactor_import_eagerly_configures_offline_tldextract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Importing ``redactor`` neutralizes ``TLD_EXTRACTOR`` before engine warmup."""
    live_singleton = tldextract.TLDExtract(
        cache_dir=str(tmp_path / "cold"),
        suffix_list_urls=tld_mod.PUBLIC_SUFFIX_LIST_URLS,
    )
    monkeypatch.setattr(tld_mod, "TLD_EXTRACTOR", live_singleton)

    reloaded = importlib.reload(presidio_redactor)
    assert reloaded._tldextract_offline_done is True
    assert tld_mod.TLD_EXTRACTOR.suffix_list_urls == ()
    assert not tld_mod.TLD_EXTRACTOR._cache.enabled
    assert live_singleton.suffix_list_urls == ()
    assert not live_singleton._cache.enabled


def test_nemo_sdd_analyzer_patch_accepts_score_threshold_and_runs_offline() -> None:
    """``_get_analyzer_patch`` accepts both ``score_threshold=...`` and zero args."""
    snapshot = pkgutil.get_data("tldextract", ".tld_set_snapshot")
    assert snapshot is not None and len(snapshot) > 100_000

    with patch.object(
        requests.Session,
        "get",
        side_effect=AssertionError("unexpected outbound PSL HTTP fetch"),
    ):
        analyzer_with_kw = nemo_manager._get_analyzer_patch(score_threshold=0.3)
        analyzer_no_args = nemo_manager._get_analyzer_patch()
        assert analyzer_with_kw is not None
        assert analyzer_with_kw is analyzer_no_args

        redacted, entities = presidio_redactor.redact_pii(
            "Reach Jane Doe at jane.doe@example.co.uk regarding the account."
        )
    assert "EMAIL_ADDRESS" in entities
    assert "jane.doe@example.co.uk" not in redacted
    assert "<EMAIL_ADDRESS>" in redacted


def test_pytest_ini_disables_randomly_plugin_by_default() -> None:
    """Blocking gate runs disable ``pytest-randomly`` so xdist worker assignment stays deterministic."""
    parser = configparser.ConfigParser()
    parser.read(_REPO_ROOT / "pytest.ini", encoding="utf-8")
    addopts = parser.get("pytest", "addopts")
    assert "-p no:randomly" in addopts
