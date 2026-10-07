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
Microsoft Presidio Identity-PII Redactor (Layer 3 Integration)
==============================================================

Encapsulates Microsoft Presidio (``presidio_analyzer`` + ``presidio_anonymizer``)
and spaCy NLP engine initialization and identity-entity redaction in its own
dedicated Layer 3 integration package, completely separated from the Layer 1
Kernel (``src/gateway/``) and from NVIDIA NeMo (``src/integrations/nemo/``).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Identity-bearing entities only. DATE_TIME, LOCATION and NRP are not
# redacted: on their own they do not identify a person, and redacting them
# mangles ordinary financial text ("reports on 22 October", "US equities")
# now that the redacted text replaces the message the agents see.
_PII_ENTITIES: list[str] = [
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PERSON",
    "CRYPTO",
    "US_SSN",
    "US_ITIN",
    "US_PASSPORT",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "IBAN_CODE",
    "IP_ADDRESS",
]

_presidio_analyzer: Any = None
_presidio_anonymizer: Any = None
_presidio_init_done: bool = False


def ensure_presidio_engines() -> None:
    """Lazy-initialise Microsoft Presidio engines once on first use.

    All callers (``redact_pii``, ``get_presidio_engines``, ``get_analyzer_patch``,
    ``build_presidio_sdd_action``, and ``MaskPIIAction``) share this single
    ``AnalyzerEngine`` + ``AnonymizerEngine`` pair so spaCy is loaded at most
    once per process.
    """
    global _presidio_analyzer, _presidio_anonymizer, _presidio_init_done
    if _presidio_init_done:
        return
    _presidio_init_done = True
    try:
        import spacy as _spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        class _SafeAnalyzer(AnalyzerEngine):
            """AnalyzerEngine that guards None input and defaults entity list when omitted."""

            _ENTITIES = list(_PII_ENTITIES)

            def analyze(self, text, entities=None, **kwargs):  # type: ignore[override, no-untyped-def]
                if text is None:
                    return []
                if not entities:
                    entities = self._ENTITIES
                return super().analyze(text=text, entities=entities, **kwargs)

        _spacy_model = (
            "en_core_web_lg"
            if _spacy.util.is_package("en_core_web_lg")
            else "en_core_web_sm"
        )
        _nlp_provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": _spacy_model}],
            }
        )
        _presidio_analyzer = _SafeAnalyzer(
            nlp_engine=_nlp_provider.create_engine(),
            default_score_threshold=0.3,
        )
        _presidio_anonymizer = AnonymizerEngine()
        logger.info(
            "✅ Presidio PII engines initialised (model=%s, entities=%d)",
            _spacy_model,
            len(_PII_ENTITIES),
        )
    except ImportError:
        logger.warning(
            "⚠️ Presidio not available — input-side PII scan disabled (graceful degradation). "
            "Install presidio-analyzer, presidio-anonymizer, and a spaCy model to enable."
        )
    except Exception as _presidio_init_exc:
        logger.warning(
            "⚠️ Presidio engine initialisation failed — input-side PII scan disabled: %s",
            _presidio_init_exc,
        )


def get_presidio_engines() -> tuple[Any, Any]:
    """Return the shared lazy-initialised ``(analyzer, anonymizer)`` singleton pair."""
    ensure_presidio_engines()
    return _presidio_analyzer, _presidio_anonymizer


def redact_pii(text: str) -> tuple[str, list[str]]:
    """Replace identity PII in ``text`` with ``<ENTITY_TYPE>`` tokens.

    Returns the redacted text and the sorted entity types found. When the
    Presidio engines are unavailable the text is returned unchanged. Engine
    errors propagate; each caller decides how to fail.
    """
    ensure_presidio_engines()
    if _presidio_analyzer is None or _presidio_anonymizer is None:
        return text, []
    results = _presidio_analyzer.analyze(
        text=text, entities=_PII_ENTITIES, language="en"
    )
    if not results:
        return text, []
    entity_types = sorted({r.entity_type for r in results})
    from presidio_anonymizer.entities import OperatorConfig

    anonymized = _presidio_anonymizer.anonymize(
        text=text,
        analyzer_results=results,  # type: ignore[arg-type]
        operators={
            et: OperatorConfig("replace", {"new_value": f"<{et}>"})
            for et in entity_types
        },
    )
    return anonymized.text, entity_types


def get_analyzer_patch() -> Any:
    """Return the shared Presidio ``AnalyzerEngine`` singleton for NeMo SDD hooks."""
    ensure_presidio_engines()
    return _presidio_analyzer


def build_presidio_sdd_action() -> Any:
    """Build a sensitive-data-detection coroutine backed by the shared Presidio singleton."""

    async def detect_sensitive_data(  # type: ignore[no-untyped-def]
        text: str = "",
        entities: list = None,  # type: ignore[assignment]
        score_threshold: float = 0.3,
        **kwargs,
    ) -> list:
        if not text:
            return []
        ensure_presidio_engines()
        if _presidio_analyzer is None:
            return []
        results = _presidio_analyzer.analyze(
            text=text, entities=entities or _PII_ENTITIES, language="en"
        )
        return [r for r in results if r.score >= score_threshold]

    return detect_sensitive_data

