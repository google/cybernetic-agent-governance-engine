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

"""Conformance reports and their provenance block. Standard library only.

A report records what was verified (``mode``, each input by the SHA-256 of its
bytes, one assertion per rule), the subject of the check
(``adapter_under_test``) and who ran it (``runner``). The verification posture
is derived from those fields alone and never taken from the report as written
(CONFORMANCE_VERIFIER_SPEC.md §3).

The runner's organization in a report is self-declared, so nothing in the
report proves who produced it. A report's own provenance can therefore carry
only ``AUTHOR_SELF_TEST`` or ``UNVERIFIED_LOCAL``: no report can be built with
``COUNTERPARTY_VERIFIED`` or ``INDEPENDENT_PARTY_VERIFIED``, and
:func:`validate_report` rejects one that claims either. Those need a verified
identity bound to the report digest, which only an attestation supplies
(``attestation.py``).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Any

from .stream_invariants import jcs_bytes

REPORT_SCHEMA_VERSION = "cage-conformance-report/1"
PROVENANCE_SCHEMA_VERSION = "cage-conformance-provenance/1"

#: The contract profile each verification mode checks against.
MODE_PROFILES: Mapping[str, str] = MappingProxyType(
    {"trace": "trace-v1", "stream": "stream-v1"}
)
MODES = tuple(MODE_PROFILES)

_ORG_TOKEN = re.compile(r"[a-z0-9]+")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_MIN_COMMIT_LENGTH = 7


class ReportError(ValueError):
    """A conformance report is malformed or internally inconsistent."""


class VerificationPosture(str, Enum):
    """Who ran a conformance check, relative to the parties to the seam."""

    AUTHOR_SELF_TEST = "AUTHOR_SELF_TEST"
    COUNTERPARTY_VERIFIED = "COUNTERPARTY_VERIFIED"
    INDEPENDENT_PARTY_VERIFIED = "INDEPENDENT_PARTY_VERIFIED"
    UNVERIFIED_LOCAL = "UNVERIFIED_LOCAL"


#: Postures that claim a verified runner identity.
ATTESTED_POSTURES = frozenset(
    {
        VerificationPosture.COUNTERPARTY_VERIFIED,
        VerificationPosture.INDEPENDENT_PARTY_VERIFIED,
    }
)


def normalize_org(name: str) -> str:
    """Compare organizations by alphanumeric runs: ``Google LLC`` == ``google-llc``."""
    return "-".join(_ORG_TOKEN.findall(name.casefold()))


def _require_text(owner: object, fields: tuple[str, ...]) -> None:
    for name in fields:
        value = getattr(owner, name)
        if not isinstance(value, str) or not value.strip():
            raise ReportError(f"{type(owner).__name__}.{name} must be non-blank text")


@dataclass(frozen=True)
class AdapterUnderTest:
    """The subject of a conformance check and the two parties to its seam."""

    provider_id: str
    adapter_author_org: str
    counterparty_org: str
    adapter_version: str
    adapter_commit: str
    contract_profile: str

    def __post_init__(self) -> None:
        _require_text(self, tuple(self.__dataclass_fields__))
        for name in ("adapter_author_org", "counterparty_org"):
            if not normalize_org(getattr(self, name)):
                raise ReportError(f"{name} must contain a letter or digit")
        if len(self.adapter_commit.strip()) < _MIN_COMMIT_LENGTH:
            raise ReportError(
                f"adapter_commit must be at least {_MIN_COMMIT_LENGTH} characters"
            )


@dataclass(frozen=True)
class RunnerProvenance:
    """Who ran the check, as the runner declared it."""

    runner_org: str
    runner_identity: str
    cage_conformance_version: str
    timestamp_utc: str

    def __post_init__(self) -> None:
        _require_text(self, tuple(self.__dataclass_fields__))
        if not normalize_org(self.runner_org):
            raise ReportError("runner_org must contain a letter or digit")
        candidate = self.timestamp_utc.strip()
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ReportError(
                f"timestamp_utc is not ISO 8601: {self.timestamp_utc!r}"
            ) from exc
        offset = parsed.utcoffset()
        if offset is None:
            raise ReportError("timestamp_utc must carry a UTC offset")
        if offset != timedelta(0):
            raise ReportError(f"timestamp_utc must be UTC, not {self.timestamp_utc!r}")


def derive_posture(
    adapter: AdapterUnderTest, runner: RunnerProvenance
) -> VerificationPosture:
    """The posture of a run without a verified runner identity.

    The author testing its own adapter claims nothing beyond that, so a
    self-declared author run is ``AUTHOR_SELF_TEST``. Any other self-declared
    runner is ``UNVERIFIED_LOCAL``: neither counterparty nor independent
    verification can be claimed without proof of who ran it.
    """
    if normalize_org(runner.runner_org) == normalize_org(adapter.adapter_author_org):
        return VerificationPosture.AUTHOR_SELF_TEST
    return VerificationPosture.UNVERIFIED_LOCAL


@dataclass(frozen=True)
class Provenance:
    """The provenance block every report carries (spec §3)."""

    adapter_under_test: AdapterUnderTest
    runner: RunnerProvenance
    verification_posture: VerificationPosture
    independent_of_author: bool
    third_party_independent: bool
    schema_version: str = PROVENANCE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "adapter_under_test": asdict(self.adapter_under_test),
            "runner": asdict(self.runner),
            "verification_posture": self.verification_posture.value,
            "independent_of_author": self.independent_of_author,
            "third_party_independent": self.third_party_independent,
        }


def build_provenance(adapter: AdapterUnderTest, runner: RunnerProvenance) -> Provenance:
    """A provenance block whose posture and flags are derived, never supplied."""
    posture = derive_posture(adapter, runner)
    return Provenance(
        adapter_under_test=adapter,
        runner=runner,
        verification_posture=posture,
        independent_of_author=posture in ATTESTED_POSTURES,
        third_party_independent=posture
        is VerificationPosture.INDEPENDENT_PARTY_VERIFIED,
    )


@dataclass(frozen=True)
class InputDigest:
    """One verified input: its file name and the SHA-256 of its bytes.

    The digest, not the name, identifies the input, so anyone holding the file
    can confirm with ``sha256sum`` that a report covers it. The CLI records the
    file name only, never the runner's local path.
    """

    name: str
    sha256: str

    def __post_init__(self) -> None:
        _require_text(self, ("name",))
        if not isinstance(self.sha256, str) or not _SHA256_HEX.fullmatch(self.sha256):
            raise ReportError("InputDigest.sha256 must be 64 lowercase hex characters")

    @classmethod
    def of_bytes(cls, name: str, data: bytes) -> InputDigest:
        """The digest of ``data``, read from the input called ``name``."""
        return cls(name=name, sha256=hashlib.sha256(data).hexdigest())


@dataclass(frozen=True)
class AssertionResult:
    """One rule's outcome over the whole input."""

    assertion_id: str
    title: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class ConformanceReport:
    """The outcome of one ``verify`` run.

    Construction enforces what :func:`validate_report` relies on: a known mode,
    at least one input, the contract profile of that mode, and a provenance
    block whose posture and flags :func:`build_provenance` derives.
    """

    mode: str
    inputs: tuple[InputDigest, ...]
    checked: int
    provenance: Provenance
    assertions: tuple[AssertionResult, ...]
    schema_version: str = REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "assertions", tuple(self.assertions))
        if not isinstance(self.mode, str) or self.mode not in MODE_PROFILES:
            raise ReportError(f"mode must be one of {list(MODES)}")
        if not self.inputs:
            raise ReportError("a report needs at least one input")
        if not all(isinstance(item, InputDigest) for item in self.inputs):
            raise ReportError("every input must be an InputDigest")
        checked = self.checked
        if isinstance(checked, bool) or not isinstance(checked, int) or checked < 0:
            raise ReportError("checked must be a non-negative integer")
        if not isinstance(self.provenance, Provenance):
            raise ReportError("provenance must be a Provenance")
        subject = self.provenance.adapter_under_test
        if subject.contract_profile != MODE_PROFILES[self.mode]:
            raise ReportError(
                f"contract_profile {subject.contract_profile!r} is not the "
                f"{self.mode} profile {MODE_PROFILES[self.mode]!r}"
            )
        if self.provenance != build_provenance(subject, self.provenance.runner):
            raise ReportError(
                "provenance posture and flags must be the ones build_provenance derives"
            )

    @property
    def conformant(self) -> bool:
        """True only if there is at least one assertion and every one passed."""
        return bool(self.assertions) and all(a.passed for a in self.assertions)

    def summary(self) -> dict[str, Any]:
        passed = sum(1 for a in self.assertions if a.passed)
        return {
            "total_assertions": len(self.assertions),
            "passed_assertions": passed,
            "failed_assertions": len(self.assertions) - passed,
            "conformant": self.conformant,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "inputs": [asdict(item) for item in self.inputs],
            "checked": self.checked,
            "provenance": self.provenance.to_dict(),
            "summary": self.summary(),
            "assertions": [asdict(a) for a in self.assertions],
        }

    def digest(self) -> str:
        """``sha256:`` + SHA-256 of the report's RFC 8785 canonical JSON."""
        return "sha256:" + hashlib.sha256(jcs_bytes(self.to_dict())).hexdigest()


# ── Strict parsing ────────────────────────────────────────────────────────────


def _mapping(raw: Any, where: str, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise ReportError(f"{where} must be a JSON object")
    missing = sorted(keys - raw.keys())
    unknown = sorted(set(raw) - keys)
    if missing:
        raise ReportError(f"{where} is missing {missing}")
    if unknown:
        raise ReportError(f"{where} has unknown fields {unknown}")
    return raw


def _strings(raw: Any, where: str, fields: tuple[str, ...]) -> dict[str, str]:
    obj = _mapping(raw, where, frozenset(fields))
    for name in fields:
        if not isinstance(obj[name], str):
            raise ReportError(f"{where}.{name} must be a string")
    return {name: obj[name] for name in fields}


def _bool(obj: Mapping[str, Any], key: str, where: str) -> bool:
    value = obj[key]
    if not isinstance(value, bool):
        raise ReportError(f"{where}.{key} must be a boolean")
    return value


_ADAPTER_FIELDS = tuple(AdapterUnderTest.__dataclass_fields__)
_RUNNER_FIELDS = tuple(RunnerProvenance.__dataclass_fields__)
_INPUT_FIELDS = tuple(InputDigest.__dataclass_fields__)
_PROVENANCE_KEYS = frozenset(
    {
        "schema_version",
        "adapter_under_test",
        "runner",
        "verification_posture",
        "independent_of_author",
        "third_party_independent",
    }
)
_REPORT_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "inputs",
        "checked",
        "provenance",
        "summary",
        "assertions",
    }
)
_ASSERTION_KEYS = frozenset({"assertion_id", "title", "passed", "detail"})


def _parse_provenance(raw: Any) -> Provenance:
    obj = _mapping(raw, "provenance", _PROVENANCE_KEYS)
    if obj["schema_version"] != PROVENANCE_SCHEMA_VERSION:
        raise ReportError(
            f"provenance.schema_version is {obj['schema_version']!r}, "
            f"expected {PROVENANCE_SCHEMA_VERSION!r}"
        )
    adapter = AdapterUnderTest(
        **_strings(obj["adapter_under_test"], "adapter_under_test", _ADAPTER_FIELDS)
    )
    runner = RunnerProvenance(**_strings(obj["runner"], "runner", _RUNNER_FIELDS))
    try:
        recorded = VerificationPosture(obj["verification_posture"])
    except ValueError as exc:
        raise ReportError(
            f"unknown verification_posture {obj['verification_posture']!r}"
        ) from exc
    if recorded in ATTESTED_POSTURES:
        raise ReportError(
            f"{recorded.value} requires a verified runner identity bound to the "
            "report digest; a report's own provenance never carries one (attest it)"
        )
    derived = build_provenance(adapter, runner)
    if recorded is not derived.verification_posture:
        raise ReportError(
            f"verification_posture {recorded.value} does not match the "
            f"derived {derived.verification_posture.value}"
        )
    for key in ("independent_of_author", "third_party_independent"):
        if _bool(obj, key, "provenance") != getattr(derived, key):
            raise ReportError(
                f"provenance.{key} contradicts {derived.verification_posture.value}"
            )
    return derived


def _parse_assertion(raw: Any, index: int) -> AssertionResult:
    where = f"assertions[{index}]"
    obj = _mapping(raw, where, _ASSERTION_KEYS)
    for key in ("assertion_id", "title", "detail"):
        if not isinstance(obj[key], str):
            raise ReportError(f"{where}.{key} must be a string")
    return AssertionResult(
        assertion_id=obj["assertion_id"],
        title=obj["title"],
        passed=_bool(obj, "passed", where),
        detail=obj["detail"],
    )


def validate_report(raw: Any) -> ConformanceReport:
    """Parse a report strictly and check that every derived field agrees.

    Raises:
        ReportError: on an unknown or missing field, a wrong type, a posture or
            independence flag that the provenance does not derive, a contract
            profile that is not the mode's, or a summary that the assertions do
            not add up to.
    """
    obj = _mapping(raw, "report", _REPORT_KEYS)
    if obj["schema_version"] != REPORT_SCHEMA_VERSION:
        raise ReportError(
            f"schema_version is {obj['schema_version']!r}, "
            f"expected {REPORT_SCHEMA_VERSION!r}"
        )
    for key in ("inputs", "assertions"):
        if not isinstance(obj[key], list):
            raise ReportError(f"{key} must be a list")

    report = ConformanceReport(
        mode=obj["mode"],
        inputs=tuple(
            InputDigest(**_strings(item, f"inputs[{index}]", _INPUT_FIELDS))
            for index, item in enumerate(obj["inputs"])
        ),
        checked=obj["checked"],
        provenance=_parse_provenance(obj["provenance"]),
        assertions=tuple(
            _parse_assertion(item, index)
            for index, item in enumerate(obj["assertions"])
        ),
    )
    if obj["summary"] != report.summary():
        raise ReportError("summary does not match the assertions")
    return report
