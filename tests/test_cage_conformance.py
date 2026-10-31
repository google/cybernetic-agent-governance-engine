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

"""packages/cage-conformance, the standalone verifier (W4).

Checks the properties the package exists for
(docs/architecture/CONFORMANCE_VERIFIER_SPEC.md):

* it applies exactly proof/'s checks: byte-identical copies, enforced by
  scripts/check_conformance_sync.py;
* it runs on the standard library alone, with no CAGE checkout;
* a self-declared runner can never claim counterparty or independent
  verification;
* a report names its inputs by SHA-256, never by local path, and its derived
  fields can't be edited without detection.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE_ROOT = _REPO_ROOT / "packages" / "cage-conformance"
_PACKAGE_SRC = _PACKAGE_ROOT / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

import cage_conformance as cc  # noqa: E402
from cage_conformance import runner as runner_mod  # noqa: E402
from cage_conformance.cli import main as cli_main  # noqa: E402
from cage_conformance.stream_invariants import (  # noqa: E402
    compute_cage_audit_hash,
    jcs_bytes,
)
from cage_conformance.trace_conformance import Finding  # noqa: E402

from proof.trace_conformance import check_trace as repo_check_trace  # noqa: E402
from scripts import check_conformance_sync as sync  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.local]

_VECTOR = json.loads(
    (_PACKAGE_SRC / "cage_conformance" / "vectors" / "trace_v1.json").read_text(
        encoding="utf-8"
    )
)
_CONFORMANT: list[dict[str, Any]] = _VECTOR["conformant_trace"]
_INPUTS = (cc.InputDigest.of_bytes("trace.jsonl", jcs_bytes(_CONFORMANT)),)
_PROVENANCE_FLAGS = [
    "--provider-id",
    "cage-kernel",
    "--adapter-author-org",
    "Google LLC",
    "--counterparty-org",
    "Example Deployer",
    "--adapter-version",
    "5.0.0",
    "--adapter-commit",
    "5b0055ad",
    "--runner-org",
    "Google LLC",
    "--runner-identity",
    "ci@example.com",
]


def _adapter(**overrides: str) -> cc.AdapterUnderTest:
    fields = {
        "provider_id": "cage-kernel",
        "adapter_author_org": "Google LLC",
        "counterparty_org": "Example Deployer",
        "adapter_version": "5.0.0",
        "adapter_commit": "5b0055ad",
        "contract_profile": "trace-v1",
    }
    return cc.AdapterUnderTest(**(fields | overrides))


def _runner(org: str = "Google LLC", **overrides: str) -> cc.RunnerProvenance:
    fields = {
        "runner_org": org,
        "runner_identity": "ci@example.com",
        "cage_conformance_version": cc.__version__,
        "timestamp_utc": "2026-10-31T19:00:00+00:00",
    }
    return cc.RunnerProvenance(**(fields | overrides))


def _provenance(org: str = "Google LLC", mode: str = "trace") -> cc.Provenance:
    adapter = _adapter(contract_profile=cc.MODE_PROFILES[mode])
    return cc.build_provenance(adapter, _runner(org))


def _write_jsonl(path: Path, items: list[dict[str, Any]]) -> Path:
    path.write_text(
        "".join(json.dumps(item) + "\n" for item in items), encoding="utf-8"
    )
    return path


# ── One source of truth: proof/ and the package never diverge ────────────────


def test_packaged_proof_modules_are_byte_identical_and_isolated() -> None:
    assert sync.sync_violations() == []
    assert sync.import_violations() == []


def test_sync_pairs_cover_every_proof_module_the_package_runs() -> None:
    assert {Path(copy).name for _, copy in sync.SYNC_PAIRS} == {
        "model.py",
        "trace_conformance.py",
        "stream_invariants.py",
    }
    for original, copy in sync.SYNC_PAIRS:
        assert Path(original).name == Path(copy).name


def test_sync_gate_catches_a_fork(tmp_path: Path) -> None:
    for original, copy in sync.SYNC_PAIRS:
        for target in (original, copy):
            (tmp_path / target).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_REPO_ROOT / original, tmp_path / target)
    assert sync.sync_violations(tmp_path) == []

    original, copy = sync.SYNC_PAIRS[2]
    forked = tmp_path / copy
    forked.write_text(forked.read_text(encoding="utf-8") + "# fork\n", encoding="utf-8")
    assert sync.sync_violations(tmp_path) == [
        f"{copy} differs from {original}: copy it from proof/"
    ]


@pytest.mark.parametrize(
    "line",
    [
        "import src.gateway.governance",
        "from src import gateway",
        "from proof.model import TIERS",
        "import proof.stream_invariants",
    ],
)
def test_isolation_gate_rejects_checkout_imports(tmp_path: Path, line: str) -> None:
    package = tmp_path / "cage_conformance"
    package.mkdir()
    (package / "fine.py").write_text("import json\nfrom .model import TIERS\n")
    (package / "leak.py").write_text(f"{line}\n")
    (errors,) = sync.import_violations(package)
    assert "leak.py:1" in errors


def test_package_version_matches_its_metadata() -> None:
    metadata = (_PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'^version = "{re.escape(cc.__version__)}"$', metadata, re.M)
    assert re.search(r"^dependencies = \[\]$", metadata, re.M), "must stay stdlib-only"


def test_runs_on_the_standard_library_alone(tmp_path: Path) -> None:
    """No site-packages and no CAGE checkout: only the package on sys.path."""
    site = tmp_path / "site"
    shutil.copytree(
        _PACKAGE_SRC / "cage_conformance",
        site / "cage_conformance",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    trace = _write_jsonl(tmp_path / "trace.jsonl", _CONFORMANT)
    report = tmp_path / "report.json"
    argv = [
        "verify",
        "--trace",
        str(trace),
        "--output",
        str(report),
        *_PROVENANCE_FLAGS,
    ]
    script = "\n".join(
        [
            "import sys",
            f"sys.path.insert(0, {str(site)!r})",
            "from cage_conformance.cli import main",
            f"code = main({argv!r})",
            "leaked = sorted(m for m in sys.modules if m.split('.')[0] in {'src', 'proof'})",
            "assert not leaked, leaked",
            "assert 'cryptography' not in sys.modules",
            "raise SystemExit(code)",
        ]
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-I", "-S", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(report.read_text())["summary"]["conformant"] is True


# ── Posture: a self-declared runner never claims verification ────────────────


@pytest.mark.parametrize(
    ("runner_org", "posture"),
    [
        ("Google LLC", cc.VerificationPosture.AUTHOR_SELF_TEST),
        ("google-llc", cc.VerificationPosture.AUTHOR_SELF_TEST),
        ("Example Deployer", cc.VerificationPosture.UNVERIFIED_LOCAL),
        ("Example Auditor", cc.VerificationPosture.UNVERIFIED_LOCAL),
    ],
)
def test_a_self_declared_runner_never_claims_verification(
    runner_org: str, posture: cc.VerificationPosture
) -> None:
    provenance = _provenance(runner_org)
    assert provenance.verification_posture is posture
    assert provenance.verification_posture not in cc.ATTESTED_POSTURES
    assert provenance.independent_of_author is False
    assert provenance.third_party_independent is False


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda: _adapter(adapter_author_org="--"), "letter or digit"),
        (lambda: _adapter(adapter_commit="abc"), "at least 7"),
        (lambda: _adapter(provider_id=" "), "non-blank"),
        (lambda: _runner(timestamp_utc="2026-10-31T19:00:00"), "UTC offset"),
        (lambda: _runner(timestamp_utc="2026-10-31T19:00:00+05:00"), "must be UTC"),
        (lambda: _runner(timestamp_utc="yesterday"), "ISO 8601"),
        (lambda: cc.InputDigest(name="trace.jsonl", sha256="AB" * 32), "lowercase hex"),
        (lambda: cc.InputDigest(name=" ", sha256="ab" * 32), "non-blank"),
    ],
)
def test_provenance_rejects_unusable_fields(build: Any, message: str) -> None:
    with pytest.raises(cc.ReportError, match=message):
        build()


# ── Reports: derived fields are checked, and edits are detected ──────────────


def _report() -> cc.ConformanceReport:
    return cc.verify_trace(_CONFORMANT, provenance=_provenance(), inputs=_INPUTS)


def test_report_round_trips_with_a_stable_digest() -> None:
    report = _report()
    parsed = cc.validate_report(json.loads(json.dumps(report.to_dict())))
    assert parsed == report
    assert parsed.digest() == report.digest()
    assert report.digest().startswith("sha256:") and len(report.digest()) == 71


def test_a_report_cannot_be_built_around_a_claimed_posture() -> None:
    """The posture is derived at construction, not only when parsing JSON."""
    derived = _provenance("Example Deployer")
    claimed = cc.Provenance(
        adapter_under_test=derived.adapter_under_test,
        runner=derived.runner,
        verification_posture=cc.VerificationPosture.COUNTERPARTY_VERIFIED,
        independent_of_author=True,
        third_party_independent=False,
    )
    with pytest.raises(cc.ReportError, match="build_provenance derives"):
        cc.verify_trace(_CONFORMANT, provenance=claimed, inputs=_INPUTS)
    with pytest.raises(cc.ReportError, match="at least one input"):
        cc.verify_trace(_CONFORMANT, provenance=derived, inputs=())


def _set(path: tuple[str | int, ...], value: Any) -> dict[str, Any]:
    raw = json.loads(json.dumps(_report().to_dict()))
    node = raw
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return raw


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (
            _set(("provenance", "verification_posture"), "COUNTERPARTY_VERIFIED"),
            "requires a verified runner identity",
        ),
        (
            _set(("provenance", "verification_posture"), "INDEPENDENT_PARTY_VERIFIED"),
            "requires a verified runner identity",
        ),
        (
            _set(("provenance", "verification_posture"), "UNVERIFIED_LOCAL"),
            "does not match the derived AUTHOR_SELF_TEST",
        ),
        (_set(("provenance", "independent_of_author"), True), "contradicts"),
        (_set(("provenance", "verification_posture"), "TRUSTED"), "unknown"),
        (
            _set(("provenance", "adapter_under_test", "contract_profile"), "stream-v1"),
            "is not the trace profile",
        ),
        (_set(("summary", "conformant"), False), "summary does not match"),
        (_set(("assertions", 1, "passed"), False), "summary does not match"),
        (_set(("checked",), True), "non-negative integer"),
        (_set(("mode",), "endpoint"), "mode must be one of"),
        (_set(("mode",), ["trace"]), "mode must be one of"),
        (_set(("inputs",), []), "at least one input"),
        (_set(("inputs", 0), "trace.jsonl"), "must be a JSON object"),
        (_set(("inputs", 0, "sha256"), "0" * 63), "lowercase hex"),
        (_set(("schema_version",), "cage-conformance-report/0"), "schema_version"),
        (_set(("extra",), 1), "unknown fields"),
        (
            _set(("provenance", "runner", "timestamp_utc"), "2026-10-31T19:00:00"),
            "UTC offset",
        ),
    ],
)
def test_validate_report_rejects_edits(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(cc.ReportError, match=message):
        cc.validate_report(raw)


def test_any_assertion_or_input_edit_changes_the_digest() -> None:
    report = _report()
    raw = report.to_dict()
    raw["assertions"][1]["detail"] = "edited"
    assert cc.validate_report(raw).digest() != report.digest()
    raw = report.to_dict()
    raw["inputs"][0]["sha256"] = "0" * 64
    assert cc.validate_report(raw).digest() != report.digest()


# ── Trace mode ────────────────────────────────────────────────────────────────


def test_trace_vector_is_conformant_in_both_copies() -> None:
    assert repo_check_trace(_CONFORMANT) == []
    report = _report()
    assert report.conformant
    assert report.checked == 2
    assert [a.assertion_id for a in report.assertions] == [
        cc.INPUT_ASSERTION,
        *cc.TRACE_RULES,
    ]


@pytest.mark.parametrize(
    ("events", "failing"),
    [
        ([_CONFORMANT[1]], {"no_direct_bind"}),
        ([*_CONFORMANT, _CONFORMANT[1]], {"single_use"}),
        ([_CONFORMANT[0] | {"profile": "DRY_RUN"}], {"seal", "reachable"}),
        ([], {cc.INPUT_ASSERTION}),
    ],
)
def test_trace_violations_fail_their_rule(
    events: list[dict[str, Any]], failing: set[str]
) -> None:
    report = cc.verify_trace(events, provenance=_provenance(), inputs=_INPUTS)
    assert not report.conformant
    assert {a.assertion_id for a in report.assertions if not a.passed} == failing


def test_a_finding_under_an_unlisted_rule_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner_mod, "check_trace", lambda events: [Finding(0, "future_rule", "x")]
    )
    report = cc.verify_trace(_CONFORMANT, provenance=_provenance(), inputs=_INPUTS)
    assert not report.conformant
    (failed,) = [a for a in report.assertions if not a.passed]
    assert failed.assertion_id == "future_rule"
    assert failed.detail == "#0: x"


# ── Stream mode ───────────────────────────────────────────────────────────────


def _chain(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    prev_hash = ""
    for sequence, payload in enumerate(payloads):
        payload_json = jcs_bytes(payload).decode("utf-8")
        fields = {
            "event_type": str(payload["type"]),
            "control_id": "AU-10",
            "trace_id": "0123456789abcdef0123456789abcdef",
            "chain_id": "chain-1",
        }
        record_hash = compute_cage_audit_hash(
            prev_hash=prev_hash,
            sequence=sequence,
            payload_json=payload_json,
            **fields,
        )
        records.append(
            {
                "schema": "cage-audit/3.0",
                "sequence": str(sequence),
                "timestamp_utc": "2026-10-31T19:00:00+00:00",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "evidence_class": "GOVERNANCE",
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "payload_json": payload_json,
                **fields,
            }
        )
        prev_hash = record_hash
    return records


_NOTES = [{"type": "AUDIT_NOTE", "note": f"n{i}"} for i in range(3)]


def test_an_intact_stream_is_conformant() -> None:
    report = cc.verify_stream(
        _chain(_NOTES), provenance=_provenance(mode="stream"), inputs=_INPUTS
    )
    assert report.conformant, [a for a in report.assertions if not a.passed]
    assert report.mode == "stream"
    assert report.checked == 3


def test_stream_tampering_and_loss_fail_their_rules() -> None:
    provenance = _provenance(mode="stream")
    records = _chain(_NOTES)
    records[1] = records[1] | {"payload_json": '{"note":"edited","type":"AUDIT_NOTE"}'}
    tampered = cc.verify_stream(records, provenance=provenance, inputs=_INPUTS)
    assert "chain_hash" in {a.assertion_id for a in tampered.assertions if not a.passed}

    lossy = cc.verify_stream(
        _chain(_NOTES), provenance=provenance, inputs=_INPUTS, publish_failures=1
    )
    failed = [a for a in lossy.assertions if not a.passed]
    assert [a.assertion_id for a in failed] == ["evidence_loss"]
    assert failed[0].detail.startswith("stream: ")


# ── CLI ───────────────────────────────────────────────────────────────────────


def test_cli_verify_then_verify_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    trace = _write_jsonl(tmp_path / "trace.jsonl", _CONFORMANT)
    out = tmp_path / "report.json"
    argv = ["verify", "--trace", str(trace), "--output", str(out), *_PROVENANCE_FLAGS]
    assert cli_main(argv) == 0
    assert "CONFORMANT" in capsys.readouterr().out

    text = out.read_text()
    digest = hashlib.sha256(trace.read_bytes()).hexdigest()
    assert json.loads(text)["inputs"] == [{"name": "trace.jsonl", "sha256": digest}]
    assert str(tmp_path) not in text, "a report must not record local paths"

    assert cli_main(["verify-report", str(out)]) == 0
    assert "posture=AUTHOR_SELF_TEST" in capsys.readouterr().out

    raw = json.loads(text)
    raw["provenance"]["verification_posture"] = "COUNTERPARTY_VERIFIED"
    out.write_text(json.dumps(raw))
    assert cli_main(["verify-report", str(out)]) == 2
    assert "invalid report" in capsys.readouterr().err


def test_cli_reads_stdin_with_crlf_line_endings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = "".join(json.dumps(event) + "\r\n" for event in _CONFORMANT).encode()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
    out = tmp_path / "report.json"
    argv = ["verify", "--trace", "-", "--output", str(out), *_PROVENANCE_FLAGS]
    assert cli_main(argv) == 0
    report = json.loads(out.read_text())
    assert report["checked"] == len(_CONFORMANT)
    assert report["inputs"] == [
        {"name": "<stdin>", "sha256": hashlib.sha256(data).hexdigest()}
    ]


def test_cli_stream_mode_and_failure_exit_codes(tmp_path: Path) -> None:
    stream = _write_jsonl(tmp_path / "stream.jsonl", _chain(_NOTES))
    assert cli_main(["verify", "--stream", str(stream), *_PROVENANCE_FLAGS]) == 0
    lossy = ["verify", "--stream", str(stream), "--publish-failures", "1"]
    assert cli_main([*lossy, *_PROVENANCE_FLAGS]) == 1
    executed_only = _write_jsonl(tmp_path / "bad.jsonl", [_CONFORMANT[1]])
    assert cli_main(["verify", "--trace", str(executed_only), *_PROVENANCE_FLAGS]) == 1
    missing = str(tmp_path / "absent.jsonl")
    assert cli_main(["verify", "--trace", missing, *_PROVENANCE_FLAGS]) == 2


def test_cli_requires_every_identity_flag(tmp_path: Path) -> None:
    trace = _write_jsonl(tmp_path / "trace.jsonl", _CONFORMANT)
    without_runner = _PROVENANCE_FLAGS[:-4]
    with pytest.raises(SystemExit) as exc:
        cli_main(["verify", "--trace", str(trace), *without_runner])
    assert exc.value.code == 2
