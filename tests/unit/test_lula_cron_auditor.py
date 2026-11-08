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

"""Unit tests for the in-cluster Lula compliance auditor, Dockerfile, RBAC, and bridge ingestion."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
from fastapi.testclient import TestClient

from src.compliance_bridge.auth import (
    _DEFAULT_TRUSTED_AUDIT_PRODUCERS,
    _DEFAULT_TRUSTED_INFRA_PRODUCERS,
)
from src.compliance_bridge.infra_custody import InfraEvidenceChain
from src.compliance_bridge.main import InfraEvent, app
from src.compliance_bridge.types import SUPPORTED_CONTROLS, get_iso_control_map

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_LULA = REPO_ROOT / "deployment" / "docker" / "Dockerfile.lula"
LULA_CRON_DIR = REPO_ROOT / "infra" / "modules" / "lula_cron"
RUN_SCRIPT = LULA_CRON_DIR / "run_lula_audit.sh"

CAGE_LULA_SA_L5D = (
    "cage-lula-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)


class TestDockerfileAndModuleHardening:
    """Verify Wolfi Lula 0.16.0 Dockerfile and least-privilege Terraform module contracts."""

    def test_dockerfile_lula_pins_0_16_0_sha256_on_wolfi_nonroot(self) -> None:
        text = DOCKERFILE_LULA.read_text(encoding="utf-8")
        assert "cgr.dev/chainguard/wolfi-base@sha256:" in text
        assert ":latest" not in text
        assert "ARG LULA_VERSION=0.16.0" in text
        assert (
            "5581257b6d0bf446e0a6ca3598de1697565f343f40e73055d0320a11d3a8c25e" in text
        )
        assert "sha256sum -c -" in text
        assert "apk add --no-cache ca-certificates curl jq" in text
        assert "USER 65532:65532" in text
        assert 'ENTRYPOINT ["/usr/local/bin/lula"]' in text

    def test_lula_cron_rbac_is_read_only_and_scopes_secrets_to_namespace(self) -> None:
        main_tf = (LULA_CRON_DIR / "main.tf").read_text(encoding="utf-8")
        cluster_role_match = re.search(
            r'resource\s+"kubernetes_cluster_role_v1"\s+"lula_reader"\s*\{(.*?)^\}',
            main_tf,
            re.M | re.S,
        )
        assert cluster_role_match is not None
        cr_body = cluster_role_match.group(1)
        assert '"secrets"' not in cr_body, (
            "ClusterRole must never grant cluster-wide secrets access"
        )
        assert '"*"' not in cr_body
        for verbs in re.findall(r"verbs\s*=\s*\[([^\]]+)\]", main_tf):
            parsed = set(re.findall(r'"([^"]+)"', verbs))
            assert parsed == {"get", "list"}, (
                f"Expected read-only get/list verbs, got {parsed}"
            )

        ns_role_match = re.search(
            r'resource\s+"kubernetes_role_v1"\s+"lula_namespace_secrets_reader"\s*\{(.*?)^\}',
            main_tf,
            re.M | re.S,
        )
        assert ns_role_match is not None
        assert "namespace = var.namespace" in ns_role_match.group(1)
        assert 'resources  = ["secrets"]' in ns_role_match.group(1)

    def test_lula_cron_security_context_and_linkerd_injection(self) -> None:
        main_tf = (LULA_CRON_DIR / "main.tf").read_text(encoding="utf-8")
        assert 'concurrency_policy            = "Forbid"' in main_tf
        assert '"linkerd.io/inject"         = "enabled"' in main_tf
        assert "read_only_root_filesystem  = true" in main_tf
        assert "allow_privilege_escalation = false" in main_tf
        assert "run_as_user                = 65532" in main_tf
        assert "run_as_group               = 65532" in main_tf
        assert 'drop = ["ALL"]' in main_tf


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestRunLulaAuditScript:
    """Execute `run_lula_audit.sh` hermetically to verify pass and fail-closed branches."""

    def _setup_mock_tools(
        self,
        tmp_path: Path,
        *,
        lula_output: str,
        lula_exit: int = 0,
        post_exit: int = 0,
        post_body: str = '{"status":"INGESTED","record_hash":"' + ("a" * 64) + '"}',
        ready_ok: bool = True,
    ) -> tuple[Path, Path, Path]:
        bin_dir = tmp_path / "bin"
        specs_dir = tmp_path / "specs"
        out_dir = tmp_path / "out"
        log_file = tmp_path / "curl.log"
        bin_dir.mkdir()
        specs_dir.mkdir()
        out_dir.mkdir()

        _write_executable(
            bin_dir / "lula",
            f"""#!/bin/sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    out="$2"
    shift 2
  else
    shift 1
  fi
done
if [ -n "$out" ]; then
  cat <<'LULA_OUT' > "$out"
{lula_output}
LULA_OUT
fi
exit {lula_exit}
""",
        )

        ready_rc = 0 if ready_ok else 1
        _write_executable(
            bin_dir / "curl",
            f"""#!/bin/sh
set -eu
url=""
body=""
idem=""
prev=""
for arg in "$@"; do
  case "$prev" in
    -d) body="$arg" ;;
    -H)
      case "$arg" in
        Idempotency-Key:*) idem="$arg" ;;
      esac
      ;;
  esac
  case "$arg" in
    http://*|https://*) url="$arg" ;;
  esac
  prev="$arg"
done
printf '%s|%s|%s\\n' "$url" "$idem" "$body" >> "{log_file}"
case "$url" in
  */ready) exit {ready_rc} ;;
  */shutdown) exit 0 ;;
  */v1/infra/events)
    if [ {post_exit} -eq 0 ]; then
      cat <<'RESP_JSON'
{post_body}
RESP_JSON
    fi
    exit {post_exit}
    ;;
esac
exit 0
""",
        )
        return bin_dir, specs_dir, log_file

    def _run(
        self, bin_dir: Path, specs_dir: Path, tmp_path: Path
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '/usr/bin:/bin')}"
        env["LULA_BIN"] = str(bin_dir / "lula")
        env["LULA_SPECS_DIR"] = str(specs_dir)
        env["LULA_OUT_DIR"] = str(tmp_path / "out")
        env["COMPLIANCE_BRIDGE_EVENTS_URL"] = (
            "http://compliance-bridge.governance-stack.svc.cluster.local:8085/v1/infra/events"
        )
        env["HOSTNAME"] = "lula-audit-28900000-abcde"
        return subprocess.run(
            ["/bin/sh", "-ec", RUN_SCRIPT.read_text(encoding="utf-8")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_all_satisfied_posts_event_without_spoofable_identity_fields_and_shuts_down_sidecar(
        self, tmp_path: Path
    ) -> None:
        bin_dir, specs_dir, log_file = self._setup_mock_tools(
            tmp_path,
            lula_output=(
                "assessment-results:\n"
                "  results:\n"
                "    - observations:\n"
                "        - relevant-evidence: []\n"
                "      findings:\n"
                "        - target:\n"
                "            status:\n"
                "              state: satisfied\n"
            ),
        )
        (specs_dir / "lula-validation-ac2.yaml").write_text(
            "metadata: {}\n", encoding="utf-8"
        )
        (specs_dir / "lula-validation-si2.yaml").write_text(
            "metadata: {}\n", encoding="utf-8"
        )

        proc = self._run(bin_dir, specs_dir, tmp_path)
        assert proc.returncode == 0, proc.stderr
        assert "status=INGESTED" in proc.stdout
        assert f"record_hash={'a' * 64}" in proc.stdout
        assert "(2/2 satisfied, 0 not-satisfied)" in proc.stdout

        calls = log_file.read_text(encoding="utf-8").strip().splitlines()
        urls = [line.split("|", 1)[0] for line in calls]
        assert "http://127.0.0.1:4191/ready" in urls
        assert (
            "http://compliance-bridge.governance-stack.svc.cluster.local:8085/v1/infra/events"
            in urls
        )
        assert urls[-1] == "http://127.0.0.1:4191/shutdown"

        post_line = next(line for line in calls if "/v1/infra/events" in line)
        _, idem_header, raw_json = post_line.split("|", 2)
        assert idem_header.startswith("Idempotency-Key: lula-audit-")
        payload = json.loads(raw_json)
        assert payload["event_type"] == "lula_audit"
        assert payload["control_hint"] == "A.5.3"
        assert "2/2 active validations satisfied" in payload["summary"]
        assert "source" not in payload
        assert "namespace" not in payload
        assert "pod_name" not in payload
        validated = InfraEvent.model_validate(payload)
        assert validated.event_type == "lula_audit"

    @pytest.mark.parametrize(
        "bad_output",
        [
            "observations:\n  - state: not-satisfied\n",
            "observations:\n  - remarks: lula-validation-error\n",
            "assessment-results:\n  results: []\n",
        ],
    )
    def test_unsatisfied_or_malformed_lula_output_fails_closed(
        self, tmp_path: Path, bad_output: str
    ) -> None:
        bin_dir, specs_dir, log_file = self._setup_mock_tools(
            tmp_path, lula_output=bad_output
        )
        (specs_dir / "lula-validation-ac2.yaml").write_text(
            "metadata: {}\n", encoding="utf-8"
        )

        proc = self._run(bin_dir, specs_dir, tmp_path)
        assert proc.returncode == 1
        calls = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert calls[-1].startswith("http://127.0.0.1:4191/shutdown|")

    def test_zero_specs_fails_closed(self, tmp_path: Path) -> None:
        bin_dir, specs_dir, log_file = self._setup_mock_tools(
            tmp_path, lula_output="observations:\n  - state: satisfied\n"
        )
        proc = self._run(bin_dir, specs_dir, tmp_path)
        assert proc.returncode == 1
        assert "zero Lula validation manifests" in proc.stderr
        calls = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert calls[-1].startswith("http://127.0.0.1:4191/shutdown|")

    def test_bridge_post_failure_fails_closed_even_when_specs_pass(
        self, tmp_path: Path
    ) -> None:
        bin_dir, specs_dir, _ = self._setup_mock_tools(
            tmp_path,
            lula_output="observations:\n  - state: satisfied\n",
            post_exit=22,
        )
        (specs_dir / "lula-validation-ac2.yaml").write_text(
            "metadata: {}\n", encoding="utf-8"
        )
        proc = self._run(bin_dir, specs_dir, tmp_path)
        assert proc.returncode == 1
        assert "failed to POST lula_audit event" in proc.stderr

    def test_unacknowledged_custody_receipt_fails_closed(self, tmp_path: Path) -> None:
        bin_dir, specs_dir, _ = self._setup_mock_tools(
            tmp_path,
            lula_output="observations:\n  - state: satisfied\n",
            post_body='{"status":"DROPPED"}',
        )
        (specs_dir / "lula-validation-ac2.yaml").write_text(
            "metadata: {}\n", encoding="utf-8"
        )
        proc = self._run(bin_dir, specs_dir, tmp_path)
        assert proc.returncode == 1
        assert "failed to POST lula_audit event" in proc.stderr


class TestComplianceBridgeLulaAuditIntegration:
    """Verify compliance-bridge authorizes `cage-lula-sa` and seals `lula_audit` events."""

    def test_universal_control_map_maps_lula_audit_to_supported_control_in_all_regions(
        self,
    ) -> None:
        assert CAGE_LULA_SA_L5D in _DEFAULT_TRUSTED_INFRA_PRODUCERS
        assert CAGE_LULA_SA_L5D in _DEFAULT_TRUSTED_AUDIT_PRODUCERS
        for region in ("US_FED", "EU_ECB", "APAC_MAS"):
            cmap = get_iso_control_map(region)
            assert cmap["lula_audit"] == "A.5.3"
            assert cmap["lula_audit"] in SUPPORTED_CONTROLS

    def test_ingest_lula_audit_event_via_cage_lula_sa_mesh_identity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "test")
        monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "false")
        monkeypatch.setenv("CAGE_INFRA_CUSTODY_FLUSH_INLINE", "false")
        monkeypatch.delenv("CAGE_TRUSTED_INFRA_PRODUCERS", raising=False)
        monkeypatch.setenv("POD_IP", "10.24.1.9")

        fake_server = fakeredis.FakeServer()
        chain = InfraEvidenceChain(
            fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
            stream_key="cage:test:infra:lula",
        )
        app.state.infra_evidence_chain = chain
        try:
            with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
                with TestClient(
                    app,
                    client=("10.24.1.9", 50000),
                    base_url="http://10.24.1.9:3001",
                    raise_server_exceptions=False,
                ) as client:
                    resp = client.post(
                        "/v1/infra/events",
                        headers={
                            "l5d-client-id": CAGE_LULA_SA_L5D,
                            "Idempotency-Key": "lula-audit-pod1-2026-11-08T00:00:00Z",
                        },
                        json={
                            "event_type": "lula_audit",
                            "timestamp_utc": "2026-11-08T00:00:00Z",
                            "summary": "lula_audit PASS: 26/26 active validations satisfied",
                            "control_hint": "A.5.3",
                        },
                    )
                    assert resp.status_code == 200, resp.text
                    body = resp.json()
                    assert body["status"] == "INGESTED"
                    assert body["event_type"] == "lula_audit"
                    assert body["control_id"] == "A.5.3"
                    assert body["evidence_class"] == "INFRA"
                    assert body["source"] == "cage-lula-sa"
                    assert body["namespace"] == "governance-stack"
                    assert len(body["record_hash"]) == 64

                    spoof_resp = client.post(
                        "/v1/infra/events",
                        headers={"l5d-client-id": CAGE_LULA_SA_L5D},
                        json={
                            "event_type": "lula_audit",
                            "timestamp_utc": "2026-11-08T00:00:00Z",
                            "summary": "lula_audit PASS: 26/26 active validations satisfied",
                            "control_hint": "A.5.3",
                            "pod_name": "spoofed-pod-123",
                        },
                    )
                    assert spoof_resp.status_code == 403
        finally:
            if hasattr(app.state, "infra_evidence_chain"):
                delattr(app.state, "infra_evidence_chain")
