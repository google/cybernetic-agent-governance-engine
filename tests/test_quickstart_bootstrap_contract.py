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

"""Quickstart bootstrap and Docker Compose smoke contract tests.

Prevents regressions on the documented `docs/QUICKSTART.md` onboarding path:
1. `docker-compose.yml`, `docker-compose.dev.yml`, `.env.example`, and
   `config/environments/local-dev.env.example` must configure `OPA_URL` as a
   base URL without a path (validated against `_opa_endpoint()`).
2. The `opa` service in `docker-compose.yml` must mount `./config/opa` and
   ONLY the active domain's Rego directory (`./src/cage_${CAGE_DOMAIN:-finance}/opa`),
   never the non-existent `./policies` directory or multiple domains at once,
   and must pass `--ignore=.*` so `config/opa/.policy_hash` does not break
   `opa run` or `opa check`.
3. `examples/governance_demo.py --no-pause` must execute all three acts cleanly
   and demonstrate atomic TOCTOU rejection.
"""

from __future__ import annotations

import pathlib
from unittest.mock import patch

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _extract_env_dict(env_list_or_dict: list[str] | dict[str, str]) -> dict[str, str]:
    if isinstance(env_list_or_dict, dict):
        return {str(k): str(v) for k, v in env_list_or_dict.items()}
    out: dict[str, str] = {}
    for entry in env_list_or_dict:
        if "=" in entry:
            k, v = entry.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def test_docker_compose_opa_mounts_and_ignore_flag() -> None:
    """OPA service in docker-compose.yml mounts existing active-domain Rego dir and ignores dotfiles."""
    compose_path = _REPO_ROOT / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    opa_svc = compose["services"]["opa"]

    assert opa_svc.get("image") == "openpolicyagent/opa:0.70.0-static", (
        "opa image must be pinned to 0.70.0-static (matching Dockerfile.opa)"
    )

    volumes: list[str] = opa_svc.get("volumes", [])
    assert not any(v.startswith("./policies:") for v in volumes), (
        "docker-compose.yml must not mount non-existent ./policies directory"
    )
    assert not any("opa_socket_vol" in v for v in volumes), (
        "opa service must not mount root-owned opa_socket_vol over /tmp in non-root static image"
    )
    assert "./src/cage_${CAGE_DOMAIN:-finance}/opa:/policies:ro" in volumes

    # Verify single-domain isolation: neither finance nor healthcare is hardcoded
    # alongside the other in the OPA volume list.
    assert not (
        any("cage_finance" in v for v in volumes)
        and any("cage_healthcare" in v for v in volumes)
    ), "OPA must mount only the active CAGE_DOMAIN policy bundle, not both domains"

    # Both runnable domains' Rego directories must exist and contain .rego files
    for domain in ("finance", "healthcare"):
        domain_opa = _REPO_ROOT / "src" / f"cage_{domain}" / "opa"
        assert domain_opa.is_dir(), f"Missing OPA directory for {domain}: {domain_opa}"
        assert list(domain_opa.glob("*.rego")), f"No .rego files in {domain_opa}"

    # Verify --ignore=.* is passed to both command and healthcheck and no unix socket is bound.
    command: list[str] = opa_svc.get("command", [])
    assert "--ignore=.*" in command, "opa command must include --ignore=.*"
    assert not any("opa.sock" in arg for arg in command), (
        "opa command must not bind unix:///tmp/opa.sock in non-root static container"
    )
    healthcheck_cmd: list[str] = opa_svc.get("healthcheck", {}).get("test", [])
    assert "--ignore=.*" in healthcheck_cmd, "opa healthcheck must include --ignore=.*"

    gw_svc = compose["services"]["gateway"]
    gw_volumes: list[str] = gw_svc.get("volumes", [])
    assert not any("opa_socket_vol" in v for v in gw_volumes), (
        "gateway service must not mount root-owned opa_socket_vol over /tmp in non-root Wolfi container"
    )
    assert gw_svc.get("healthcheck"), (
        "gateway service must define a healthcheck for docker compose up -d --wait"
    )


@pytest.mark.parametrize(
    "compose_relpath,service_names",
    [
        ("docker-compose.yml", ("gateway", "app")),
        ("docker-compose.dev.yml", ("gateway",)),
    ],
)
def test_docker_compose_opa_url_is_base_url_without_path(
    compose_relpath: str, service_names: tuple[str, ...]
) -> None:
    """Every compose service setting OPA_URL must pass _opa_endpoint() fail-closed validation."""
    from config.settings import Config
    from src.gateway.core.policy import _opa_endpoint

    compose_path = _REPO_ROOT / compose_relpath
    compose = yaml.safe_load(compose_path.read_text())

    for svc_name in service_names:
        svc = compose["services"][svc_name]
        env_map = _extract_env_dict(svc.get("environment", []))
        opa_url = env_map.get("OPA_URL")
        assert opa_url == "http://opa:8181", (
            f"{compose_relpath} service {svc_name!r} must set OPA_URL=http://opa:8181 "
            f"(base URL without path), got {opa_url!r}"
        )
        with patch.object(Config, "OPA_URL", opa_url):
            base, uds = _opa_endpoint()
            assert base == "http://opa:8181"
            assert uds is None


def test_env_examples_define_valid_opa_base_url_and_token() -> None:
    """Both .env.example and local-dev.env.example must configure base OPA_URL and non-empty OPA_AUTH_TOKEN."""
    for rel in (".env.example", "config/environments/local-dev.env.example"):
        path = _REPO_ROOT / rel
        lines = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        env_map = _extract_env_dict(lines)
        assert env_map.get("OPA_URL") in (
            "http://localhost:8181",
            "http://opa:8181",
        ), f"{rel} has invalid OPA_URL={env_map.get('OPA_URL')!r}"
        assert env_map.get("OPA_AUTH_TOKEN"), (
            f"{rel} must set a non-empty dev default for OPA_AUTH_TOKEN so "
            "docker compose up succeeds with opa --authentication=token"
        )
        assert env_map.get("CAGE_DEPLOYMENT_REGION") in {
            "US_FED",
            "EU_ECB",
            "APAC_MAS",
        }, (
            f"{rel} has unsupported CAGE_DEPLOYMENT_REGION={env_map.get('CAGE_DEPLOYMENT_REGION')!r}"
        )


def test_quickstart_governance_demo_executes_all_acts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Step 4 of docs/QUICKSTART.md (`examples/governance_demo.py --no-pause`) runs cleanly and rejects 2 of 3 racing agents."""
    from examples import governance_demo

    with patch("sys.argv", ["governance_demo.py", "--no-pause"]):
        rc = governance_demo.main()

    assert rc == 0, "examples/governance_demo.py --no-pause returned non-zero exit code"
    out = capsys.readouterr().out
    assert "PASS — exactly one reservation atomically succeeded" in out
    assert "All acts passed — governance-as-code demo complete" in out


def test_quickstart_documents_the_default_health_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Step 3 of docs/QUICKSTART.md shows what /health returns under the compose defaults.

    NeMo rails are opt-in, compose does not set CAGE_NEMO_ENABLED, and with no
    rails built the gateway reports ``"nemo": "off"``. W5 changed that default
    while the document still said "active"; this pins the two together.
    """
    import asyncio
    import json
    import re

    import src.gateway.server.mcp_tool_server as mod
    from src.gateway.governance.feature_flags import nemo_rails_enabled

    compose = yaml.safe_load(
        (_REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )
    gateway_env = compose["services"]["gateway"].get("environment") or []
    assert not any(str(entry).startswith("CAGE_NEMO_ENABLED") for entry in gateway_env)
    monkeypatch.delenv("CAGE_NEMO_ENABLED", raising=False)
    assert not nemo_rails_enabled()

    text = (_REPO_ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
    match = re.search(
        r"curl http://localhost:8080/health\n# Expected: (\{.*?\})\n", text
    )
    assert match is not None, "QUICKSTART no longer documents the /health response"

    monkeypatch.setattr(mod.app.state, "nemo_rails", None, raising=False)
    assert asyncio.run(mod.health_check()) == json.loads(match.group(1))
