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

"""Deployment-region resolution for the test session.

Two run modes, one rule each:

* **Hermetic runs** (no ``--run-integration`` / ``--run-e2e``): the session
  region is pinned to :data:`HERMETIC_DEFAULT_REGION`, whatever the shell or
  ``.env`` says. A test marked ``us_fed`` / ``eu_ecb`` / ``apac_mas`` is
  executed *under* that region (see :func:`region_pin`), so every region's
  tests run in a single job.
* **Live runs** (``--run-integration`` or ``--run-e2e``): the session region is
  the one the CAGE deployment is configured with, read from the
  ``cage-deployment`` ConfigMap (the single source of
  ``CAGE_DEPLOYMENT_REGION`` for every workload). A conflicting
  ``CAGE_DEPLOYMENT_REGION`` in the environment fails the session; a
  live test marked for another region is skipped (see
  :func:`live_region_mismatch`).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

REGION_ENV_VAR = "CAGE_DEPLOYMENT_REGION"
DEPLOYMENT_CONFIG_MAP = "cage-deployment"
DEFAULT_NAMESPACE = "governance-stack"
HERMETIC_DEFAULT_REGION = "US_FED"

#: Facet marker -> region it selects (pytest.ini declares the markers).
REGION_MARKERS: dict[str, str] = {
    "us_fed": "US_FED",
    "eu_ecb": "EU_ECB",
    "apac_mas": "APAC_MAS",
}

#: Selection markers whose tests exercise the deployed stack.
LIVE_MARKERS: frozenset[str] = frozenset({"integration", "e2e"})

_KUBECTL_TIMEOUT_S = 15


class DeploymentRegionError(RuntimeError):
    """The deployed region cannot be determined or contradicts the environment."""


def is_live_run(config: pytest.Config) -> bool:
    """True when the session targets a deployed stack."""
    return bool(
        config.getoption("--run-integration", default=False)
        or config.getoption("--run-e2e", default=False)
    )


def discover_deployed_region(namespace: str) -> str:
    """Read ``CAGE_DEPLOYMENT_REGION`` from the deployment's ConfigMap.

    Raises:
        DeploymentRegionError: kubectl is missing, the read fails, or the
            value is not a region the kernel has a jurisdiction for.
    """
    from src.gateway.governance.jurisdiction.registry import JURISDICTIONS

    kubectl = shutil.which("kubectl")
    if kubectl is None:
        raise DeploymentRegionError(
            "kubectl not found on PATH; cannot read the deployed region from "
            f"ConfigMap {namespace}/{DEPLOYMENT_CONFIG_MAP}."
        )
    jsonpath = "{.data." + REGION_ENV_VAR + "}"
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                kubectl,
                "get",
                "configmap",
                DEPLOYMENT_CONFIG_MAP,
                "--namespace",
                namespace,
                "--output",
                f"jsonpath={jsonpath}",
            ],
            capture_output=True,
            text=True,
            timeout=_KUBECTL_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DeploymentRegionError(
            f"kubectl timed out reading ConfigMap {namespace}/{DEPLOYMENT_CONFIG_MAP}."
        ) from exc
    if result.returncode != 0:
        raise DeploymentRegionError(
            f"kubectl could not read ConfigMap {namespace}/{DEPLOYMENT_CONFIG_MAP}: "
            f"{result.stderr.strip()}"
        )
    region = result.stdout.strip().upper()
    if region not in JURISDICTIONS:
        raise DeploymentRegionError(
            f"ConfigMap {namespace}/{DEPLOYMENT_CONFIG_MAP} has "
            f"{REGION_ENV_VAR}={region!r}; expected one of {sorted(JURISDICTIONS)}."
        )
    return region


def resolve_session_region(
    *, live: bool, namespace: str, env_region: str | None
) -> str:
    """Return the region the whole test session runs under.

    Raises:
        DeploymentRegionError: live run whose deployed region cannot be read
            or differs from an explicitly exported ``CAGE_DEPLOYMENT_REGION``.
    """
    if not live:
        return HERMETIC_DEFAULT_REGION
    deployed = discover_deployed_region(namespace)
    requested = (env_region or "").strip().upper()
    if requested and requested != deployed:
        raise DeploymentRegionError(
            f"{REGION_ENV_VAR}={requested} is exported, but the deployment in "
            f"namespace {namespace!r} is configured for {deployed}. Unset it or "
            "point kubectl at the matching cluster."
        )
    return deployed


def marked_region(item: pytest.Item) -> str | None:
    """Region selected by the item's region facet marker, if any.

    Raises:
        pytest.UsageError: the item carries more than one region marker.
    """
    regions = {
        region for marker, region in REGION_MARKERS.items() if marker in item.keywords
    }
    if len(regions) > 1:
        raise pytest.UsageError(
            f"{item.nodeid} carries several region markers ({sorted(regions)}); "
            "a test runs under exactly one region. Use the `each_region` "
            "fixture for cross-region invariants."
        )
    return regions.pop() if regions else None


def is_live_test(item: pytest.Item) -> bool:
    """True when the item exercises the deployed stack."""
    return bool(LIVE_MARKERS & set(item.keywords))


def live_region_mismatch(item: pytest.Item, session_region: str) -> str | None:
    """Skip reason for a live test marked for a region other than the deployed one."""
    if not is_live_test(item):
        return None
    region = marked_region(item)
    if region is None or region == session_region:
        return None
    return (
        f"{region}-only live test; the deployment under test is configured for "
        f"{session_region} (ConfigMap {DEPLOYMENT_CONFIG_MAP})."
    )


def region_pin(item: pytest.Item) -> str | None:
    """Region a hermetic test must run under (``None``: session default).

    Live tests never get a pin: they run under the deployed region and are
    filtered at collection by :func:`live_region_mismatch`.
    """
    if is_live_test(item):
        return None
    return marked_region(item)
