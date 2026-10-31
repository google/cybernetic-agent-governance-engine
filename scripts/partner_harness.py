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

"""The partner over-the-wire harness: what each partner runs and receives.

`.github/workflows/ci-partner-integration.yml` runs one job per partner against
the partner's live sandbox (AGENTS.md, Tier 1). This module is the single
source for four things the workflow depends on:

* the partner list and each partner's pytest target;
* the secrets each partner's job receives;
* the credentials a job mints during the run instead of storing;
* the variables its live tests read that the workflow deliberately leaves out.

The harness itself runs only on dispatch and on a weekly schedule, so drift
between it and the live tests would otherwise surface weeks late, if at all.
`tests/test_partner_harness.py` checks the workflow and the live tests against
this module on every pull request.

Standard library only, so the workflow can run it before installing anything::

    python3 scripts/partner_harness.py matrix all|<partner>
    python3 scripts/partner_harness.py target <partner>
"""

from __future__ import annotations

import json
import sys

#: Partner -> pytest target. The workflow's dispatch choices list exactly these.
PARTNER_TARGETS: dict[str, str] = {
    "provider_01": "tests/integrations/provider_01",
    "provider_02": "tests/integrations/provider_02",
    "provider_03": "tests/integrations/provider_03",
    "provider_05": "tests/integrations/provider_05",
    "provider_07": "tests/integrations/provider_07",
    "provider_08": "tests/integrations/provider_08",
    "actuator_01": "tests/test_actuator_01_live.py",
}

#: Partner -> variables its job receives, each from the repository secret of the
#: same name. A secret reaches only its own partner's job.
PARTNER_SECRETS: dict[str, tuple[str, ...]] = {
    "provider_01": ("PROVIDER_01_ENDPOINT", "PROVIDER_01_API_KEY"),
    "provider_02": (
        "PROVIDER_02_API_ENDPOINT",
        "PROVIDER_02_JWK_ENDPOINT",
        "PROVIDER_02_API_KEY_SECRET",
        "PROVIDER_02_TEST_CERT_HASH",
    ),
    "provider_03": ("PROVIDER_03_ENDPOINT", "PROVIDER_03_API_KEY"),
    "provider_05": ("PROVIDER_05_ATTESTATION_ENDPOINT",),
    "provider_07": (
        "PROVIDER_07_ENDPOINT",
        "PROVIDER_07_API_KEY",
        "PROVIDER_07_JWKS_URL",
        "PROVIDER_07_EXPECTED_KID",
    ),
    "provider_08": ("PROVIDER_08_ENDPOINT", "PROVIDER_08_API_KEY"),
    "actuator_01": (
        "ACTUATOR_01_ENDPOINT",
        "ACTUATOR_01_TENANT_ID",
        "ACTUATOR_01_RECEIPT_KEY_MANIFEST_URL",
        "CAGE_OPERATOR_URNS",
    ),
}

#: actuator_01's mTLS material: the secret holding each PEM -> the path variable
#: the adapter reads. The workflow writes a PEM to a file only when its secret
#: is set, so a missing secret leaves the path unset and the test names it.
STAGED_FILES: dict[str, str] = {
    "ACTUATOR_01_CLIENT_CERT": "ACTUATOR_01_CERT_PATH",
    "ACTUATOR_01_CLIENT_KEY": "ACTUATOR_01_KEY_PATH",
    "ACTUATOR_01_CA_CERT": "ACTUATOR_01_CA_PATH",
}

#: actuator_01's Workload Identity Federation + Cloud KMS signing configuration
#: (GitHub Actions repository variable names). Leaves no long-lived Ed25519
#: private keys in repository secrets and no maintainer project IDs in source:
#: the job authenticates via GitHub OIDC and signs with the Ed25519 KMS key.
ACTUATOR_01_GCP_AUTH: dict[str, str] = {
    "workload_identity_provider": "ACTUATOR_01_WIF_PROVIDER",
    "service_account": "ACTUATOR_01_WIF_SERVICE_ACCOUNT",
    "kms_governance_key": "ACTUATOR_01_KMS_KEY",
}

#: provider_01's Cloud Run ingress (Domain Restricted Sharing) requires a Google
#: ID token next to the FlowSignal key. An ID token expires within the hour, so
#: the job mints one per run through Workload Identity Federation instead of
#: storing it. FlowSignal grants run.invoker to one CAGE service account, the
#: invoker. The federated principal reaches it through the delegate, which holds
#: Token Creator on the invoker. Values are GitHub Actions repository variable
#: names, so no project ID appears in source.
PROVIDER_01_GCP_AUTH: dict[str, str] = {
    "workload_identity_provider": "PROVIDER_01_WIF_PROVIDER",
    "delegates": "PROVIDER_01_WIF_DELEGATE",
    "service_account": "PROVIDER_01_INVOKER_SERVICE_ACCOUNT",
}

#: Variables a job mints during the run instead of reading a secret.
MINTED: dict[str, str] = {
    "PROVIDER_01_GCP_ID_TOKEN": (
        "Google ID token for FlowSignal's Cloud Run ingress, audience "
        "PROVIDER_01_ENDPOINT, minted per run with PROVIDER_01_GCP_AUTH."
    ),
}

_EMPTY_REPLACES_DEFAULT = (
    "Test parameter with a default. GitHub sets a missing secret to an empty "
    "string, which would replace the default."
)

#: Variables a partner's live tests read that the workflow does not supply.
UNSUPPLIED: dict[str, str] = {
    "PROVIDER_03_TEST_REGION": _EMPTY_REPLACES_DEFAULT,
    "ACTUATOR_01_SIGNING_KEYS_DIR": (
        "Local Ed25519 private key directory. Left unset in CI so "
        "Actuator01Adapter.from_env() signs via Cloud KMS (KMS_GOVERNANCE_KEY) "
        "using Workload Identity Federation."
    ),
}


def matrix(selection: str) -> list[str]:
    """Partners one run covers: all of them for ``all`` or empty (the schedule)."""
    if selection in ("", "all"):
        return list(PARTNER_TARGETS)
    if selection in PARTNER_TARGETS:
        return [selection]
    raise ValueError(
        f"unknown partner {selection!r}; expected 'all' or one of: "
        + ", ".join(PARTNER_TARGETS)
    )


def main(argv: list[str]) -> int:
    """Print the matrix (JSON) or one partner's pytest target."""
    if len(argv) == 2 and argv[0] in ("matrix", "target"):
        command, selection = argv
        try:
            partners = matrix(selection)
        except ValueError as exc:
            print(f"partner_harness: {exc}", file=sys.stderr)
            return 2
        if command == "matrix":
            print(json.dumps(partners))
            return 0
        if selection in PARTNER_TARGETS:
            print(PARTNER_TARGETS[selection])
            return 0
    print(
        "usage: partner_harness.py matrix all|<partner>\n"
        "       partner_harness.py target <partner>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
