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

    python3 scripts/partner_harness.py matrix provisioned|all|<partner>
    python3 scripts/partner_harness.py target <partner>
    python3 scripts/partner_harness.py disclosure provisioned|all|<partner>
    python3 scripts/partner_harness.py verdict provisioned|all|<partner>
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

#: Partners with active live sandboxes and credentials provisioned in GitHub
#: Actions. The weekly Monday schedule runs these failing closed.
PROVISIONED_PARTNERS: tuple[str, ...] = (
    "provider_01",
    "provider_05",
    "provider_08",
)

#: Exact complement ``set(PARTNER_TARGETS) - set(PROVISIONED_PARTNERS)``,
#: mapped to the blocker keeping each partner out of the weekly schedule.
UNPROVISIONED_PARTNER_REASONS: dict[str, str] = {
    "provider_02": (
        "Missing GitHub Actions sandbox secrets (PROVIDER_02_API_ENDPOINT, "
        "PROVIDER_02_JWK_ENDPOINT, PROVIDER_02_API_KEY_SECRET, "
        "PROVIDER_02_TEST_CERT_HASH) and open CER signature verification defect."
    ),
    "provider_03": (
        "No live partner sandbox endpoint or API key provisioned in GitHub "
        "Actions secrets (PROVIDER_03_ENDPOINT, PROVIDER_03_API_KEY)."
    ),
    "provider_07": (
        "Missing valid PROVIDER_07_API_KEY and sandbox secrets "
        "(PROVIDER_07_ENDPOINT, PROVIDER_07_JWKS_URL, PROVIDER_07_EXPECTED_KID) "
        "in GitHub Actions."
    ),
    "actuator_01": (
        "Missing sandbox endpoint and mTLS secrets in GitHub Actions "
        "(ACTUATOR_01_ENDPOINT, ACTUATOR_01_TENANT_ID, ACTUATOR_01_CLIENT_CERT, "
        "ACTUATOR_01_CLIENT_KEY, ACTUATOR_01_CA_CERT)."
    ),
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
        "Google ID token for provider_01 Cloud Run ingress, audience "
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


def validate_partner_partition() -> None:
    """Ensure PROVISIONED_PARTNERS and UNPROVISIONED_PARTNER_REASONS partition PARTNER_TARGETS."""
    provisioned = set(PROVISIONED_PARTNERS)
    unprovisioned = set(UNPROVISIONED_PARTNER_REASONS)
    targets = set(PARTNER_TARGETS)
    if len(PROVISIONED_PARTNERS) != len(provisioned):
        raise RuntimeError("PROVISIONED_PARTNERS contains duplicate entries")
    overlap = sorted(provisioned & unprovisioned)
    if overlap:
        raise RuntimeError(
            "partners listed in both PROVISIONED_PARTNERS and "
            f"UNPROVISIONED_PARTNER_REASONS: {overlap}"
        )
    if provisioned | unprovisioned != targets:
        missing = sorted(targets - (provisioned | unprovisioned))
        unknown = sorted((provisioned | unprovisioned) - targets)
        raise RuntimeError(
            "PROVISIONED_PARTNERS and UNPROVISIONED_PARTNER_REASONS must partition "
            f"PARTNER_TARGETS (missing={missing}, unknown={unknown})"
        )
    empty = sorted(
        partner
        for partner, reason in UNPROVISIONED_PARTNER_REASONS.items()
        if not reason or not reason.strip()
    )
    if empty:
        raise RuntimeError(
            f"UNPROVISIONED_PARTNER_REASONS has blank reason for: {empty}"
        )


def matrix(selection: str) -> list[str]:
    """Partners one run covers: provisioned for schedule/default, all 7 for ``all``."""
    validate_partner_partition()
    if selection in ("", "provisioned"):
        return list(PROVISIONED_PARTNERS)
    if selection == "all":
        return list(PARTNER_TARGETS)
    if selection in PARTNER_TARGETS:
        return [selection]
    raise ValueError(
        f"unknown partner {selection!r}; expected 'provisioned', 'all', or one of: "
        + ", ".join(PARTNER_TARGETS)
    )


def disclosure(selection: str) -> str:
    """Render scope header, selected partners, and NOT RUN partners with blockers."""
    selected = matrix(selection)
    mode = "provisioned" if selection == "" else selection
    total = len(PARTNER_TARGETS)
    selected_set = set(selected)
    omitted = [partner for partner in PARTNER_TARGETS if partner not in selected_set]

    omitted_summary = ", ".join(omitted) if omitted else "none"
    lines = [
        f"### Partner Harness Scope: {len(selected)} of {total} partners selected (mode: {mode})",
        "",
        f"SELECTED ({len(selected)} of {total}): {', '.join(selected)}",
        f"NOT RUN ({len(omitted)} of {total}): {omitted_summary}",
        "",
        f"#### Selected / Run ({len(selected)} of {total})",
        "",
        "| Partner | Status | Pytest Target | Notes |",
        "| --- | --- | --- | --- |",
    ]
    for partner in selected:
        target = PARTNER_TARGETS[partner]
        if partner in UNPROVISIONED_PARTNER_REASONS:
            note = f"Unprovisioned sandbox: {UNPROVISIONED_PARTNER_REASONS[partner]}"
        else:
            note = "Provisioned live sandbox"
        lines.append(f"| `{partner}` | SELECTED | `{target}` | {note} |")

    lines.extend(["", f"#### Not Run ({len(omitted)} of {total})", ""])
    if not omitted:
        lines.append(
            f"None — all {total} of {total} partners in PARTNER_TARGETS were selected."
        )
    else:
        lines.extend(
            [
                "| Partner | Status | Pytest Target | Reason |",
                "| --- | --- | --- | --- |",
            ]
        )
        for partner in omitted:
            target = PARTNER_TARGETS[partner]
            if partner in UNPROVISIONED_PARTNER_REASONS:
                reason = UNPROVISIONED_PARTNER_REASONS[partner]
                if mode != "provisioned":
                    reason = f"Excluded from selection ({mode}); {reason}"
            else:
                reason = (
                    f"Excluded from single-partner selection ({mode}); "
                    "live sandbox is provisioned."
                )
            lines.append(f"| `{partner}` | NOT RUN | `{target}` | {reason} |")
    return "\n".join(lines)


def verdict_summary(selection: str) -> str:
    """Return the fail-closed pass summary naming exact verified and NOT RUN counts."""
    selected = matrix(selection)
    mode = "provisioned" if selection == "" else selection
    total = len(PARTNER_TARGETS)
    not_run_count = total - len(selected)
    if mode == "provisioned":
        return (
            f"PASSED: {len(selected)} of {total} partners verified over the wire; "
            f"{not_run_count} of {total} NOT RUN (unprovisioned)"
        )
    if mode == "all":
        return (
            f"PASSED: {len(selected)} of {total} partners verified over the wire; "
            f"0 of {total} NOT RUN"
        )
    return (
        f"PASSED: {len(selected)} of {total} partners ({selected[0]}) verified over "
        f"the wire; {not_run_count} of {total} NOT RUN (excluded from selection)"
    )


def main(argv: list[str]) -> int:
    """Print the matrix (JSON), pytest target, scope disclosure, or pass verdict."""
    if len(argv) == 2 and argv[0] in ("matrix", "target", "disclosure", "verdict"):
        command, selection = argv
        try:
            if command == "matrix":
                print(json.dumps(matrix(selection)))
                return 0
            if command == "disclosure":
                print(disclosure(selection))
                return 0
            if command == "verdict":
                print(verdict_summary(selection))
                return 0
            matrix(selection)
        except ValueError as exc:
            print(f"partner_harness: {exc}", file=sys.stderr)
            return 2
        if selection in PARTNER_TARGETS:
            print(PARTNER_TARGETS[selection])
            return 0
    print(
        "usage: partner_harness.py matrix provisioned|all|<partner>\n"
        "       partner_harness.py target <partner>\n"
        "       partner_harness.py disclosure provisioned|all|<partner>\n"
        "       partner_harness.py verdict provisioned|all|<partner>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
