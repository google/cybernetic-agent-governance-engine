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
Green-Stack Governance KFP Pipeline.

Defines a Kubeflow Pipelines (KFP v2) pipeline that runs the cybernetic
governance evaluation loop:
  1. Fetch compliance metrics from the compliance-bridge.
  2. Evaluate against ISO 42001 thresholds.
  3. Trigger NeMo refinement if thresholds are breached.
"""

try:
    from kfp import dsl as dsl  # type: ignore[import]

    _KFP_AVAILABLE = True
except ImportError:
    dsl = None  # type: ignore[assignment]
    _KFP_AVAILABLE = False


def _noop_decorator(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Stand-in decorator when kfp is not installed."""

    def wrapper(fn):  # type: ignore[no-untyped-def]
        return fn

    if len(args) == 1 and callable(args[0]):
        return args[0]
    return wrapper


if not _KFP_AVAILABLE:

    class _FakeDsl:  # type: ignore[no-redef]
        component = staticmethod(_noop_decorator)
        pipeline = staticmethod(_noop_decorator)

    dsl = _FakeDsl()  # type: ignore[assignment]


@dsl.component(base_image="python:3.12-slim", packages_to_install=["requests>=2.32.0"])
def fetch_compliance_metrics(
    compliance_bridge_url: str,
    control_id: str,
) -> dict:  # type: ignore[type-arg]
    """Fetch current compliance metrics from the compliance-bridge service."""
    import json
    import urllib.request

    url = f"{compliance_bridge_url}/v1/metrics/{control_id}"
    with urllib.request.urlopen(url, timeout=30) as resp:  # nosec B310
        return json.loads(resp.read())


@dsl.component(base_image="python:3.12-slim")
def evaluate_governance_metrics(
    metrics: dict,  # type: ignore[type-arg]
    safety_threshold: float = 0.95,
) -> str:
    """Evaluate metrics against governance thresholds and return a verdict."""
    safety_rate = metrics.get("safety_rate", 0.0)
    if safety_rate >= safety_threshold:
        return "PASS"
    return f"FAIL: safety_rate={safety_rate:.4f} < threshold={safety_threshold}"


@dsl.component(
    base_image="python:3.12-slim",
    packages_to_install=["requests>=2.32.0"],
)
def trigger_nemo_refinement(
    verdict: str,
    backend_url: str,
    control_id: str = "A.5.2",
) -> str:
    """If the verdict is FAIL, propose a NeMo Guardrails policy refinement.

    CRITICAL CHANGE (Priority 2 — Evidentiary Independence):
      This component previously called POST /v1/nemo/apply-refinement directly,
      which created a recursive self-authentication loop:

        Agent execution → telemetry → KFP → NeMo hot-reload → governs agent

      The system was autonomously modifying its own governance rules based on
      its own telemetry — the textbook definition of "legalizing its own drift."

      Now this component calls POST /v1/nemo/propose-refinement, which STAGES
      the configuration change without applying it.  A human risk officer must
      review and approve the change via POST /v1/nemo/approve-refinement/{id}
      before it takes effect.

    Satisfies:
      - EU AI Act Article 14 (human oversight of high-risk AI systems)
      - ISO 42001 A.7.2 (accountability — human decision record)
      - NIST AI RMF GOVERN-5 (human oversight and intervention)

    Returns:
        "NO_ACTION" if the verdict was PASS.
        "PROPOSAL_STAGED: ..." if a refinement proposal was staged.
        "PROPOSAL_FAILED: ..." if the staging request failed.
    """
    if verdict.startswith("PASS"):
        return "NO_ACTION"

    import json
    import urllib.request

    payload = json.dumps(
        {
            "control_id": control_id,
            "verdict": verdict,
            "source": "kfp-governance-loop",
        }
    ).encode()
    req = urllib.request.Request(
        f"{backend_url.rstrip('/')}/v1/nemo/propose-refinement",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
            body = resp.read().decode()
            return f"PROPOSAL_STAGED: HTTP {resp.status} — {body[:200]}"
    except Exception as exc:
        return f"PROPOSAL_FAILED: {exc}"


@dsl.pipeline(
    name="green-stack-governance-loop",
    description="Cybernetic governance evaluation and refinement loop",
)
def governance_pipeline(
    compliance_bridge_url: str = "http://compliance-bridge/",
    backend_url: str = "http://governed-financial-advisor/",
    control_id: str = "A.5.2",
    safety_threshold: float = 0.95,
) -> None:
    """Top-level KFP pipeline orchestrating the governance loop."""
    fetch_task = fetch_compliance_metrics(
        compliance_bridge_url=compliance_bridge_url,
        control_id=control_id,
    )
    eval_task = evaluate_governance_metrics(
        metrics=fetch_task.output,
        safety_threshold=safety_threshold,
    )
    trigger_nemo_refinement(
        verdict=eval_task.output,
        backend_url=backend_url,
        control_id=control_id,
    )
