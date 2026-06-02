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
Evaluator Auditor — System 3 (Algedonic) governance component.

Audits agent execution traces against STAMP/STPA safety constraints and
ISO 42001 governance requirements, producing structured audit verdicts.

SC-1 enforcement delegates to STPAValidator (single source of truth) when
available; falls back to inline check if STPAValidator cannot be imported.
"""

import os
import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger("EvaluatorAuditor")

# ---------------------------------------------------------------------------
# STPAValidator — lazy import to avoid circular / heavyweight dependencies.
# R-09: SC-1 check delegates to STPAValidator to maintain a single source
# of truth. Falls back to inline check if the import fails.
# ---------------------------------------------------------------------------
try:
    from src.gateway.governance.stpa_validator import STPAValidator
    _stpa_validator = STPAValidator()
    _USE_STPA = True
except ImportError:
    _USE_STPA = False

# Actions that require an approval_token (SC-1 constraint) — used for the
# inline fallback when STPAValidator is unavailable.
_WRITE_ACTIONS = {"write_db", "delete_db"}

# Actions considered safety-critical for quality scoring
_SAFETY_CRITICAL_ACTIONS = {"execute_trade", "write_db", "delete_db", "submit_order"}

# Governance best-practice actions that raise quality score
_GOVERNANCE_ACTIONS = {
    "wait_for_approval",
    "request_approval",
    "risk_assessment",
    "market_analysis",
    "compliance_check",
}


class EvaluatorAuditor:
    """
    Audits an agent execution trace (plan + history) against governance policies.

    audit_trace() returns a dict with:
      - verdict: "PASS" | "FAIL"
      - safety_score: float 0–100
      - quality_score: float 0–1
      - violations: list of violation message strings
    """

    def __init__(self) -> None:
        self._compliance_tracer = None
        self._initialized = False

    def _init_compliance_telemetry(self) -> None:
        """
        Lazily initializes the secondary OpenTelemetry TracerProvider 
        only if explicit compliance keys are present in the environment.
        """
        if self._initialized:
            return

        public_key = os.environ.get("LANGFUSE_COMPLIANCE_PUBLIC_KEY")
        secret_key = os.environ.get("LANGFUSE_COMPLIANCE_SECRET_KEY")
        host = os.environ.get("LANGFUSE_COMPLIANCE_HOST", "https://cloud.langfuse.com")

        if public_key and secret_key:
            try:
                # Lazy-load OpenTelemetry SDK components to prevent overhead/exceptions
                from opentelemetry.sdk.trace import TracerProvider
                from opentelemetry.sdk.trace.export import BatchSpanProcessor
                from opentelemetry.sdk.resources import Resource
                from opentelemetry.sdk.trace.sampling import ALWAYS_ON
                import base64

                # Standard OTel Http Span Exporter package
                try:
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHttpSpanExporter
                except ImportError:
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPHttpSpanExporter

                logger.info("Initializing dedicated CAGE Compliance TracerProvider (100% Sampling)...")
                
                # Build isolated OTLP endpoint auth header mapping Langfuse OTel specs
                credentials = f"{public_key}:{secret_key}".encode("utf-8")
                auth_header = f"Basic {base64.b64encode(credentials).decode('utf-8')}"
                
                resource = Resource.create(attributes={
                    "service.name": "cage-compliance-audit",
                    "service.environment": os.environ.get("CAGE_ENV", "production")
                })

                # Force OTLP endpoint to native compliance collection paths
                endpoint = f"{host.rstrip('/')}/api/public/otel"
                exporter = OTLPHttpSpanExporter(
                    endpoint=endpoint,
                    headers={"Authorization": auth_header},
                    timeout=5 # Strict 5s timeout
                )

                provider = TracerProvider(resource=resource, sampler=ALWAYS_ON)
                provider.add_span_processor(BatchSpanProcessor(exporter))
                self._compliance_tracer = provider.get_tracer("CAGE.EvaluatorAuditor.Compliance")
                logger.info("✅ EvaluatorAuditor: Compliance tracer initialized successfully.")
                
            except Exception as e:
                logger.error(f"POAM-003 Failure: Failed to initialize compliance OTel provider: {str(e)}. Falling back to default.")
                self._compliance_tracer = None
        else:
            # Clean fallback to default global provider for local/test environments
            try:
                import opentelemetry.trace as trace_api
                self._compliance_tracer = trace_api.get_tracer("CAGE.EvaluatorAuditor.Default")
            except Exception:
                logger.warning("OpenTelemetry API not present. Compliance tracing will execute via standard logging.")
                self._compliance_tracer = None

        self._initialized = True

    def audit_trace(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an agent trace and return an audit result dict.

        Args:
            trace: {
                "plan": {"steps": [{"action": str, "parameters": dict}, ...]},
                "history": [{"role": str, "content": str}, ...]
            }

        Returns:
            {
                "verdict": "PASS" | "FAIL",
                "safety_score": float,   # 0–100
                "quality_score": float,  # 0–1
                "violations": list[str]
            }
        """
        self._init_compliance_telemetry()

        steps: List[Dict[str, Any]] = trace.get("plan", {}).get("steps", [])
        violations: List[str] = []
        safety_deductions = 0.0
        governance_bonus = 0.0

        for step in steps:
            action = step.get("action", "")
            params = step.get("parameters", {})

            # SC-1: Check for unauthorized control actions.
            # R-09: Delegate to STPAValidator for single-source-of-truth SC-1 logic.
            if action in _WRITE_ACTIONS:
                if _USE_STPA:
                    # STPAValidator.validate() returns list[str] of violation messages.
                    # Filter for SC-1 violations specifically.
                    stpa_violations = _stpa_validator.validate(action, params)
                    sc1_hits = [v for v in stpa_violations if "SC-1" in v]
                    if sc1_hits:
                        msg = f"SC-1: Unauthorized control action (via STPAValidator) for '{action}'"
                        violations.append(msg)
                        safety_deductions += 30.0
                        logger.warning(msg)
                    elif not params.get("approval_token"):
                        # STPAValidator may not have SC-1 constraints registered for
                        # every write action — use inline fallback as safety net.
                        msg = (
                            f"SC-1 Violation: '{action}' executed without approval_token. "
                            "Write operations require a signed approval token."
                        )
                        violations.append(msg)
                        safety_deductions += 30.0
                        logger.warning(msg)
                else:
                    # Fallback: inline SC-1 check (STPAValidator unavailable)
                    if not params.get("approval_token"):
                        msg = (
                            f"SC-1 Violation: '{action}' executed without approval_token. "
                            "Write operations require a signed approval token."
                        )
                        violations.append(msg)
                        safety_deductions += 30.0
                        logger.warning(msg)

            # Governance quality: reward safe sequencing behaviours
            if action in _GOVERNANCE_ACTIONS:
                governance_bonus += 0.15

        safety_score = max(0.0, 100.0 - safety_deductions)
        # Base quality: 0.6 + bonus for governance-aware steps, capped at 1.0
        quality_score = min(1.0, 0.6 + governance_bonus)

        verdict = "FAIL" if violations else "PASS"

        result = {
            "verdict": verdict,
            "safety_score": safety_score,
            "quality_score": quality_score,
            "violations": violations,
        }

        # Structure secure, audit-safe metadata envelope (No PII or raw transaction parameters)
        sanitized_metadata = {
            "verdict": verdict,
            "safety_score": safety_score,
            "quality_score": quality_score,
            "violations_count": len(violations),
            "policy_rules_evaluated": [step.get("action", "") for step in steps],
            "cage_version": "2.0.0"
        }

        # Handle path where OpenTelemetry is not available or initialized
        if self._compliance_tracer is None:
            logger.info(
                "Audit complete: [LOG-ONLY AUDIT] Control: A.5.3 | Verdict: %s | Metadata: %s",
                verdict,
                json.dumps(sanitized_metadata),
            )
        else:
            try:
                # Execute genuine OpenTelemetry Span injection
                with self._compliance_tracer.start_as_current_span("evaluator_auditor.audit_trace") as span:
                    span.set_attribute("iso42001.standard", "ISO/IEC 42001:2023")
                    span.set_attribute("iso42001.control_id", "A.5.3")
                    span.set_attribute("iso42001.outcome", "PASSED" if verdict == "PASS" else "BLOCKED")
                    span.set_attribute("iso42001.metadata", json.dumps(sanitized_metadata))
                    
                    # Inject standardized tags format for Langfuse indexing
                    span.set_attribute("langfuse.trace.tags", json.dumps([
                        "iso-42001", 
                        "control:A.5.3", 
                        f"verdict:{verdict}"
                    ]))

                    # Emit structured Span Event matching continuous verification requirements
                    passed_flag = "1" if verdict == "PASS" else "0"
                    score_value = "1.0" if verdict == "PASS" else "0.0"
                    
                    span.add_event("compliance.score", {
                        "compliance.control_id": "A.5.3",
                        "compliance.passed": passed_flag,
                        "compliance.score": score_value,
                        "compliance.comment": f"Automated structural runtime verification assertion: {verdict}"
                    })

                    logger.info("Compliance attestation trace emitted for control A.5.3 with outcome: %s", verdict)
            except Exception as exc:
                logger.error("Failed to emit compliance attestation trace: %s", exc)

        logger.info(
            "Audit complete: verdict=%s safety=%.1f quality=%.2f violations=%d",
            verdict,
            safety_score,
            quality_score,
            len(violations),
        )
        return result


# Module-level singleton used by tests and other modules
evaluator_auditor = EvaluatorAuditor()
