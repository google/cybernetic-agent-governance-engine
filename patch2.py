import re

with open("src/gateway/governance/symbolic_governor.py", "r") as f:
    content = f.read()

pattern = r'''                if isinstance\(policy_resp, dict\):
                    policy_decision = policy_resp\.get\(
                        "allow", policy_resp\.get\("decision", "DENY"\)
                    \)
                elif isinstance\(policy_resp, str\):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                if policy_decision in \("DENY", "GOVERNANCE_VIOLATION"\):'''

replacement = '''                verdict = decode_opa_verdict(policy_resp)
                if verdict == OpaVerdict.DENY:'''

content = re.sub(pattern, replacement, content)

pattern2 = r'''                elif policy_decision == "MANUAL_REVIEW":
                    _opa_meta = ControlRegistry\(\)\.get_mapping\(
                        GovernanceControl\.OPA_POLICY_ENFORCEMENT
                    \)
                    violations\.append\(Violation\(
                        tier="opa",
                        code="OPA_MANUAL_REVIEW",
                        message=f"\[\{GovernanceControl\.OPA_POLICY_ENFORCEMENT\.value\}\] \{_opa_meta\['primary_framework'\]\} Warning: Manual Review required\.",
                        kind=ViolationKind\.HITL
                    \)\)
                else:
                    pass'''

replacement2 = '''                elif verdict == OpaVerdict.MANUAL_REVIEW:
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(Violation(
                        tier="opa",
                        code="OPA_MANUAL_REVIEW",
                        message=f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] {_opa_meta['primary_framework']} Warning: Manual Review required.",
                        kind=ViolationKind.HITL
                    ))
                elif verdict != OpaVerdict.ALLOW:
                    # Unknown verdicts fail closed
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(Violation(
                        tier="opa",
                        code="OPA_UNKNOWN_VERDICT",
                        message=f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] {_opa_meta['primary_framework']} Error: Unknown OPA decision format.",
                        kind=ViolationKind.HARD
                    ))'''

content = re.sub(pattern2, replacement2, content)

with open("src/gateway/governance/symbolic_governor.py", "w") as f:
    f.write(content)
