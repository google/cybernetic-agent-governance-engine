import { PROTOCOL_VERSION, type IntegrityFinding, type IntegrityResult } from "@agent-integrity/protocol";

export function calculateOutcome(findings: readonly IntegrityFinding[]): IntegrityResult {
  const status = findings.some((finding) => finding.severity === "blocked")
    ? "BLOCKED"
    : findings.some((finding) => finding.severity === "review")
      ? "REVIEW"
      : "PASS";

  return { protocolVersion: PROTOCOL_VERSION, status, findings: [...findings] };
}

export function checkerFailure(error: unknown): IntegrityResult {
  const detail = error instanceof Error ? error.message : "Unknown checker failure";
  return calculateOutcome([
    {
      code: "checker.failure",
      severity: "blocked",
      message: `Integrity checker failed closed: ${detail}`
    }
  ]);
}
