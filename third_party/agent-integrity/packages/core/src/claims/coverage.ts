import type {
  ClaimKind,
  EvidenceItem,
  IntegrityClaim,
  IntegrityFinding,
  ResponseSection,
} from "@agent-integrity/protocol";
import { indexEvidence, validateEvidenceLinks } from "./evidence.js";

export interface ClaimValidationInput {
  readonly sections: readonly ResponseSection[];
  readonly claims: readonly IntegrityClaim[];
  readonly evidence: readonly EvidenceItem[];
  readonly requiredEvidenceFor: readonly ClaimKind[];
  readonly contradictions: "review" | "block";
}

function assertIdentifier(value: string, path: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${path} must be a non-empty string`);
  }
}

export function validateClaims(input: ClaimValidationInput): readonly IntegrityFinding[] {
  const findings: IntegrityFinding[] = [];
  const sections = new Map<string, ResponseSection>();
  for (const [index, section] of input.sections.entries()) {
    assertIdentifier(section.sectionId, `sections[${index}].sectionId`);
    if (sections.has(section.sectionId)) throw new Error(`duplicate section ID: ${section.sectionId}`);
    sections.set(section.sectionId, section);
  }

  const evidence = indexEvidence(input.evidence);
  const claimIds = new Set<string>();
  const coveredSections = new Set<string>();
  for (const [index, claim] of input.claims.entries()) {
    assertIdentifier(claim.claimId, `claims[${index}].claimId`);
    assertIdentifier(claim.sectionId, `claims[${index}].sectionId`);
    if (claimIds.has(claim.claimId)) throw new Error(`duplicate claim ID: ${claim.claimId}`);
    claimIds.add(claim.claimId);
    if (!sections.has(claim.sectionId)) {
      throw new Error(`claims[${index}] references unknown section: ${claim.sectionId}`);
    }
    if (!("factual recommendation inference".split(" ") as string[]).includes(claim.kind)) {
      throw new Error(`claims[${index}].kind is invalid`);
    }
    coveredSections.add(claim.sectionId);
    validateEvidenceLinks(claim, index, evidence);
    findings.push(...claimEvidenceFindings(claim, index, input));
  }

  for (const [index, section] of input.sections.entries()) {
    if (!coveredSections.has(section.sectionId)) {
      findings.push({
        code: "claim.section_uncovered",
        severity: "blocked",
        message: `Section ${section.sectionId} has no registered claim`,
        path: `sections[${index}]`,
      });
    }
  }
  return findings;
}

function claimEvidenceFindings(
  claim: IntegrityClaim,
  index: number,
  input: ClaimValidationInput,
): IntegrityFinding[] {
  const findings: IntegrityFinding[] = [];
  const supporting = claim.evidence.filter((link) => link.role === "supporting");
  if (input.requiredEvidenceFor.includes(claim.kind)) {
    if (supporting.length === 0) {
      findings.push({
        code: "claim.support_missing",
        severity: "blocked",
        message: `Claim ${claim.claimId} requires supporting evidence`,
        path: `claims[${index}]`,
      });
    } else if (!supporting.some((link) => (link.support ?? "direct") === "direct")) {
      findings.push({
        code: "claim.support_ambiguous",
        severity: "review",
        message: `Claim ${claim.claimId} has only ambiguous supporting evidence`,
        path: `claims[${index}].evidence`,
      });
    }
  }

  for (const [linkIndex, link] of claim.evidence.entries()) {
    if (link.role === "contradictory" && link.disclosed !== true) {
      findings.push({
        code: "claim.contradiction_undisclosed",
        severity: input.contradictions === "block" ? "blocked" : "review",
        message: `Claim ${claim.claimId} has contradictory evidence that is not disclosed`,
        path: `claims[${index}].evidence[${linkIndex}]`,
      });
    }
  }
  return findings;
}
