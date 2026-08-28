import { describe, expect, it } from "vitest";
import type { EvidenceItem, IntegrityClaim, ResponseSection } from "@agent-integrity/protocol";
import { validateClaims } from "../../src/claims/coverage.js";

const sections: ResponseSection[] = [
  { sectionId: "summary", substantive: true, byteStart: 0, byteEnd: 1, sha256: "a".repeat(64) },
];
const evidence: EvidenceItem[] = [{ evidenceId: "ev-1", sourceId: "source-1" }];

function claim(overrides: Partial<IntegrityClaim> = {}): IntegrityClaim {
  return {
    claimId: "claim-1",
    sectionId: "summary",
    kind: "factual",
    evidence: [{ evidenceId: "ev-1", role: "supporting", support: "direct" }],
    ...overrides,
  };
}

describe("claim coverage and evidence roles", () => {
  it("passes complete claims with direct supporting evidence", () => {
    expect(validateClaims({ sections, claims: [claim()], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toEqual([]);
  });

  it("blocks an uncovered substantive section", () => {
    expect(validateClaims({ sections, claims: [], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toContainEqual(expect.objectContaining({ code: "claim.section_uncovered", severity: "blocked", path: "sections[0]" }));
  });

  it("requires claims for non-substantive sections under the alpha security profile", () => {
    expect(validateClaims({ sections: [{ sectionId: "footer", substantive: false, byteStart: 0, byteEnd: 1, sha256: "a".repeat(64) }], claims: [], evidence: [], requiredEvidenceFor: ["factual"], contradictions: "review" })).toContainEqual(expect.objectContaining({ code: "claim.section_uncovered", severity: "blocked" }));
  });

  it("blocks required claims with no evidence or contextual-only evidence", () => {
    for (const links of [[], [{ evidenceId: "ev-1", role: "contextual" as const }]]) {
      expect(validateClaims({ sections, claims: [claim({ evidence: links })], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toContainEqual(expect.objectContaining({ code: "claim.support_missing", severity: "blocked" }));
    }
  });

  it("routes ambiguous support to review instead of blocking", () => {
    const findings = validateClaims({ sections, claims: [claim({ evidence: [{ evidenceId: "ev-1", role: "supporting", support: "ambiguous" }] })], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" });
    expect(findings).toEqual([expect.objectContaining({ code: "claim.support_ambiguous", severity: "review" })]);
  });

  it("rejects dangling evidence references and invalid role metadata", () => {
    expect(() => validateClaims({ sections, claims: [claim({ evidence: [{ evidenceId: "missing", role: "supporting", support: "direct" }] })], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toThrow(/unknown evidence/);
    expect(() => validateClaims({ sections, claims: [claim({ evidence: [{ evidenceId: "ev-1", role: "contextual", support: "direct" }] })], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toThrow(/support is only valid/);
  });

  it("rejects duplicate identifiers and duplicate evidence links", () => {
    expect(() => validateClaims({ sections: [...sections, sections[0]!], claims: [claim()], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toThrow(/duplicate section ID/);
    expect(() => validateClaims({ sections, claims: [claim(), claim()], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toThrow(/duplicate claim ID/);
    expect(() => validateClaims({ sections, claims: [claim()], evidence: [...evidence, evidence[0]!], requiredEvidenceFor: ["factual"], contradictions: "review" })).toThrow(/duplicate evidence ID/);
    expect(() => validateClaims({ sections, claims: [claim({ evidence: [{ evidenceId: "ev-1", role: "supporting" }, { evidenceId: "ev-1", role: "contextual" }] })], evidence, requiredEvidenceFor: ["factual"], contradictions: "review" })).toThrow(/duplicate evidence link/);
  });
});
