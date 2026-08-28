import { describe, expect, it } from "vitest";
import { validateClaims } from "../../src/claims/coverage.js";

const base = {
  sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 1, sha256: "a".repeat(64) }],
  evidence: [
    { evidenceId: "support", sourceId: "policy" },
    { evidenceId: "conflict", sourceId: "audit" },
  ],
  requiredEvidenceFor: ["recommendation"] as const,
};

function claims(disclosed?: boolean) {
  return [{
    claimId: "recommendation",
    sectionId: "answer",
    kind: "recommendation" as const,
    evidence: [
      { evidenceId: "support", role: "supporting" as const, support: "direct" as const },
      { evidenceId: "conflict", role: "contradictory" as const, disclosed },
    ],
  }];
}

describe("hidden contradiction resistance", () => {
  it("routes an undisclosed contradiction to review under review policy", () => {
    expect(validateClaims({ ...base, claims: claims(false), contradictions: "review" })).toContainEqual(expect.objectContaining({ code: "claim.contradiction_undisclosed", severity: "review" }));
  });

  it("blocks an undisclosed contradiction under block policy", () => {
    expect(validateClaims({ ...base, claims: claims(false), contradictions: "block" })).toContainEqual(expect.objectContaining({ code: "claim.contradiction_undisclosed", severity: "blocked" }));
  });

  it("accepts a disclosed contradiction", () => {
    expect(validateClaims({ ...base, claims: claims(true), contradictions: "review" })).toEqual([]);
  });
});
