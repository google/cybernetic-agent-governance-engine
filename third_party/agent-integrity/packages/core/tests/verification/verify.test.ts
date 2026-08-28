import { describe, expect, it } from "vitest";
import { PROTOCOL_VERSION, type IntegrityEnvelope } from "@agent-integrity/protocol";
import { verifyEnvelope } from "../../src/verify.js";

function envelope(): IntegrityEnvelope {
  return {
    protocolVersion: PROTOCOL_VERSION,
    policy: {
      version: 1,
      sources: { allowedRoots: ["docs"] },
      decisions: { path: "integrity/decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual", "recommendation"],
        contradictions: "review",
        rejectedDecisions: "block",
        responseMutation: "block",
        replay: "block",
      },
    },
    response: { content: "The approved policy is active.", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 30, sha256: "61fe3a22fbb5346c380e9517bfc80b11fa5af77c800bec0b20c3c143a45b28df" }] },
    sources: [{ sourceId: "policy", path: "docs/policy.md", sha256: "a".repeat(64), size: 12 }],
    decisionRegistryDigest: "a".repeat(64),
    decisions: [{ eventId: "event-1", decisionId: "decision-1", revision: 1, action: "activate" }],
    evidence: [{ evidenceId: "evidence-1", sourceId: "policy" }],
    claims: [{ claimId: "claim-1", sectionId: "answer", kind: "factual", decisionIds: ["decision-1"], evidence: [{ evidenceId: "evidence-1", role: "supporting", support: "direct" }] }],
  };
}

describe("complete-envelope verification", () => {
  it("passes a complete valid envelope and binds its canonical digest", () => {
    const result = verifyEnvelope(envelope());
    expect(result.status).toBe("PASS");
    expect(result.envelopeDigest).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("routes ambiguous support to review", () => {
    const input = envelope();
    input.claims = [{ ...input.claims[0]!, evidence: [{ evidenceId: "evidence-1", role: "supporting", support: "ambiguous" }] }];
    expect(verifyEnvelope(input).status).toBe("REVIEW");
  });

  it("does not globally block unrelated rejected history", () => {
    const input = envelope();
    input.decisions = [...input.decisions, { eventId: "event-2", decisionId: "decision-1", revision: 2, action: "reject" }];
    input.claims = [];
    const result = verifyEnvelope(input);
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toEqual(["claim.section_uncovered"]);
  });

  it("fails closed on malformed input", () => {
    const input = envelope();
    input.sources = [{ ...input.sources[0]!, sha256: "invalid" }];
    const result = verifyEnvelope(input);
    expect(result.status).toBe("BLOCKED");
    expect(result.findings[0]?.code).toBe("checker.failure");
    expect(result.envelopeDigest).toBeUndefined();
  });

  it("changes the binding when any response byte changes", () => {
    const first = verifyEnvelope(envelope());
    const changed = envelope();
    changed.response.content += " ";
    const second = verifyEnvelope(changed);
    expect(second.envelopeDigest).not.toBe(first.envelopeDigest);
  });
});
