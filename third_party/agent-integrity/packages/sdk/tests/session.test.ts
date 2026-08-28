import { describe, expect, it } from "vitest";
import { PROTOCOL_VERSION, type IntegrityPolicy } from "@agent-integrity/protocol";
import { AgentIntegritySession } from "../src/session.js";

const policy: IntegrityPolicy = {
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
};

describe("AgentIntegritySession", () => {
  it("constructs a complete envelope without a per-run manifest", () => {
    const session = new AgentIntegritySession(policy, "a".repeat(64))
      .setResponse("Supported answer", [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 16, sha256: "f66b51d1938ea26bc8fa6432aae63470ebbf8aa72b3b8bde7f7a92b48999dd3a" }])
      .addSource({ sourceId: "source-1", path: "docs/source.md", sha256: "a".repeat(64), size: 10 })
      .addEvidence({ evidenceId: "evidence-1", sourceId: "source-1" })
      .addClaim({
        claimId: "claim-1",
        sectionId: "answer",
        kind: "factual",
        decisionIds: [],
        evidence: [{ evidenceId: "evidence-1", role: "supporting", support: "direct" }],
      });

    expect(session.buildEnvelope()).toEqual({
      protocolVersion: PROTOCOL_VERSION,
      policy,
      response: { content: "Supported answer", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 16, sha256: "f66b51d1938ea26bc8fa6432aae63470ebbf8aa72b3b8bde7f7a92b48999dd3a" }] },
      sources: [{ sourceId: "source-1", path: "docs/source.md", sha256: "a".repeat(64), size: 10 }],
      decisionRegistryDigest: "a".repeat(64),
      decisions: [],
      evidence: [{ evidenceId: "evidence-1", sourceId: "source-1" }],
      claims: [{
        claimId: "claim-1",
        sectionId: "answer",
        kind: "factual",
        decisionIds: [],
        evidence: [{ evidenceId: "evidence-1", role: "supporting", support: "direct" }],
      }],
    });
  });

  it("refuses to build before a response is set", () => {
    expect(() => new AgentIntegritySession(policy, "a".repeat(64)).buildEnvelope()).toThrow("response has not been set");
  });
});
