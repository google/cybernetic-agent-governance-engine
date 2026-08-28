import { PROTOCOL_VERSION, type IntegrityEnvelope } from "@agent-integrity/protocol";

export function validEnvelope(): IntegrityEnvelope {
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
    response: { content: "Supported response", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 18, sha256: "a31069ff26ded3cd55c0d40ebaa3430097950a210b8caaece07b27dedbb92766" }] },
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
  };
}
