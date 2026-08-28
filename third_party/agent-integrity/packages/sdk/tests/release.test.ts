import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyTrustedEnvelope } from "@agent-integrity/core";
import { PROTOCOL_VERSION, type IntegrityEnvelope } from "@agent-integrity/protocol";
import { releaseVerifiedResponse } from "../src/release.js";

const digest = (value: string): string => createHash("sha256").update(value).digest("hex");

async function fixture(): Promise<{ envelope: IntegrityEnvelope; context: { projectRoot: string; allowedRoots: string[]; decisionRegistryPath: string; trustedPolicy: IntegrityEnvelope["policy"] } }> {
  const projectRoot = await mkdtemp(join(tmpdir(), "agent-integrity-release-"));
  await mkdir(join(projectRoot, "docs"));
  await mkdir(join(projectRoot, "integrity"));
  await writeFile(join(projectRoot, "docs", "source.md"), "source text");
  const registry = "version: 1\nevents: []\n";
  await writeFile(join(projectRoot, "integrity", "decisions.yaml"), registry);
  const policy: IntegrityEnvelope["policy"] = {
    version: 1,
    sources: { allowedRoots: ["docs"] },
    decisions: { path: "integrity/decisions.yaml" },
    rules: { requireEvidenceFor: ["factual", "recommendation"], contradictions: "review", rejectedDecisions: "block", responseMutation: "block", replay: "block" },
  };
  return {
    context: { projectRoot, allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: policy },
    envelope: {
      protocolVersion: PROTOCOL_VERSION,
      policy,
      response: { content: "Supported response", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 18, sha256: "a31069ff26ded3cd55c0d40ebaa3430097950a210b8caaece07b27dedbb92766" }] },
      sources: [{ sourceId: "source-1", path: "docs/source.md", sha256: digest("source text"), size: 11 }],
      decisionRegistryDigest: digest(registry),
      decisions: [],
      evidence: [{ evidenceId: "evidence-1", sourceId: "source-1", anchor: { byteStart: 0, byteEnd: 6, sha256: digest("source") } }],
      claims: [{ claimId: "claim-1", sectionId: "answer", kind: "factual", decisionIds: [], evidence: [{ evidenceId: "evidence-1", role: "supporting", support: "direct" }] }],
    },
  };
}

describe("releaseVerifiedResponse", () => {
  it("releases only the exact response bound to a trusted PASS result", async () => {
    const { envelope, context } = await fixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    await expect(releaseVerifiedResponse({ envelope, verification, context })).resolves.toEqual({ status: "PASS", response: "Supported response", verification });
  });

  it("releases nothing for REVIEW", async () => {
    const { envelope: base, context } = await fixture();
    const envelope = { ...base, claims: [{ ...base.claims[0]!, evidence: [{ evidenceId: "evidence-1", role: "supporting" as const, support: "ambiguous" as const }] }] };
    const verification = await verifyTrustedEnvelope(envelope, context);
    const result = await releaseVerifiedResponse({ envelope, verification, context });
    expect(result.status).toBe("REVIEW");
    expect("response" in result).toBe(false);
  });

  it("releases nothing for BLOCKED", async () => {
    const { envelope: base, context } = await fixture();
    const envelope = { ...base, claims: [{ ...base.claims[0]!, evidence: [] }] };
    const verification = await verifyTrustedEnvelope(envelope, context);
    const result = await releaseVerifiedResponse({ envelope, verification, context });
    expect(result.status).toBe("BLOCKED");
    expect("response" in result).toBe(false);
  });

  it("blocks post-verification response mutation", async () => {
    const { envelope, context } = await fixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const mutated = { ...envelope, response: { content: "Changed after checking", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 22, sha256: "d7e39934bbd672eec72ac901869071c5a98498bd14bb5a6b0596ab954ece672c" }] } };
    const result = await releaseVerifiedResponse({ envelope: mutated, verification, context });
    expect(result.status).toBe("BLOCKED");
    expect("response" in result).toBe(false);
  });

  it("blocks post-verification source mutation", async () => {
    const { envelope, context } = await fixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    await writeFile(join(context.projectRoot, "docs", "source.md"), "changed text");
    const result = await releaseVerifiedResponse({ envelope, verification, context });
    expect(result.status).toBe("BLOCKED");
    expect("response" in result).toBe(false);
  });

  it("fails closed when supplied malformed input", async () => {
    const { envelope, context } = await fixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const result = await releaseVerifiedResponse({ envelope: null as never, verification, context });
    expect(result.status).toBe("BLOCKED");
  });
});
