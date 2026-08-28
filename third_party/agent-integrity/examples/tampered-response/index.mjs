import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { collectSource, verifyTrustedEnvelope } from "../../packages/core/dist/index.js";
import { releaseVerifiedResponse } from "../../packages/sdk/dist/index.js";

const envelope = {
  protocolVersion: "1-alpha",
  policy: { version: 1, sources: { allowedRoots: ["docs"] }, decisions: { path: "integrity/decisions.yaml" }, rules: { requireEvidenceFor: ["factual"], contradictions: "review", rejectedDecisions: "block", responseMutation: "block", replay: "block" } },
  response: { content: "Original response", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 17, sha256: "d874e9ec7af7a8d905750e12e764804ec3aee19b31a4dc3c5aa9554ae1c2712f" }] },
  sources: [],
  decisionRegistryDigest: "44fbe87080e7534ae05e225047dcdc1851e5d3a1e7e45d654d7828a5dd8e0e88",
  decisions: [],
  evidence: [],
  claims: [{ claimId: "claim", sectionId: "answer", kind: "factual", decisionIds: [], evidence: [{ evidenceId: "evidence", role: "supporting", support: "direct" }] }],
};

const projectRoot = fileURLToPath(new URL(".", import.meta.url));
const policy = envelope.policy;
const context = { projectRoot, allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: policy };
const source = await collectSource({ ...context, sourcePath: "docs/source.md" });
envelope.sources = [{ sourceId: "source", ...source }];
envelope.evidence = [{
  evidenceId: "evidence",
  sourceId: "source",
  anchor: { byteStart: 0, byteEnd: 16, sha256: createHash("sha256").update("trusted evidence").digest("hex") },
}];
const verification = await verifyTrustedEnvelope(envelope, context);
const changed = { ...envelope, response: { ...envelope.response, content: "Changed response" } };
const result = await releaseVerifiedResponse({ envelope: changed, verification, context });
console.log(JSON.stringify(result, null, 2));
if (result.status !== "BLOCKED" || "response" in result) process.exitCode = 1;
