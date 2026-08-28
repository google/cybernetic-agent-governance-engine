import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { collectSource, verifyTrustedEnvelope } from "../../packages/core/dist/index.js";
import { AgentIntegritySession, releaseVerifiedResponse } from "../../packages/sdk/dist/index.js";

const policy = {
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

const projectRoot = fileURLToPath(new URL(".", import.meta.url));
const context = { projectRoot, allowedRoots: policy.sources.allowedRoots, decisionRegistryPath: policy.decisions.path, trustedPolicy: policy };
const collected = await collectSource({ ...context, sourcePath: "docs/maintenance.md" });
const sourceBytes = await readFile(new URL("docs/maintenance.md", import.meta.url));
const anchorBytes = sourceBytes.subarray(0, 43);
const registryBytes = await readFile(new URL("integrity/decisions.yaml", import.meta.url));
const decisionRegistryDigest = createHash("sha256").update(registryBytes).digest("hex");

const session = new AgentIntegritySession(policy, decisionRegistryDigest)
  .setResponse("The maintenance window begins at 09:00 UTC.", [
    { sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 43, sha256: "540beff0286b1ba21c45be4113a48f85ca13cb1b6b4b1f9ef9de06bf08238f6a" },
  ])
  .addSource({
    sourceId: "maintenance-policy",
    path: "docs/maintenance.md",
    sha256: collected.sha256,
    size: collected.size,
  })
  .addEvidence({
    evidenceId: "maintenance-window",
    sourceId: "maintenance-policy",
    anchor: { byteStart: 0, byteEnd: anchorBytes.length, sha256: createHash("sha256").update(anchorBytes).digest("hex") },
  })
  .addClaim({
    claimId: "window-start",
    sectionId: "answer",
    kind: "factual",
    decisionIds: [],
    evidence: [{ evidenceId: "maintenance-window", role: "supporting", support: "direct" }],
  });

const envelope = session.buildEnvelope();
const verification = await verifyTrustedEnvelope(envelope, context);
const release = await releaseVerifiedResponse({ envelope, verification, context });
console.log(JSON.stringify(release, null, 2));
if (release.status !== "PASS") process.exitCode = 1;
