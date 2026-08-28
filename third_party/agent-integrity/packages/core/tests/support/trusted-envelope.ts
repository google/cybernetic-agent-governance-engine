import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IntegrityEnvelope } from "@agent-integrity/protocol";
import type { TrustedVerificationContext } from "../../src/verify-trusted.js";
import { validEnvelope } from "./valid-envelope.js";

const digest = (bytes: string | Buffer): string => createHash("sha256").update(bytes).digest("hex");

export async function trustedEnvelopeFixture(): Promise<{
  envelope: IntegrityEnvelope;
  context: TrustedVerificationContext;
}> {
  const projectRoot = await mkdtemp(join(tmpdir(), "agent-integrity-trusted-fixture-"));
  await mkdir(join(projectRoot, "docs"));
  await mkdir(join(projectRoot, "integrity"));
  const bytes = Buffer.from("0123456789", "utf8");
  await writeFile(join(projectRoot, "docs", "source.md"), bytes);
  const registry = "version: 1\nevents: []\n";
  await writeFile(join(projectRoot, "integrity", "decisions.yaml"), registry);
  const base = validEnvelope();
  return {
    context: { projectRoot, allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: base.policy },
    envelope: {
      ...base,
      decisionRegistryDigest: digest(registry),
      sources: [{ sourceId: "source-1", path: "docs/source.md", size: bytes.length, sha256: digest(bytes) }],
      evidence: [{ evidenceId: "evidence-1", sourceId: "source-1", anchor: { byteStart: 0, byteEnd: 4, sha256: digest("0123") } }],
    },
  };
}
