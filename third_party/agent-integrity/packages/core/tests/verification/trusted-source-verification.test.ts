import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "../../src/verify.js";
import { verifyTrustedEnvelope } from "../../src/verify-trusted.js";
import { validEnvelope } from "../support/valid-envelope.js";

const sha256 = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");

async function fixture() {
  const projectRoot = await mkdtemp(join(tmpdir(), "agent-integrity-trusted-"));
  await mkdir(join(projectRoot, "docs"));
  await mkdir(join(projectRoot, "integrity"));
  const registry = "version: 1\nevents: []\n";
  await writeFile(join(projectRoot, "integrity", "decisions.yaml"), registry);
  const bytes = Buffer.from("trusted source bytes\n", "utf8");
  await writeFile(join(projectRoot, "docs", "source.md"), bytes);
  const base = validEnvelope();
  return {
    projectRoot,
    bytes,
    envelope: {
      ...base,
      decisionRegistryDigest: sha256(Buffer.from(registry)),
      sources: [{ sourceId: "source-1", path: "docs/source.md", size: bytes.length, sha256: sha256(bytes) }],
      evidence: [{
        evidenceId: "evidence-1",
        sourceId: "source-1",
        anchor: { byteStart: 0, byteEnd: 7, sha256: sha256(bytes.subarray(0, 7)) },
      }],
    },
  };
}

describe("verifyTrustedEnvelope", () => {
  it("blocks a fabricated source record", async () => {
    const test = await fixture();
    const envelope = {
      ...test.envelope,
      sources: [{ ...test.envelope.sources[0]!, sha256: "0".repeat(64) }],
    };
    const result = await verifyTrustedEnvelope(envelope, {
      projectRoot: test.projectRoot,
      allowedRoots: ["docs"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
    });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.some((finding) => finding.code === "source.digest_mismatch")).toBe(true);
  });

  it("blocks source mutation after an earlier trusted verification", async () => {
    const test = await fixture();
    const context = { projectRoot: test.projectRoot, allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: test.envelope.policy };
    expect((await verifyTrustedEnvelope(test.envelope, context)).status).toBe("PASS");
    await writeFile(join(test.projectRoot, "docs", "source.md"), "changed source bytes\n");
    const result = await verifyTrustedEnvelope(test.envelope, context);
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.some((finding) => finding.code === "source.digest_mismatch")).toBe(true);
  });

  it("compares the normalized live path and byte size", async () => {
    const test = await fixture();
    const wrongSize = {
      ...test.envelope,
      sources: [{ ...test.envelope.sources[0]!, size: test.bytes.length + 1 }],
    };
    const sizeResult = await verifyTrustedEnvelope(wrongSize, {
      projectRoot: test.projectRoot,
      allowedRoots: ["docs"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
    });
    expect(sizeResult.findings.some((finding) => finding.code === "source.size_mismatch")).toBe(true);

    const nonNormalized = {
      ...test.envelope,
      sources: [{ ...test.envelope.sources[0]!, path: "docs/./source.md" }],
    };
    const pathResult = await verifyTrustedEnvelope(nonNormalized, {
      projectRoot: test.projectRoot,
      allowedRoots: ["docs"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
    });
    expect(pathResult.findings.some((finding) => finding.code === "source.path_mismatch")).toBe(true);
  });

  it("requires trusted roots to match the policy roots", async () => {
    const test = await fixture();
    const result = await verifyTrustedEnvelope(test.envelope, {
      projectRoot: test.projectRoot,
      allowedRoots: ["other"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
    });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.some((finding) => finding.code === "trusted.context_invalid")).toBe(true);
  });

  it("checks evidence anchors against the recollected source bytes", async () => {
    const test = await fixture();
    const envelope = {
      ...test.envelope,
      evidence: [{ ...test.envelope.evidence[0]!, anchor: { byteStart: 0, byteEnd: 7, sha256: "0".repeat(64) } }],
    };
    const result = await verifyTrustedEnvelope(envelope, {
      projectRoot: test.projectRoot,
      allowedRoots: ["docs"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
    });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.some((finding) => finding.code === "evidence.anchor_digest_mismatch")).toBe(true);
  });

  it("rejects missing and out-of-range anchors", async () => {
    const test = await fixture();
    const missing = { ...test.envelope, evidence: [{ evidenceId: "evidence-1", sourceId: "source-1" }] };
    expect((await verifyTrustedEnvelope(missing, { projectRoot: test.projectRoot, allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: test.envelope.policy })).status)
      .toBe("BLOCKED");
    const outside = {
      ...test.envelope,
      evidence: [{ ...test.envelope.evidence[0]!, anchor: { byteStart: 0, byteEnd: 999, sha256: "0".repeat(64) } }],
    };
    expect((await verifyTrustedEnvelope(outside, { projectRoot: test.projectRoot, allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: test.envelope.policy })).status)
      .toBe("BLOCKED");
  });

  it("blocks a source larger than the configured per-source budget", async () => {
    const test = await fixture();
    const result = await verifyTrustedEnvelope(test.envelope, {
      projectRoot: test.projectRoot,
      allowedRoots: ["docs"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
      maxSourceBytes: test.bytes.length - 1,
    });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.some((finding) => finding.code === "source.collection_failed" && /limit/u.test(finding.message))).toBe(true);
  });

  it("blocks sources that cumulatively exceed the configured total budget", async () => {
    const test = await fixture();
    const second = Buffer.from("second source\n", "utf8");
    await writeFile(join(test.projectRoot, "docs", "second.md"), second);
    const envelope = {
      ...test.envelope,
      sources: [
        ...test.envelope.sources,
        { sourceId: "source-2", path: "docs/second.md", size: second.length, sha256: sha256(second) },
      ],
    };
    const result = await verifyTrustedEnvelope(envelope, {
      projectRoot: test.projectRoot,
      allowedRoots: ["docs"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
      maxSourceBytes: 1024,
      maxTotalSourceBytes: test.bytes.length + second.length - 1,
    });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.some((finding) => finding.code === "source.collection_failed" && /limit/u.test(finding.message))).toBe(true);
  });

  it("blocks an embedded policy downgrade from the separately trusted policy", async () => {
    const test = await fixture();
    const envelope = {
      ...test.envelope,
      policy: { ...test.envelope.policy, rules: { ...test.envelope.policy.rules, requireEvidenceFor: ["recommendation"] as const } },
      evidence: [],
      claims: test.envelope.claims.map((claim) => ({ ...claim, evidence: [] })),
    };
    expect(verifyEnvelope(envelope).status).toBe("PASS");
    const result = await verifyTrustedEnvelope(envelope, {
      projectRoot: test.projectRoot,
      allowedRoots: ["docs"],
      decisionRegistryPath: "integrity/decisions.yaml",
      trustedPolicy: test.envelope.policy,
    });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("trusted.policy_mismatch");
  });
});
