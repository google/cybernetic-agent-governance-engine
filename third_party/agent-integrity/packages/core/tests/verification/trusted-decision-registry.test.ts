import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyTrustedEnvelope } from "../../src/verify-trusted.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";

const digest = (value: string): string => createHash("sha256").update(value).digest("hex");
const registry = (events: readonly object[]): string => `version: 1\nevents:\n${events.map((event) => `  - ${JSON.stringify(event)}`).join("\n")}\n`;

async function withRegistry(events: readonly object[]) {
  const test = await trustedEnvelopeFixture();
  const yaml = registry(events);
  await mkdir(join(test.context.projectRoot, "integrity"), { recursive: true });
  await writeFile(join(test.context.projectRoot, "integrity", "decisions.yaml"), yaml);
  return {
    ...test,
    envelope: { ...test.envelope, decisionRegistryDigest: digest(yaml), decisions: events },
  };
}

describe("trusted decision registry", () => {
  it("requires registry configuration from the trusted context", async () => {
    const test = await withRegistry([]);
    const context = { projectRoot: test.context.projectRoot, allowedRoots: ["docs"], trustedPolicy: test.envelope.policy } as never;
    const result = await verifyTrustedEnvelope(test.envelope, context);
    expect(result.findings.some((finding) => finding.code === "trusted.context_invalid")).toBe(true);
  });

  it("blocks an omitted registry snapshot", async () => {
    const event = { eventId: "e1", decisionId: "approved", revision: 1, action: "activate" } as const;
    const test = await withRegistry([event]);
    const result = await verifyTrustedEnvelope({ ...test.envelope, decisions: [] }, test.context);
    expect(result.findings.some((finding) => finding.code === "decision.snapshot_mismatch")).toBe(true);
  });

  it("blocks stale decision references", async () => {
    const events = [
      { eventId: "e1", decisionId: "old", revision: 1, action: "activate" },
      { eventId: "e2", decisionId: "new", revision: 1, action: "activate" },
      { eventId: "e3", decisionId: "old", revision: 2, action: "supersede", supersededBy: "new" },
    ] as const;
    const test = await withRegistry(events);
    const claims = [{ ...test.envelope.claims[0]!, decisionIds: ["old"] }];
    const result = await verifyTrustedEnvelope({ ...test.envelope, claims }, test.context);
    expect(result.findings.some((finding) => finding.code === "decision.superseded")).toBe(true);
  });

  it("does not block unrelated rejected or superseded history", async () => {
    const events = [
      { eventId: "e1", decisionId: "old", revision: 1, action: "activate" },
      { eventId: "e2", decisionId: "current", revision: 1, action: "activate" },
      { eventId: "e3", decisionId: "old", revision: 2, action: "supersede", supersededBy: "current" },
      { eventId: "e4", decisionId: "rejected", revision: 1, action: "activate" },
      { eventId: "e5", decisionId: "rejected", revision: 2, action: "reject" },
    ] as const;
    const test = await withRegistry(events);
    const claims = [{ ...test.envelope.claims[0]!, decisionIds: ["current"] }];
    expect((await verifyTrustedEnvelope({ ...test.envelope, claims }, test.context)).status).toBe("PASS");
  });

  it("blocks registry mutation after verification", async () => {
    const event = { eventId: "e1", decisionId: "approved", revision: 1, action: "activate" } as const;
    const test = await withRegistry([event]);
    const claims = [{ ...test.envelope.claims[0]!, decisionIds: ["approved"] }];
    const envelope = { ...test.envelope, claims };
    expect((await verifyTrustedEnvelope(envelope, test.context)).status).toBe("PASS");
    await writeFile(join(test.context.projectRoot, "integrity", "decisions.yaml"), registry([]));
    const result = await verifyTrustedEnvelope(envelope, test.context);
    expect(result.findings.some((finding) => finding.code === "decision.registry_digest_mismatch")).toBe(true);
  });
});
