import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, recheckTrustedReceipt, verifyTrustedEnvelope } from "../../src/index.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";
import { receiptSigningOptions, receiptTrust } from "../support/receipt-keys.js";

describe("receipt replay and mutation resistance", () => {
  it("blocks replay against a changed response", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-replay-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({
      runId: "run-replay",
      path: join(directory, "receipt.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const changed = { ...envelope, response: { content: "Supported response!", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 19, sha256: "f32e91553e55c5c345097029c44fbb5afb3e1c91c957cbc36752e5a91e4a05cc" }] } };
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope: changed, context, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.subject_changed");
  });

  it("blocks a modified receipt", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-replay-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({
      runId: "run-edit",
      path: join(directory, "receipt.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const edited = { ...receipt, runId: "attacker-run" };
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt: edited, envelope, context, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.mutated");
  });
});
