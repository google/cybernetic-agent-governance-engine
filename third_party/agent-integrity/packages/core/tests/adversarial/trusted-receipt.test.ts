import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, verifyEnvelope } from "../../src/index.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";
import { receiptSigningOptions } from "../support/receipt-keys.js";

describe("trusted receipt creation", () => {
  it("rejects a fabricated source record even when structural verification passed", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-adversarial-"));
    const { envelope: base, context } = await trustedEnvelopeFixture();
    const envelope = { ...base, sources: [{ ...base.sources[0]!, sha256: "0".repeat(64) }] };
    const structural = verifyEnvelope(envelope);
    expect(structural.status).toBe("PASS");
    await expect(createReceipt({
      runId: "fabricated",
      path: join(directory, "fabricated.json"),
      envelope,
      verification: structural,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    })).rejects.toThrow(/verification does not match/u);
  });

  it("rejects missing evidence anchors even when structural verification passed", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-adversarial-"));
    const { envelope: base, context } = await trustedEnvelopeFixture();
    const envelope = { ...base, evidence: [{ evidenceId: "evidence-1", sourceId: "source-1" }] };
    const structural = verifyEnvelope(envelope);
    expect(structural.status).toBe("PASS");
    await expect(createReceipt({
      runId: "missing-anchor",
      path: join(directory, "missing-anchor.json"),
      envelope,
      verification: structural,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    })).rejects.toThrow(/verification does not match/u);
  });
});
