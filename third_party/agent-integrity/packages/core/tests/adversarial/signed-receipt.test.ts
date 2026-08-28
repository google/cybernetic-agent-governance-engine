import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, recheckTrustedReceipt, sha256Canonical, verifyTrustedEnvelope } from "../../src/index.js";
import { receiptSigningOptions, receiptTrust } from "../support/receipt-keys.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";

async function issued(runId: string) {
  const directory = await mkdtemp(join(tmpdir(), "integrity-signed-receipt-"));
  const { envelope, context } = await trustedEnvelopeFixture();
  const verification = await verifyTrustedEnvelope(envelope, context);
  const receipt = await createReceipt({
    runId, path: join(directory, `${runId}.json`), envelope, verification, context,
    ...receiptSigningOptions,
    createdAt: new Date("2026-08-02T00:00:00.000Z"),
    expiresAt: new Date("2026-08-02T01:00:00.000Z"),
  });
  return { receipt, envelope, context };
}

describe("signed receipt authentication", () => {
  it("publishes the exact canonical Ed25519 signature encoding constraint", async () => {
    const schema = JSON.parse(await readFile(new URL("../../../../schemas/integrity-receipt.schema.json", import.meta.url), "utf8"));
    expect(schema.properties.signature.properties.value).toEqual({
      type: "string", minLength: 88, maxLength: 88, pattern: "^[A-Za-z0-9+/]{86}==$",
    });
  });
  it("blocks a forged body even when the attacker recomputes the public digest", async () => {
    const { receipt, envelope, context } = await issued("forgery");
    const forgedWithoutDigest = { ...receipt, audience: "attacker" };
    const { receiptDigest: _old, ...body } = forgedWithoutDigest;
    const forged = { ...body, receiptDigest: sha256Canonical(body) };
    const result = await recheckTrustedReceipt({ receipt: forged, envelope, context, trust: receiptTrust, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.invalid_signature");
  });

  it.each([
    ["wrong audience", { audience: "other" }, "receipt.wrong_audience"],
    ["wrong purpose", { purpose: "other" }, "receipt.wrong_purpose"],
    ["wrong engine", { engineVersion: "9.9.9" }, "receipt.wrong_engine"],
    ["revoked key", { revokedKeyIds: ["test-key-1"] }, "receipt.key_revoked"],
  ])("blocks %s", async (_name, override, code) => {
    const { receipt, envelope, context } = await issued(`case-${code}`);
    const result = await recheckTrustedReceipt({ receipt, envelope, context, trust: { ...receiptTrust, ...override }, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.findings.map((finding) => finding.code)).toContain(code);
  });

  it("blocks an unknown signing key", async () => {
    const { receipt, envelope, context } = await issued("unknown-key");
    const other = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    const result = await recheckTrustedReceipt({ receipt, envelope, context, trust: { ...receiptTrust, keys: { other } }, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.unknown_key");
  });

  it("binds the key ID into the Ed25519 signature", async () => {
    const { receipt, envelope, context } = await issued("key-alias");
    const aliasedWithoutDigest = { ...receipt, signature: { ...receipt.signature, keyId: "alias-key" } };
    const { receiptDigest: _old, ...body } = aliasedWithoutDigest;
    const aliased = { ...body, receiptDigest: sha256Canonical(body) };
    const result = await recheckTrustedReceipt({
      receipt: aliased, envelope, context,
      trust: { ...receiptTrust, keys: { ...receiptTrust.keys, "alias-key": receiptTrust.keys["test-key-1"]! }, revokedKeyIds: ["test-key-1"] },
      now: new Date("2026-08-02T00:30:00.000Z"),
    });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.invalid_signature");
  });

  it("blocks an envelope policy downgrade against receipt trust configuration", async () => {
    const { receipt, envelope, context } = await issued("policy-downgrade");
    const downgraded = {
      ...envelope,
      policy: { ...envelope.policy, rules: { ...envelope.policy.rules, requireEvidenceFor: ["recommendation"] as const } },
    };
    const result = await recheckTrustedReceipt({ receipt, envelope: downgraded, context, trust: receiptTrust, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.policy_downgrade");
  });

  it.each([
    ["unpadded", (value: string) => value.replace(/==$/u, "")],
    ["whitespace", (value: string) => `${value.slice(0, 20)}\n${value.slice(20)}`],
    ["wrong length", (_value: string) => Buffer.alloc(63).toString("base64")],
  ])("rejects %s Ed25519 signature encoding", async (_name, mutate) => {
    const { receipt, envelope, context } = await issued(`encoding-${_name.replace(" ", "-")}`);
    const changedWithoutDigest = { ...receipt, signature: { ...receipt.signature, value: mutate(receipt.signature.value) } };
    const { receiptDigest: _old, ...body } = changedWithoutDigest;
    const changed = { ...body, receiptDigest: sha256Canonical(body) };
    const result = await recheckTrustedReceipt({ receipt: changed, envelope, context, trust: receiptTrust, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.invalid_signature_encoding");
  });

  it("rejects excessive lifetime at issuance", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-lifetime-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    await expect(createReceipt({ runId: "long", path: join(directory, "long.json"), envelope, verification, context, ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T02:00:00.000Z") })).rejects.toThrow(/lifetime/u);
  });

  it("blocks receipts issued too far in the future", async () => {
    const { receipt, envelope, context } = await issued("future");
    const result = await recheckTrustedReceipt({ receipt, envelope, context, trust: receiptTrust, now: new Date("2026-08-01T23:00:00.000Z") });
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.future_issued");
  });
});
