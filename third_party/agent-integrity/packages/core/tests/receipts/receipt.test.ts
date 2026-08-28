import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, FileReceiptStore, recheckTrustedReceipt, verifyTrustedEnvelope } from "../../src/index.js";
import { isUnsupportedDirectoryOpenError } from "../../src/receipts/file-receipt-store.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";
import { receiptSigner, receiptSigningOptions, receiptTrust } from "../support/receipt-keys.js";

describe("signed alpha receipts", () => {
  it("classifies only known unsupported directory-open errors", () => {
    for (const code of ["EPERM", "EACCES", "EISDIR"]) expect(isUnsupportedDirectoryOpenError({ code })).toBe(true);
    for (const code of ["ENOENT", "EMFILE", "EIO", undefined]) expect(isUnsupportedDirectoryOpenError({ code })).toBe(false);
  });
  it("persists a producer-authenticated content-bound receipt without overwriting", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const path = join(directory, "run-1.json");
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    });

    expect(receipt.signature.algorithm).toBe("Ed25519");
    expect(receipt.signature.keyId).toBe(receiptSigner.keyId);
    expect(receipt.envelopeDigest).toBe(verification.envelopeDigest);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(receipt);
    await expect(createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    })).rejects.toThrow(/already exists/u);
  });

  it("rejects duplicate run IDs even when a different receipt filename is supplied", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const common = {
      runId: "same-run",
      envelope,
      verification,
      context,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore: new FileReceiptStore(join(directory, "store")),
      ...receiptSigningOptions,
    };
    await createReceipt({ ...common, path: join(directory, "first.json") });
    await expect(createReceipt({ ...common, path: join(directory, "second.json") }))
      .rejects.toThrow(/(run ID|transaction).*exists/u);
  });

  it("passes a fresh receipt only when all live bound content is unchanged", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const receipt = await createReceipt({
      runId: "run-2",
      path: join(directory, "run-2.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    });
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("PASS");
  });

  it("blocks expired receipts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const receipt = await createReceipt({
      runId: "run-3",
      path: join(directory, "run-3.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    });
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore, now: new Date("2026-08-02T01:00:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.expired");
  });

  it("allows exactly one concurrent consumer and rejects copied receipt replay", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-consume-"));
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "one-use", path: join(directory, "receipt.json"), envelope, verification, context, receiptStore, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const options = { trust: receiptTrust, receipt: structuredClone(receipt), envelope, context, receiptStore, now: new Date("2026-08-02T00:30:00.000Z") };
    const results = await Promise.all([recheckTrustedReceipt(options), recheckTrustedReceipt(options)]);
    expect(results.map((result) => result.status).sort()).toEqual(["BLOCKED", "PASS"]);
    expect(results.flatMap((result) => result.findings.map((finding) => finding.code))).toContain("receipt.replayed");
  });

  it("preserves consumed state after the store is reopened", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-restored-"));
    const storePath = join(directory, "store");
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "restored", path: join(directory, "receipt.json"), envelope, verification, context, receiptStore: new FileReceiptStore(storePath), ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    expect((await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore: new FileReceiptStore(storePath), now: new Date("2026-08-02T00:30:00.000Z") })).status).toBe("PASS");
    const replay = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore: new FileReceiptStore(storePath), now: new Date("2026-08-02T00:31:00.000Z") });
    expect(replay.status).toBe("BLOCKED");
    expect(replay.findings.map((finding) => finding.code)).toContain("receipt.replayed");
  });

  it("retains authoritative issuance when receipt output cannot be written", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-rollback-"));
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const path = join(directory, "receipt.json");
    await import("node:fs/promises").then(({ writeFile }) => writeFile(path, "occupied"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const base = { runId: "retryable", path, envelope, verification, context, receiptStore, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") };
    await expect(createReceipt(base)).rejects.toThrow(/was issued but output completion failed/u);
    await import("node:fs/promises").then(({ unlink }) => unlink(path));
    const [issuedName] = await readdir(join(directory, "store", "issued"));
    const digest = issuedName!.replace(/\.json$/u, "");
    await expect(receiptStore.completeReceiptFile(digest, path)).resolves.toMatchObject({ runId: "retryable" });
    await expect(createReceipt({ ...base, path: join(directory, "other.json") })).rejects.toThrow(/transaction.*exists/u);
  });

  it("allows exactly one concurrent issuance for a run ID and nonce", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-concurrent-issue-"));
    const sourceStore = new FileReceiptStore(join(directory, "source-store"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "concurrent", path: join(directory, "receipt.json"), envelope, verification, context, receiptStore: sourceStore, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const target = new FileReceiptStore(join(directory, "target-store"));
    const results = await Promise.allSettled([target.issue(receipt), target.issue(receipt)]);
    expect(results.map((result) => result.status).sort()).toEqual(["fulfilled", "rejected"]);
  });

  it("does not steal or delete a stalled legacy lock file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-no-lock-steal-"));
    const storePath = join(directory, "store");
    await mkdir(storePath);
    await writeFile(join(storePath, ".lock"), "live-owner");
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    await createReceipt({ runId: "no-lock", path: join(directory, "receipt.json"), envelope, verification, context, receiptStore: new FileReceiptStore(storePath), ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    expect(await readFile(join(storePath, ".lock"), "utf8")).toBe("live-owner");
  });

  it("requires the exact owner token to recover an abandoned store lock", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-abandoned-lock-"));
    const storePath = join(directory, "store");
    await mkdir(storePath);
    await writeFile(join(storePath, ".store-lock.json"), JSON.stringify({ version: 1, ownerToken: "exact-owner" }));
    const store = new FileReceiptStore(storePath);
    await expect(store.recoverAbandonedLock({ offlineExclusive: true, ownerToken: "wrong" })).rejects.toThrow(/ownership changed/u);
    expect(JSON.parse(await readFile(join(storePath, ".store-lock.json"), "utf8")).ownerToken).toBe("exact-owner");
    await expect(store.recoverAbandonedLock({ offlineExclusive: true, ownerToken: "exact-owner" })).resolves.toBeUndefined();
  });

  it("recovers an interrupted issuance without orphaning run ID or nonce", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-recover-issue-"));
    const storePath = join(directory, "store");
    const store = new FileReceiptStore(storePath);
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "recoverable", path: join(directory, "receipt.json"), envelope, verification, context, receiptStore: store, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    await rm(join(storePath, "issued", `${receipt.receiptDigest}.json`));
    const transactionName = createHash("sha256").update(receipt.receiptDigest).digest("hex");
    const transaction = JSON.parse(await readFile(join(storePath, "transactions", `${transactionName}.json`), "utf8"));
    await store.recoverInterruptedIssue(receipt, { offlineExclusive: true, transactionId: transaction.transactionId });
    await expect(store.issue(receipt)).resolves.toBeUndefined();
  });

  it("reconstructs a missing receipt file after a crash following store issuance", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-complete-output-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const source = new FileReceiptStore(join(directory, "source"));
    const receipt = await createReceipt({ runId: "crash-window", path: join(directory, "original.json"), envelope, verification, context, receiptStore: source, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const recoveredStore = new FileReceiptStore(join(directory, "recovered-store"));
    await recoveredStore.issue(receipt);
    const recoveredPath = join(directory, "recovered.json");
    await expect(recoveredStore.completeReceiptFile(receipt.receiptDigest, recoveredPath)).resolves.toEqual(receipt);
    expect(JSON.parse(await readFile(recoveredPath, "utf8"))).toEqual(receipt);
    await expect(recoveredStore.issue(receipt)).rejects.toThrow(/(run ID|transaction).*exists/u);
  });

  it("enforces a concurrency-safe maximum receipt count", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-store-quota-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const first = await createReceipt({ runId: "quota-one", path: join(directory, "one.json"), envelope, verification, context, receiptStore: new FileReceiptStore(join(directory, "source-one")), ...receiptSigningOptions, nonce: "quota-nonce-one", createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const second = await createReceipt({ runId: "quota-two", path: join(directory, "two.json"), envelope, verification, context, receiptStore: new FileReceiptStore(join(directory, "source-two")), ...receiptSigningOptions, nonce: "quota-nonce-two", createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const target = new FileReceiptStore(join(directory, "target"), { maxRecords: 1 });
    await target.issue(first);
    const transactionsBefore = await readdir(join(directory, "target", "transactions"));
    await expect(target.issue(second)).rejects.toThrow(/record limit/u);
    expect(await readdir(join(directory, "target", "transactions"))).toEqual(transactionsBefore);
    expect(() => new FileReceiptStore(join(directory, "bad"), { maxRecords: 0 })).toThrow(/maxRecords/u);
  });

  it("does not accumulate transaction intents across repeated quota-full attempts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-store-quota-growth-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const seed = await createReceipt({ runId: "quota-seed", path: join(directory, "seed.json"), envelope, verification, context, receiptStore: new FileReceiptStore(join(directory, "seed-store")), ...receiptSigningOptions, nonce: "quota-seed-nonce", createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const storePath = join(directory, "target");
    const target = new FileReceiptStore(storePath, { maxRecords: 1 });
    await target.issue(seed);
    const stateCounts = async () => Object.fromEntries(await Promise.all(["transactions", "quota", "runs", "nonces", "issued", "cleanup", ".staging"].map(async (name) => [name, (await readdir(join(storePath, name))).length])));
    const before = await stateCounts();
    for (let index = 0; index < 12; index += 1) {
      const candidate = {
        ...seed,
        runId: `failed-run-${index}`,
        nonce: `failed-nonce-${index}`,
        receiptDigest: createHash("sha256").update(`failed-receipt-${index}`).digest("hex"),
      };
      await expect(target.issue(candidate)).rejects.toThrow(/record limit/u);
    }
    expect(await stateCounts()).toEqual(before);
  });

  it("retains issuance when the receipt parent is a file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-parent-file-"));
    const parent = join(directory, "not-a-directory");
    await writeFile(parent, "file");
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const base = { runId: "parent-file", envelope, verification, context, receiptStore, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") };
    await expect(createReceipt({ ...base, path: join(parent, "receipt.json") })).rejects.toThrow(/was issued/u);
    const [issuedName] = await readdir(join(directory, "store", "issued"));
    await expect(receiptStore.completeReceiptFile(issuedName!.replace(/\.json$/u, ""), join(directory, "retry.json"))).resolves.toMatchObject({ runId: "parent-file" });
    await expect(createReceipt({ ...base, path: join(directory, "other.json") })).rejects.toThrow(/transaction.*exists/u);
  });

  it("does not let recovery race a live issuer paused before commit", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-live-issuer-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const seed = await createReceipt({ runId: "live-race", path: join(directory, "seed.json"), envelope, verification, context, receiptStore: new FileReceiptStore(join(directory, "seed-store")), ...receiptSigningOptions, nonce: "live-race-nonce", createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    let release!: () => void;
    const paused = new Promise<void>((resolve) => { release = resolve; });
    let reached!: () => void;
    const atPause = new Promise<void>((resolve) => { reached = resolve; });
    const store = new FileReceiptStore(join(directory, "target"), { faultInjector: async (point) => { if (point === "issue:before-issued") { reached(); await paused; } } });
    const issuing = store.issue(seed);
    await atPause;
    const transactionName = createHash("sha256").update(seed.receiptDigest).digest("hex");
    const transaction = JSON.parse(await readFile(join(directory, "target", "transactions", `${transactionName}.json`), "utf8"));
    await expect(new FileReceiptStore(join(directory, "target")).recoverInterruptedIssue(seed, { offlineExclusive: true, transactionId: transaction.transactionId })).rejects.toThrow(/store is locked/u);
    await expect(new FileReceiptStore(join(directory, "target")).issue(seed)).rejects.toThrow(/store is locked/u);
    release();
    await expect(issuing).resolves.toBeUndefined();
  });

  it("publishes only complete records and fails closed at injected boundaries", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-publish-fault-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "fault-record", path: join(directory, "seed.json"), envelope, verification, context, receiptStore: new FileReceiptStore(join(directory, "seed-store")), ...receiptSigningOptions, nonce: "fault-record-nonce", createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const targetPath = join(directory, "target");
    const fault = new FileReceiptStore(targetPath, { faultInjector: (point) => { if (point === "run:after-temp-sync") throw new Error("injected crash"); } });
    await expect(fault.issue(receipt)).rejects.toThrow(/injected crash/u);
    expect(await import("node:fs/promises").then(({ readdir }) => readdir(join(targetPath, ".staging")))).toEqual([]);
    await expect(new FileReceiptStore(targetPath).issue(receipt)).resolves.toBeUndefined();
    const consumeFault = new FileReceiptStore(targetPath, { faultInjector: (point) => { if (point === "consumed:after-temp-sync") throw new Error("consume crash"); } });
    await expect(consumeFault.consume(receipt, new Date("2026-08-02T00:30:00.000Z"))).rejects.toThrow(/consume crash/u);
    await expect(new FileReceiptStore(targetPath).consume(receipt, new Date("2026-08-02T00:31:00.000Z"))).resolves.toBeUndefined();

    const postPublishPath = join(directory, "post-publish");
    await new FileReceiptStore(postPublishPath).issue(receipt);
    const afterPublish = new FileReceiptStore(postPublishPath, { faultInjector: (point) => { if (point === "consumed:after-publish") throw new Error("post-publish crash"); } });
    await expect(afterPublish.consume(receipt, new Date("2026-08-02T00:32:00.000Z"))).rejects.toThrow(/post-publish crash/u);
    await expect(new FileReceiptStore(postPublishPath).consume(receipt, new Date("2026-08-02T00:33:00.000Z"))).rejects.toThrow(/already been consumed/u);

    const abandoned = join(targetPath, ".staging", ".integrity-abandoned.tmp");
    await writeFile(abandoned, "{partial");
    await expect(new FileReceiptStore(targetPath).cleanupStaging(undefined as never)).rejects.toThrow(/offlineExclusive/u);
    await expect(new FileReceiptStore(targetPath).cleanupStaging({ offlineExclusive: true })).resolves.toBe(1);
    await expect(readFile(abandoned)).rejects.toThrow();

    const orphanPath = join(directory, "quota-orphan");
    const quotaFault = new FileReceiptStore(orphanPath, { faultInjector: (point) => { if (point === "quota:after-publish") throw new Error("quota crash"); } });
    await expect(quotaFault.issue(receipt)).rejects.toThrow(/quota reservation failed/u);
    const transactionName = createHash("sha256").update(receipt.receiptDigest).digest("hex");
    const transaction = JSON.parse(await readFile(join(orphanPath, "transactions", `${transactionName}.json`), "utf8"));
    expect(await readdir(join(orphanPath, "quota"))).toHaveLength(1);
    await new FileReceiptStore(orphanPath).recoverInterruptedIssue(receipt, { offlineExclusive: true, transactionId: transaction.transactionId });
    expect(await readdir(join(orphanPath, "transactions"))).toEqual([]);
    expect(await readdir(join(orphanPath, "quota"))).toEqual([]);
    await expect(new FileReceiptStore(orphanPath, { maxRecords: 1 }).issue(receipt)).resolves.toBeUndefined();
  });

  it("removes pre-publication quota intent and permits an immediate retry", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-quota-prepublish-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "quota-prepublish", path: join(directory, "seed.json"), envelope, verification, context, receiptStore: new FileReceiptStore(join(directory, "seed-store")), ...receiptSigningOptions, nonce: "quota-prepublish-nonce", createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const targetPath = join(directory, "target");
    const faulty = new FileReceiptStore(targetPath, { faultInjector: (point) => { if (point === "quota:after-temp-sync") throw new Error("quota prepublication crash"); } });
    await expect(faulty.issue(receipt)).rejects.toThrow(/quota reservation failed/u);
    expect(await readdir(join(targetPath, "transactions"))).toEqual([]);
    expect(await readdir(join(targetPath, "quota"))).toEqual([]);
    expect(await readdir(join(targetPath, "cleanup"))).toEqual([]);
    await expect(new FileReceiptStore(targetPath).issue(receipt)).resolves.toBeUndefined();
  });

  it.each(["cleanup:after-ownership-read", "cleanup:after-removal"])("resumes durable cleanup journal after %s fault", async (faultPoint) => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-cleanup-journal-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: `cleanup-${faultPoint.endsWith("read") ? "read" : "remove"}`, path: join(directory, "seed.json"), envelope, verification, context, receiptStore: new FileReceiptStore(join(directory, "seed-store")), ...receiptSigningOptions, nonce: `nonce-${faultPoint.endsWith("read") ? "read" : "remove"}`, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const targetPath = join(directory, "target");
    await new FileReceiptStore(targetPath).issue(receipt);
    let fired = false;
    const faulty = new FileReceiptStore(targetPath, { faultInjector: (point) => { if (!fired && point === faultPoint) { fired = true; throw new Error("cleanup crash"); } } });
    await expect(faulty.rollbackIssue(receipt.receiptDigest)).rejects.toThrow(/cleanup crash/u);
    await expect(new FileReceiptStore(targetPath).reconcileCleanup(receipt.receiptDigest)).resolves.toBeUndefined();
    await expect(new FileReceiptStore(targetPath).issue(receipt)).resolves.toBeUndefined();
  });
});
