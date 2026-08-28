import { sign } from "node:crypto";
import { dirname, join } from "node:path";
import {
  PROTOCOL_VERSION,
  type AlphaIntegrityReceipt,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
} from "@agent-integrity/protocol";
import { canonicalJson } from "../canonical-json.js";
import { sha256Canonical } from "../hash.js";
import { verifyTrustedEnvelope, type TrustedVerificationContext } from "../verify-trusted.js";
import { FileReceiptStore } from "./file-receipt-store.js";

const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

export interface CreateReceiptOptions {
  readonly runId: string;
  readonly path: string;
  readonly envelope: IntegrityEnvelope;
  readonly verification: EnvelopeVerificationResult;
  readonly context: TrustedVerificationContext;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly runRegistryDirectory?: string;
  readonly receiptStore?: FileReceiptStore;
  readonly signer: {
    readonly keyId: string;
    readonly privateKey: string;
    readonly issuer: string;
  };
  readonly audience: string;
  readonly purpose: string;
  readonly nonce: string;
  readonly engineVersion: string;
  readonly maxLifetimeMs?: number;
}

function isoDate(value: Date, name: string): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`${name} must be a valid Date`);
  }
  return value.toISOString();
}

export async function createReceipt(options: CreateReceiptOptions): Promise<AlphaIntegrityReceipt> {
  if (!RUN_ID.test(options.runId)) {
    throw new Error("runId must be 1-128 safe identifier characters");
  }
  const createdAt = isoDate(options.createdAt, "createdAt");
  const expiresAt = isoDate(options.expiresAt, "expiresAt");
  if (options.expiresAt.getTime() <= options.createdAt.getTime()) {
    throw new Error("expiresAt must be later than createdAt");
  }
  const maxLifetimeMs = options.maxLifetimeMs ?? 3_600_000;
  if (options.expiresAt.getTime() - options.createdAt.getTime() > maxLifetimeMs) {
    throw new Error("receipt lifetime exceeds configured maximum");
  }
  for (const [name, value] of Object.entries({ keyId: options.signer.keyId, issuer: options.signer.issuer, audience: options.audience, purpose: options.purpose, nonce: options.nonce, engineVersion: options.engineVersion })) {
    if (typeof value !== "string" || value.length < 1 || value.length > 256) throw new Error(`${name} must be 1-256 characters`);
  }

  const liveVerification = await verifyTrustedEnvelope(options.envelope, options.context);
  if (liveVerification.envelopeDigest === undefined) {
    throw new Error("cannot create a receipt for a malformed envelope");
  }
  if (sha256Canonical(liveVerification) !== sha256Canonical(options.verification)) {
    throw new Error("verification does not match the supplied envelope");
  }

  const body = {
    protocolVersion: PROTOCOL_VERSION,
    receiptVersion: "2-alpha" as const,
    engineVersion: options.engineVersion,
    issuer: options.signer.issuer,
    audience: options.audience,
    purpose: options.purpose,
    nonce: options.nonce,
    runId: options.runId,
    createdAt,
    expiresAt,
    policyDigest: sha256Canonical(options.envelope.policy),
    envelopeDigest: liveVerification.envelopeDigest,
    verification: {
      protocolVersion: liveVerification.protocolVersion,
      status: liveVerification.status,
      findings: liveVerification.findings,
    },
  };
  const protectedSignature = {
    algorithm: "Ed25519" as const,
    keyId: options.signer.keyId,
  };
  const signature = {
    ...protectedSignature,
    value: sign(null, Buffer.from(canonicalJson({ protected: protectedSignature, body }), "utf8"), options.signer.privateKey).toString("base64"),
  };
  const signed = { ...body, signature };
  const receipt: AlphaIntegrityReceipt = { ...signed, receiptDigest: sha256Canonical(signed) };

  const registryDirectory = options.runRegistryDirectory ?? join(dirname(options.path), ".integrity-receipts");
  const store = options.receiptStore ?? new FileReceiptStore(registryDirectory);
  await store.issue(receipt);

  try {
    await store.completeReceiptFile(receipt.receiptDigest, options.path);
  } catch (error) {
    throw new Error(`receipt was issued but output completion failed; recover it with completeReceiptFile: ${error instanceof Error ? error.message : "unknown failure"}`);
  }
  return receipt;
}
