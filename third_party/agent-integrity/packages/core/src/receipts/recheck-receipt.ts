import {
  PROTOCOL_VERSION,
  type AlphaIntegrityReceipt,
  type IntegrityEnvelope,
  type IntegrityFinding,
  type IntegrityPolicy,
  type ReceiptRecheckResult,
} from "@agent-integrity/protocol";
import { verify as verifySignature } from "node:crypto";
import { canonicalJson } from "../canonical-json.js";
import { sha256Canonical } from "../hash.js";
import { calculateOutcome, checkerFailure } from "../outcome.js";
import { verifyEnvelope } from "../verify.js";
import { verifyTrustedEnvelope, type TrustedVerificationContext } from "../verify-trusted.js";
import { FileReceiptStore } from "./file-receipt-store.js";

export interface RecheckReceiptOptions {
  readonly receipt: AlphaIntegrityReceipt;
  readonly envelope: IntegrityEnvelope;
  readonly now: Date;
  readonly trust: {
    readonly keys: Readonly<Record<string, string>>;
    readonly revokedKeyIds?: readonly string[];
    readonly issuer: string;
    readonly audience: string;
    readonly purpose: string;
    readonly engineVersion: string;
    /** Policy loaded independently of the envelope and receipt. */
    readonly trustedPolicy: IntegrityPolicy;
    readonly maxClockSkewMs?: number;
    readonly maxLifetimeMs?: number;
  };
}

function receiptBody(receipt: AlphaIntegrityReceipt): Omit<AlphaIntegrityReceipt, "receiptDigest"> {
  const { receiptDigest: _receiptDigest, ...body } = receipt;
  return body;
}

function unsignedBody(receipt: AlphaIntegrityReceipt): Omit<AlphaIntegrityReceipt, "receiptDigest" | "signature"> {
  const { receiptDigest: _receiptDigest, signature: _signature, ...body } = receipt;
  return body;
}

function signaturePayload(receipt: AlphaIntegrityReceipt): unknown {
  return {
    protected: { algorithm: receipt.signature.algorithm, keyId: receipt.signature.keyId },
    body: unsignedBody(receipt),
  };
}

function blocked(code: string, message: string): IntegrityFinding {
  return { code, severity: "blocked", message, path: "receipt" };
}

function canonicalEd25519Signature(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9+/]{86}==$/u.test(value)) return undefined;
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== 64 || decoded.toString("base64") !== value) return undefined;
  return decoded;
}

function recheckUnsafe(options: RecheckReceiptOptions): ReceiptRecheckResult {
  const { receipt, envelope, now } = options;
  if (receipt === null || typeof receipt !== "object") throw new Error("receipt must be an object");
  if (receipt.protocolVersion !== PROTOCOL_VERSION || receipt.receiptVersion !== "2-alpha") {
    throw new Error("unsupported receipt version");
  }
  if (receipt.signature?.algorithm !== "Ed25519" || typeof receipt.signature.keyId !== "string" || typeof receipt.signature.value !== "string") throw new Error("invalid signed receipt");
  const signatureBytes = canonicalEd25519Signature(receipt.signature.value);
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("now must be a valid Date");

  const findings: IntegrityFinding[] = [];
  const calculatedReceiptDigest = sha256Canonical(receiptBody(receipt));
  if (calculatedReceiptDigest !== receipt.receiptDigest) {
    findings.push(blocked("receipt.mutated", "Receipt content changed after creation"));
  }
  const key = options.trust.keys[receipt.signature.keyId];
  if (options.trust.revokedKeyIds?.includes(receipt.signature.keyId)) {
    findings.push(blocked("receipt.key_revoked", "Receipt signing key is revoked"));
  } else if (key === undefined) {
    findings.push(blocked("receipt.unknown_key", "Receipt signing key is not trusted"));
  } else if (signatureBytes === undefined) {
    findings.push(blocked("receipt.invalid_signature_encoding", "Receipt signature must be canonical base64 encoding of exactly 64 bytes"));
  } else {
    let valid = false;
    try {
      valid = verifySignature(null, Buffer.from(canonicalJson(signaturePayload(receipt)), "utf8"), key, signatureBytes);
    } catch { valid = false; }
    if (!valid) findings.push(blocked("receipt.invalid_signature", "Receipt signature is invalid"));
  }
  if (receipt.issuer !== options.trust.issuer) findings.push(blocked("receipt.wrong_issuer", "Receipt issuer does not match"));
  if (receipt.audience !== options.trust.audience) findings.push(blocked("receipt.wrong_audience", "Receipt audience does not match"));
  if (receipt.purpose !== options.trust.purpose) findings.push(blocked("receipt.wrong_purpose", "Receipt purpose does not match"));
  if (receipt.engineVersion !== options.trust.engineVersion) findings.push(blocked("receipt.wrong_engine", "Receipt engine version does not match"));
  const trustedPolicyDigest = sha256Canonical(options.trust.trustedPolicy);
  if (trustedPolicyDigest !== sha256Canonical(envelope.policy)) findings.push(blocked("receipt.policy_downgrade", "Envelope policy does not match the separately trusted policy"));
  if (receipt.policyDigest !== trustedPolicyDigest) findings.push(blocked("receipt.policy_changed", "Receipt policy does not match the separately trusted policy"));
  const expiresAt = Date.parse(receipt.expiresAt);
  const createdAt = Date.parse(receipt.createdAt);
  const maxClockSkewMs = options.trust.maxClockSkewMs ?? 60_000;
  const maxLifetimeMs = options.trust.maxLifetimeMs ?? 3_600_000;
  if (!Number.isFinite(expiresAt) || !Number.isFinite(createdAt) || expiresAt <= createdAt) {
    findings.push(blocked("receipt.invalid_time", "Receipt timestamps are invalid"));
  } else if (createdAt > now.getTime() + maxClockSkewMs) {
    findings.push(blocked("receipt.future_issued", "Receipt creation time is too far in the future"));
  } else if (expiresAt - createdAt > maxLifetimeMs) {
    findings.push(blocked("receipt.lifetime_exceeded", "Receipt lifetime exceeds configured maximum"));
  } else if (now.getTime() >= expiresAt) {
    findings.push(blocked("receipt.expired", "Receipt has expired"));
  }

  const liveVerification = verifyEnvelope(envelope);
  if (liveVerification.envelopeDigest === undefined) {
    findings.push(blocked("receipt.live_check_failed", "Live envelope could not be verified"));
  } else if (liveVerification.envelopeDigest !== receipt.envelopeDigest) {
    findings.push(blocked("receipt.subject_changed", "Response or another bound subject changed"));
  }
  if (liveVerification.envelopeDigest === receipt.envelopeDigest &&
      (liveVerification.status !== receipt.verification.status ||
       sha256Canonical(liveVerification.findings) !== sha256Canonical(receipt.verification.findings))) {
    findings.push(blocked("receipt.outcome_changed", "Verification outcome no longer matches the receipt"));
  }

  const outcome = calculateOutcome([...receipt.verification.findings, ...findings]);
  return {
    ...outcome,
    receiptDigest: calculatedReceiptDigest,
    ...(liveVerification.envelopeDigest === undefined
      ? {}
      : { envelopeDigest: liveVerification.envelopeDigest }),
  };
}

export function recheckReceipt(options: RecheckReceiptOptions): ReceiptRecheckResult {
  try {
    return recheckUnsafe(options);
  } catch (error) {
    return checkerFailure(error);
  }
}

export interface RecheckTrustedReceiptOptions extends RecheckReceiptOptions {
  readonly context: TrustedVerificationContext;
  readonly receiptStore?: FileReceiptStore;
}

/** Rechecks the receipt against freshly recollected source bytes. */
export async function recheckTrustedReceipt(options: RecheckTrustedReceiptOptions): Promise<ReceiptRecheckResult> {
  try {
    const baseline = recheckUnsafe(options);
    const live = await verifyTrustedEnvelope(options.envelope, options.context);
    const findings = [...baseline.findings];
    if (live.status !== "PASS") findings.push(...live.findings);
    if (live.envelopeDigest === undefined) {
      findings.push(blocked("receipt.live_source_check_failed", "Trusted source verification did not produce an envelope digest"));
    }
    const result = {
      ...calculateOutcome(findings),
      ...(baseline.receiptDigest === undefined ? {} : { receiptDigest: baseline.receiptDigest }),
      ...(live.envelopeDigest === undefined ? {} : { envelopeDigest: live.envelopeDigest }),
    };
    if (result.status === "PASS") {
      if (options.receiptStore === undefined) {
        return { ...calculateOutcome([...findings, blocked("receipt.store_required", "A trusted receipt store is required for single-use consumption")]), ...(baseline.receiptDigest === undefined ? {} : { receiptDigest: baseline.receiptDigest }), ...(live.envelopeDigest === undefined ? {} : { envelopeDigest: live.envelopeDigest }) };
      }
      try {
        await options.receiptStore.consume(options.receipt, options.now);
      } catch (error) {
        return { ...calculateOutcome([...findings, blocked("receipt.replayed", error instanceof Error ? error.message : "Receipt consumption failed")]), ...(baseline.receiptDigest === undefined ? {} : { receiptDigest: baseline.receiptDigest }), ...(live.envelopeDigest === undefined ? {} : { envelopeDigest: live.envelopeDigest }) };
      }
    }
    return result;
  } catch (error) {
    return checkerFailure(error);
  }
}
