export const PROTOCOL_VERSION = "1-alpha" as const;

export type IntegrityStatus = "PASS" | "REVIEW" | "BLOCKED";
export type FindingSeverity = "review" | "blocked";

export interface IntegrityFinding {
  readonly code: string;
  readonly severity: FindingSeverity;
  readonly message: string;
  readonly path?: string;
}

export interface IntegrityResult {
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly status: IntegrityStatus;
  readonly findings: readonly IntegrityFinding[];
}

export interface SourceRecord {
  readonly sourceId: string;
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface ResponseDocument {
  readonly content: string;
  readonly sections: readonly ResponseSection[];
}

export interface IntegrityEnvelope {
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly policy: import("./policy.js").IntegrityPolicy;
  readonly response: ResponseDocument;
  readonly sources: readonly SourceRecord[];
  /** SHA-256 of the exact trusted decision registry YAML bytes. */
  readonly decisionRegistryDigest: string;
  readonly decisions: readonly DecisionEvent[];
  readonly evidence: readonly EvidenceItem[];
  readonly claims: readonly IntegrityClaim[];
}

export interface EnvelopeVerificationResult extends IntegrityResult {
  readonly envelopeDigest?: string;
}

export interface ReceiptSignature {
  readonly algorithm: "Ed25519";
  readonly keyId: string;
  readonly value: string;
}

export interface AlphaIntegrityReceipt {
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly receiptVersion: "2-alpha";
  readonly engineVersion: string;
  readonly issuer: string;
  readonly audience: string;
  readonly purpose: string;
  readonly nonce: string;
  readonly runId: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly policyDigest: string;
  readonly envelopeDigest: string;
  readonly verification: IntegrityResult;
  readonly signature: ReceiptSignature;
  readonly receiptDigest: string;
}

export interface ReceiptRecheckResult extends IntegrityResult {
  readonly receiptDigest?: string;
  readonly envelopeDigest?: string;
}

export type DecisionAction = "activate" | "reject" | "supersede";

export interface DecisionEvent {
  readonly eventId: string;
  readonly decisionId: string;
  readonly revision: number;
  readonly action: DecisionAction;
  readonly supersededBy?: string;
}

export type DecisionStatus = "active" | "rejected" | "superseded";

export interface DecisionState {
  readonly decisionId: string;
  readonly status: DecisionStatus;
  readonly revision: number;
  readonly supersededBy?: string;
}

export type ClaimKind = "factual" | "recommendation" | "inference";
export type EvidenceRole = "supporting" | "contradictory" | "contextual";
export type EvidenceSupport = "direct" | "ambiguous";

export interface ResponseSection {
  readonly sectionId: string;
  readonly substantive: boolean;
  /** Inclusive UTF-8 byte offset into ResponseDocument.content. */
  readonly byteStart: number;
  /** Exclusive UTF-8 byte offset into ResponseDocument.content. */
  readonly byteEnd: number;
  /** SHA-256 of the exact UTF-8 bytes in [byteStart, byteEnd). */
  readonly sha256: string;
}

export interface EvidenceItem {
  readonly evidenceId: string;
  readonly sourceId: string;
  /** Exact byte range in the referenced source. Required by trusted verification. */
  readonly anchor?: EvidenceAnchor;
}

export interface EvidenceAnchor {
  /** Inclusive byte offset into the source file. */
  readonly byteStart: number;
  /** Exclusive byte offset into the source file. */
  readonly byteEnd: number;
  /** SHA-256 of the exact source bytes in [byteStart, byteEnd). */
  readonly sha256: string;
}

export interface ClaimEvidence {
  readonly evidenceId: string;
  readonly role: EvidenceRole;
  readonly support?: EvidenceSupport;
  readonly disclosed?: boolean;
}

export interface IntegrityClaim {
  readonly claimId: string;
  readonly sectionId: string;
  readonly kind: ClaimKind;
  readonly decisionIds: readonly string[];
  readonly evidence: readonly ClaimEvidence[];
}
