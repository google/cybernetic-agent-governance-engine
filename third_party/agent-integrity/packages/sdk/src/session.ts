import {
  PROTOCOL_VERSION,
  type DecisionEvent,
  type EvidenceItem,
  type IntegrityClaim,
  type IntegrityEnvelope,
  type IntegrityPolicy,
  type ResponseSection,
  type SourceRecord,
} from "@agent-integrity/protocol";

/** Collects one agent run into a protocol envelope without a per-run manifest. */
export class AgentIntegritySession {
  readonly #policy: IntegrityPolicy;
  readonly #decisionRegistryDigest: string;
  #response: { content: string; sections: readonly ResponseSection[] } | undefined;
  readonly #sources: SourceRecord[] = [];
  readonly #decisions: DecisionEvent[] = [];
  readonly #evidence: EvidenceItem[] = [];
  readonly #claims: IntegrityClaim[] = [];

  constructor(policy: IntegrityPolicy, decisionRegistryDigest: string) {
    this.#policy = structuredClone(policy);
    if (!/^[a-f0-9]{64}$/u.test(decisionRegistryDigest)) throw new Error("decisionRegistryDigest must be a SHA-256 digest");
    this.#decisionRegistryDigest = decisionRegistryDigest;
  }

  setResponse(content: string, sections: readonly ResponseSection[]): this {
    this.#response = { content, sections: structuredClone(sections) };
    return this;
  }

  addSource(source: SourceRecord): this {
    this.#sources.push(structuredClone(source));
    return this;
  }

  addDecision(decision: DecisionEvent): this {
    this.#decisions.push(structuredClone(decision));
    return this;
  }

  addEvidence(evidence: EvidenceItem): this {
    this.#evidence.push(structuredClone(evidence));
    return this;
  }

  addClaim(claim: IntegrityClaim): this {
    this.#claims.push(structuredClone(claim));
    return this;
  }

  buildEnvelope(): IntegrityEnvelope {
    if (this.#response === undefined) throw new Error("response has not been set");
    return structuredClone({
      protocolVersion: PROTOCOL_VERSION,
      policy: this.#policy,
      response: this.#response,
      sources: this.#sources,
      decisionRegistryDigest: this.#decisionRegistryDigest,
      decisions: this.#decisions,
      evidence: this.#evidence,
      claims: this.#claims,
    });
  }
}
