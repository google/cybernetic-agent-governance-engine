import {
  PROTOCOL_VERSION,
  type EnvelopeVerificationResult,
  type IntegrityEnvelope,
  type IntegrityFinding,
  type SourceRecord,
} from "@agent-integrity/protocol";
import { validateClaims } from "./claims/coverage.js";
import { reduceDecisions } from "./decisions/reduce-decisions.js";
import { sha256Canonical } from "./hash.js";
import { calculateOutcome, checkerFailure } from "./outcome.js";
import { assertIntegrityEnvelope } from "./schema/validate-envelope.js";
import { assertCompleteResponseCoverage } from "./response/coverage.js";

const SHA256 = /^[a-f0-9]{64}$/u;

function validateSources(sources: readonly SourceRecord[]): void {
  const sourceIds = new Set<string>();
  const paths = new Set<string>();
  for (const [index, source] of sources.entries()) {
    if (typeof source.sourceId !== "string" || source.sourceId.trim() === "") {
      throw new Error(`sources[${index}].sourceId must be a non-empty string`);
    }
    if (sourceIds.has(source.sourceId)) throw new Error(`duplicate source ID: ${source.sourceId}`);
    sourceIds.add(source.sourceId);
    if (typeof source.path !== "string" || source.path.trim() === "") {
      throw new Error(`sources[${index}].path must be a non-empty string`);
    }
    if (paths.has(source.path)) throw new Error(`duplicate source path: ${source.path}`);
    paths.add(source.path);
    if (!SHA256.test(source.sha256)) throw new Error(`sources[${index}].sha256 is invalid`);
    if (!Number.isSafeInteger(source.size) || source.size < 0) {
      throw new Error(`sources[${index}].size must be a non-negative safe integer`);
    }
  }
}

function decisionFindings(envelope: IntegrityEnvelope): IntegrityFinding[] {
  const states = reduceDecisions(envelope.decisions);
  const byId = new Map(states.map((state) => [state.decisionId, state]));
  const referenced = new Set(envelope.claims.flatMap((claim) => claim.decisionIds));
  return [...referenced].sort().flatMap((decisionId) => {
    const state = byId.get(decisionId);
    if (state?.status === "active") return [];
    return [{
      code: state === undefined ? "decision.unknown" : `decision.${state.status}`,
      severity: "blocked" as const,
      message: state === undefined ? `Decision ${decisionId} does not exist` : `Decision ${decisionId} is ${state.status}`,
      path: "claims",
    }];
  });
}

function verifyUnsafe(envelope: IntegrityEnvelope): EnvelopeVerificationResult {
  assertIntegrityEnvelope(envelope);
  assertCompleteResponseCoverage(envelope.response);
  validateSources(envelope.sources);
  const sourceIds = new Set(envelope.sources.map((source) => source.sourceId));
  for (const [index, evidence] of envelope.evidence.entries()) {
    if (!sourceIds.has(evidence.sourceId)) {
      throw new Error(`evidence[${index}] references unknown source: ${evidence.sourceId}`);
    }
  }

  const findings = [
    ...decisionFindings(envelope),
    ...validateClaims({
      sections: envelope.response.sections,
      claims: envelope.claims,
      evidence: envelope.evidence,
      requiredEvidenceFor: envelope.policy.rules.requireEvidenceFor,
      contradictions: envelope.policy.rules.contradictions,
    }),
  ];
  return { ...calculateOutcome(findings), envelopeDigest: sha256Canonical(envelope) };
}

export function verifyEnvelope(envelope: IntegrityEnvelope): EnvelopeVerificationResult {
  try {
    return verifyUnsafe(envelope);
  } catch (error) {
    return checkerFailure(error);
  }
}
