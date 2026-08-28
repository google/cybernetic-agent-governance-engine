import {
  PROTOCOL_VERSION,
  type IntegrityEnvelope,
} from "@agent-integrity/protocol";

const MAX_ITEMS = 10_000;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;

function record(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw new Error(`${path} must be a plain object`);
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, keys: readonly string[], path: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${path} must contain exactly: ${expected.join(", ")}`);
  }
}

function list(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be a list`);
  if (value.length > MAX_ITEMS) throw new Error(`${path} exceeds ${MAX_ITEMS} items`);
  return value;
}

function string(value: unknown, path: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.trim() === "")) {
    throw new Error(`${path} must be ${allowEmpty ? "a string" : "a non-empty string"}`);
  }
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], path: string): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} is unsupported`);
  }
  return value as T;
}

function validatePolicy(value: unknown): void {
  const policy = record(value, "policy");
  exact(policy, ["version", "sources", "decisions", "rules"], "policy");
  if (policy.version !== 1) throw new Error("policy.version must be 1");
  const sources = record(policy.sources, "policy.sources");
  exact(sources, ["allowedRoots"], "policy.sources");
  const roots = list(sources.allowedRoots, "policy.sources.allowedRoots");
  if (roots.length === 0) throw new Error("policy.sources.allowedRoots must not be empty");
  const normalizedRoots = roots.map((root, index) => string(root, `policy.sources.allowedRoots[${index}]`));
  if (new Set(normalizedRoots).size !== normalizedRoots.length) throw new Error("duplicate allowed root");
  const decisions = record(policy.decisions, "policy.decisions");
  exact(decisions, ["path"], "policy.decisions");
  if (!/\.ya?ml$/u.test(string(decisions.path, "policy.decisions.path"))) {
    throw new Error("policy.decisions.path must point to YAML");
  }
  const rules = record(policy.rules, "policy.rules");
  exact(rules, ["requireEvidenceFor", "contradictions", "rejectedDecisions", "responseMutation", "replay"], "policy.rules");
  const kinds = list(rules.requireEvidenceFor, "policy.rules.requireEvidenceFor");
  if (kinds.length === 0) throw new Error("policy.rules.requireEvidenceFor must not be empty");
  const normalizedKinds = kinds.map((kind, index) => oneOf(kind, ["factual", "recommendation"], `policy.rules.requireEvidenceFor[${index}]`));
  if (new Set(normalizedKinds).size !== normalizedKinds.length) throw new Error("duplicate required evidence kind");
  oneOf(rules.contradictions, ["review", "block"], "policy.rules.contradictions");
  for (const key of ["rejectedDecisions", "responseMutation", "replay"] as const) {
    if (rules[key] !== "block") throw new Error(`policy.rules.${key} must be block`);
  }
}

export function assertIntegrityEnvelope(value: unknown): asserts value is IntegrityEnvelope {
  const envelope = record(value, "envelope");
  exact(envelope, ["protocolVersion", "policy", "response", "sources", "decisionRegistryDigest", "decisions", "evidence", "claims"], "envelope");
  if (envelope.protocolVersion !== PROTOCOL_VERSION) throw new Error("unsupported protocol version");
  validatePolicy(envelope.policy);
  if (!SHA256.test(string(envelope.decisionRegistryDigest, "decisionRegistryDigest"))) throw new Error("decisionRegistryDigest is invalid");

  const response = record(envelope.response, "response");
  exact(response, ["content", "sections"], "response");
  const content = string(response.content, "response.content", true);
  if (Buffer.byteLength(content, "utf8") > MAX_CONTENT_BYTES) throw new Error("response.content is too large");
  list(response.sections, "response.sections").forEach((entry, index) => {
    const section = record(entry, `response.sections[${index}]`);
    exact(section, ["sectionId", "substantive", "byteStart", "byteEnd", "sha256"], `response.sections[${index}]`);
    string(section.sectionId, `response.sections[${index}].sectionId`);
    if (typeof section.substantive !== "boolean") throw new Error(`response.sections[${index}].substantive must be boolean`);
    for (const key of ["byteStart", "byteEnd"] as const) {
      if (!Number.isSafeInteger(section[key]) || (section[key] as number) < 0) {
        throw new Error(`response.sections[${index}].${key} must be a non-negative safe integer`);
      }
    }
    if (!SHA256.test(string(section.sha256, `response.sections[${index}].sha256`))) {
      throw new Error(`response.sections[${index}].sha256 is invalid`);
    }
  });

  list(envelope.sources, "sources").forEach((entry, index) => {
    const source = record(entry, `sources[${index}]`);
    exact(source, ["sourceId", "path", "sha256", "size"], `sources[${index}]`);
    string(source.sourceId, `sources[${index}].sourceId`);
    string(source.path, `sources[${index}].path`);
    if (!SHA256.test(string(source.sha256, `sources[${index}].sha256`))) throw new Error(`sources[${index}].sha256 is invalid`);
    if (!Number.isSafeInteger(source.size) || (source.size as number) < 0) throw new Error(`sources[${index}].size is invalid`);
  });

  list(envelope.decisions, "decisions").forEach((entry, index) => {
    const decision = record(entry, `decisions[${index}]`);
    const keys = decision.action === "supersede"
      ? ["eventId", "decisionId", "revision", "action", "supersededBy"]
      : ["eventId", "decisionId", "revision", "action"];
    exact(decision, keys, `decisions[${index}]`);
    string(decision.eventId, `decisions[${index}].eventId`);
    string(decision.decisionId, `decisions[${index}].decisionId`);
    if (!Number.isSafeInteger(decision.revision) || (decision.revision as number) < 1) throw new Error(`decisions[${index}].revision is invalid`);
    const action = oneOf(decision.action, ["activate", "reject", "supersede"], `decisions[${index}].action`);
    if (action === "supersede") string(decision.supersededBy, `decisions[${index}].supersededBy`);
  });

  list(envelope.evidence, "evidence").forEach((entry, index) => {
    const evidence = record(entry, `evidence[${index}]`);
    exact(evidence, ["evidenceId", "sourceId", ...(evidence.anchor === undefined ? [] : ["anchor"])], `evidence[${index}]`);
    string(evidence.evidenceId, `evidence[${index}].evidenceId`);
    string(evidence.sourceId, `evidence[${index}].sourceId`);
    if (evidence.anchor !== undefined) {
      const anchor = record(evidence.anchor, `evidence[${index}].anchor`);
      exact(anchor, ["byteStart", "byteEnd", "sha256"], `evidence[${index}].anchor`);
      for (const key of ["byteStart", "byteEnd"] as const) {
        if (!Number.isSafeInteger(anchor[key]) || (anchor[key] as number) < 0) {
          throw new Error(`evidence[${index}].anchor.${key} must be a non-negative safe integer`);
        }
      }
      if ((anchor.byteEnd as number) <= (anchor.byteStart as number)) {
        throw new Error(`evidence[${index}].anchor must contain at least one byte`);
      }
      if (!SHA256.test(string(anchor.sha256, `evidence[${index}].anchor.sha256`))) {
        throw new Error(`evidence[${index}].anchor.sha256 is invalid`);
      }
    }
  });

  list(envelope.claims, "claims").forEach((entry, index) => {
    const claim = record(entry, `claims[${index}]`);
    exact(claim, ["claimId", "sectionId", "kind", "decisionIds", "evidence"], `claims[${index}]`);
    string(claim.claimId, `claims[${index}].claimId`);
    string(claim.sectionId, `claims[${index}].sectionId`);
    oneOf(claim.kind, ["factual", "recommendation", "inference"], `claims[${index}].kind`);
    const decisionIds = list(claim.decisionIds, `claims[${index}].decisionIds`).map((value, decisionIndex) =>
      string(value, `claims[${index}].decisionIds[${decisionIndex}]`));
    if (new Set(decisionIds).size !== decisionIds.length) throw new Error(`claims[${index}].decisionIds contains duplicates`);
    list(claim.evidence, `claims[${index}].evidence`).forEach((entryValue, evidenceIndex) => {
      const link = record(entryValue, `claims[${index}].evidence[${evidenceIndex}]`);
      const keys = ["evidenceId", "role", ...(link.support === undefined ? [] : ["support"]), ...(link.disclosed === undefined ? [] : ["disclosed"])];
      exact(link, keys, `claims[${index}].evidence[${evidenceIndex}]`);
      string(link.evidenceId, `claims[${index}].evidence[${evidenceIndex}].evidenceId`);
      oneOf(link.role, ["supporting", "contradictory", "contextual"], `claims[${index}].evidence[${evidenceIndex}].role`);
      if (link.support !== undefined) oneOf(link.support, ["direct", "ambiguous"], `claims[${index}].evidence[${evidenceIndex}].support`);
      if (link.disclosed !== undefined && typeof link.disclosed !== "boolean") throw new Error(`claims[${index}].evidence[${evidenceIndex}].disclosed must be boolean`);
    });
  });
}
