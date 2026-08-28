import type { IntegrityPolicy } from "@agent-integrity/protocol";
import { isAlias, isMap, isScalar, isSeq, parseDocument, type Node } from "yaml";

const ROOT_KEYS = ["version", "sources", "decisions", "rules"] as const;
const RULE_KEYS = [
  "requireEvidenceFor",
  "contradictions",
  "rejectedDecisions",
  "responseMutation",
  "replay"
] as const;

function assertRecord(value: unknown, path: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be a mapping`);
  }
}

function assertExactKeys(value: Record<string, unknown>, keys: readonly string[], path: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${path} must contain exactly: ${expected.join(", ")}`);
  }
}

function assertNonEmptyString(value: unknown, path: string): asserts value is string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${path} must be a non-empty string`);
  }
}

function rejectUnsafeNodes(node: Node | null | undefined): void {
  if (!node) return;
  if (isAlias(node)) throw new Error("YAML aliases are not supported");
  if (node.tag && !node.tag.startsWith("tag:yaml.org,2002:")) {
    throw new Error(`Custom YAML tag is not supported: ${node.tag}`);
  }
  if (isMap(node)) {
    for (const pair of node.items) {
      rejectUnsafeNodes(pair.key as Node | null);
      rejectUnsafeNodes(pair.value as Node | null);
    }
  } else if (isSeq(node)) {
    for (const item of node.items) rejectUnsafeNodes(item as Node | null);
  } else if (!isScalar(node)) {
    throw new Error("Unsupported YAML node");
  }
}

export function parsePolicy(input: string): IntegrityPolicy {
  const document = parseDocument(input, {
    schema: "core",
    strict: true,
    uniqueKeys: true
  });
  if (document.errors.length > 0) {
    throw new Error(`Invalid YAML policy: ${document.errors.map((error) => error.message).join("; ")}`);
  }
  if (document.warnings.length > 0) {
    throw new Error(`Unsafe YAML policy: ${document.warnings.map((warning) => warning.message).join("; ")}`);
  }
  rejectUnsafeNodes(document.contents);

  const value: unknown = document.toJS({ maxAliasCount: 0 });
  assertRecord(value, "policy");
  assertExactKeys(value, ROOT_KEYS, "policy");
  if (value.version !== 1) throw new Error("policy.version must be 1");

  assertRecord(value.sources, "policy.sources");
  assertExactKeys(value.sources, ["allowedRoots"], "policy.sources");
  if (!Array.isArray(value.sources.allowedRoots) || value.sources.allowedRoots.length === 0) {
    throw new Error("policy.sources.allowedRoots must be a non-empty list");
  }
  const allowedRoots = value.sources.allowedRoots.map((root, index) => {
    assertNonEmptyString(root, `policy.sources.allowedRoots[${index}]`);
    return root;
  });
  if (new Set(allowedRoots).size !== allowedRoots.length) {
    throw new Error("policy.sources.allowedRoots must not contain duplicates");
  }

  assertRecord(value.decisions, "policy.decisions");
  assertExactKeys(value.decisions, ["path"], "policy.decisions");
  assertNonEmptyString(value.decisions.path, "policy.decisions.path");
  if (!/\.ya?ml$/u.test(value.decisions.path)) {
    throw new Error("policy.decisions.path must point to a YAML file");
  }

  assertRecord(value.rules, "policy.rules");
  assertExactKeys(value.rules, RULE_KEYS, "policy.rules");
  if (!Array.isArray(value.rules.requireEvidenceFor) || value.rules.requireEvidenceFor.length === 0) {
    throw new Error("policy.rules.requireEvidenceFor must be a non-empty list");
  }
  const requireEvidenceFor = value.rules.requireEvidenceFor.map((kind, index) => {
    if (kind !== "factual" && kind !== "recommendation") {
      throw new Error(`policy.rules.requireEvidenceFor[${index}] is unsupported`);
    }
    return kind;
  });
  if (new Set(requireEvidenceFor).size !== requireEvidenceFor.length) {
    throw new Error("policy.rules.requireEvidenceFor must not contain duplicates");
  }
  if (value.rules.contradictions !== "review" && value.rules.contradictions !== "block") {
    throw new Error("policy.rules.contradictions must be review or block");
  }
  for (const key of ["rejectedDecisions", "responseMutation", "replay"] as const) {
    if (value.rules[key] !== "block") throw new Error(`policy.rules.${key} must be block`);
  }

  return {
    version: 1,
    sources: { allowedRoots },
    decisions: { path: value.decisions.path },
    rules: {
      requireEvidenceFor,
      contradictions: value.rules.contradictions,
      rejectedDecisions: "block",
      responseMutation: "block",
      replay: "block"
    }
  };
}
