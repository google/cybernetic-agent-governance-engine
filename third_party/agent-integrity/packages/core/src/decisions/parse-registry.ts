import type { DecisionEvent } from "@agent-integrity/protocol";
import { isAlias, isMap, isScalar, isSeq, parseDocument, type Node } from "yaml";
import { reduceDecisions } from "./reduce-decisions.js";

export interface DecisionRegistry {
  readonly version: 1;
  readonly events: readonly DecisionEvent[];
}

function rejectUnsafeNodes(node: Node | null | undefined): void {
  if (!node) return;
  if (isAlias(node)) throw new Error("YAML aliases are not supported");
  if (node.tag && !node.tag.startsWith("tag:yaml.org,2002:")) throw new Error(`Custom YAML tag is not supported: ${node.tag}`);
  if (isMap(node)) for (const pair of node.items) { rejectUnsafeNodes(pair.key as Node | null); rejectUnsafeNodes(pair.value as Node | null); }
  else if (isSeq(node)) for (const item of node.items) rejectUnsafeNodes(item as Node | null);
  else if (!isScalar(node)) throw new Error("Unsupported YAML node");
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${path} must be a mapping`);
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, keys: readonly string[], path: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${path} must contain exactly: ${expected.join(", ")}`);
  }
}

function identifier(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${path} must be a non-empty string`);
  return value;
}

export function parseDecisionRegistry(input: string): DecisionRegistry {
  const document = parseDocument(input, { schema: "core", strict: true, uniqueKeys: true });
  if (document.errors.length > 0) throw new Error(`Invalid YAML decision registry: ${document.errors.map((error) => error.message).join("; ")}`);
  if (document.warnings.length > 0) throw new Error(`Unsafe YAML decision registry: ${document.warnings.map((warning) => warning.message).join("; ")}`);
  rejectUnsafeNodes(document.contents);
  const root = record(document.toJS({ maxAliasCount: 0 }), "decision registry");
  exact(root, ["version", "events"], "decision registry");
  if (root.version !== 1) throw new Error("decision registry.version must be 1");
  if (!Array.isArray(root.events)) throw new Error("decision registry.events must be a list");
  if (root.events.length > 10_000) throw new Error("decision registry.events exceeds 10000 items");
  const events = root.events.map((entry, index): DecisionEvent => {
    const event = record(entry, `decision registry.events[${index}]`);
    const action = event.action;
    const keys = action === "supersede" ? ["eventId", "decisionId", "revision", "action", "supersededBy"] : ["eventId", "decisionId", "revision", "action"];
    exact(event, keys, `decision registry.events[${index}]`);
    if (action !== "activate" && action !== "reject" && action !== "supersede") throw new Error(`decision registry.events[${index}].action is invalid`);
    if (!Number.isSafeInteger(event.revision) || (event.revision as number) < 1) throw new Error(`decision registry.events[${index}].revision is invalid`);
    return {
      eventId: identifier(event.eventId, `decision registry.events[${index}].eventId`),
      decisionId: identifier(event.decisionId, `decision registry.events[${index}].decisionId`),
      revision: event.revision as number,
      action,
      ...(action === "supersede" ? { supersededBy: identifier(event.supersededBy, `decision registry.events[${index}].supersededBy`) } : {}),
    };
  });
  const nextRevision = new Map<string, number>();
  for (const event of events) {
    const expected = nextRevision.get(event.decisionId) ?? 1;
    if (event.revision !== expected) {
      throw new Error(
        `decision ${event.decisionId} violates append order: expected revision ${expected}, received ${event.revision}`,
      );
    }
    nextRevision.set(event.decisionId, expected + 1);
  }
  reduceDecisions(events);
  return { version: 1, events };
}
