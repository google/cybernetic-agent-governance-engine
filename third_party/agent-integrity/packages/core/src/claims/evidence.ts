import type {
  ClaimEvidence,
  EvidenceItem,
  IntegrityClaim,
} from "@agent-integrity/protocol";

function assertIdentifier(value: string, path: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${path} must be a non-empty string`);
  }
}

export function indexEvidence(items: readonly EvidenceItem[]): ReadonlyMap<string, EvidenceItem> {
  const indexed = new Map<string, EvidenceItem>();
  for (const [index, item] of items.entries()) {
    assertIdentifier(item.evidenceId, `evidence[${index}].evidenceId`);
    assertIdentifier(item.sourceId, `evidence[${index}].sourceId`);
    if (indexed.has(item.evidenceId)) {
      throw new Error(`duplicate evidence ID: ${item.evidenceId}`);
    }
    indexed.set(item.evidenceId, item);
  }
  return indexed;
}

export function validateEvidenceLinks(
  claim: IntegrityClaim,
  claimIndex: number,
  knownEvidence: ReadonlyMap<string, EvidenceItem>,
): void {
  const linked = new Set<string>();
  for (const [linkIndex, link] of claim.evidence.entries()) {
    const path = `claims[${claimIndex}].evidence[${linkIndex}]`;
    assertIdentifier(link.evidenceId, `${path}.evidenceId`);
    if (!knownEvidence.has(link.evidenceId)) {
      throw new Error(`${path} references unknown evidence: ${link.evidenceId}`);
    }
    if (linked.has(link.evidenceId)) {
      throw new Error(`claim ${claim.claimId} has duplicate evidence link: ${link.evidenceId}`);
    }
    linked.add(link.evidenceId);
    validateRoleMetadata(link, path);
  }
}

function validateRoleMetadata(link: ClaimEvidence, path: string): void {
  if (!("supporting contradictory contextual".split(" ") as string[]).includes(link.role)) {
    throw new Error(`${path}.role is invalid`);
  }
  if (link.role === "supporting") {
    if (link.support !== undefined && link.support !== "direct" && link.support !== "ambiguous") {
      throw new Error(`${path}.support is invalid`);
    }
    if (link.disclosed !== undefined) {
      throw new Error(`${path}.disclosed is only valid for contradictory evidence`);
    }
    return;
  }
  if (link.support !== undefined) {
    throw new Error(`${path}.support is only valid for supporting evidence`);
  }
  if (link.role === "contextual" && link.disclosed !== undefined) {
    throw new Error(`${path}.disclosed is only valid for contradictory evidence`);
  }
}
