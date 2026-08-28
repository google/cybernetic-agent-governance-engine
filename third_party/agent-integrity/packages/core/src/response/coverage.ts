import { createHash } from "node:crypto";
import type { ResponseDocument } from "@agent-integrity/protocol";

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function utf8Boundaries(content: string): Set<number> {
  const boundaries = new Set<number>([0]);
  let offset = 0;
  for (const codePoint of content) {
    offset += Buffer.byteLength(codePoint, "utf8");
    boundaries.add(offset);
  }
  return boundaries;
}

/** Validates that ordered sections partition every response UTF-8 byte exactly once. */
export function assertCompleteResponseCoverage(response: ResponseDocument): void {
  const bytes = Buffer.from(response.content, "utf8");
  if (bytes.length > 0 && response.sections.length === 0) {
    throw new Error("non-empty response requires at least one section");
  }
  if (bytes.length === 0 && response.sections.length > 0) {
    throw new Error("empty response must not contain sections");
  }

  const boundaries = utf8Boundaries(response.content);
  let cursor = 0;
  for (const [index, section] of response.sections.entries()) {
    if (section.byteStart !== cursor) {
      throw new Error(`response.sections[${index}] must start at byte ${cursor}`);
    }
    if (section.byteEnd <= section.byteStart || section.byteEnd > bytes.length) {
      throw new Error(`response.sections[${index}] has an invalid byte range`);
    }
    if (!boundaries.has(section.byteStart) || !boundaries.has(section.byteEnd)) {
      throw new Error(`response.sections[${index}] splits a UTF-8 code point`);
    }
    const actual = sha256(bytes.subarray(section.byteStart, section.byteEnd));
    if (actual !== section.sha256) {
      throw new Error(`response.sections[${index}].sha256 does not match exact response bytes`);
    }
    cursor = section.byteEnd;
  }
  if (cursor !== bytes.length) throw new Error(`response sections end at byte ${cursor}, expected ${bytes.length}`);
}
