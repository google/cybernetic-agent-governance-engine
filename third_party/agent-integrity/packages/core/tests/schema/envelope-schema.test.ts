import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "../../src/index.js";
import { readFile } from "node:fs/promises";
import { validEnvelope as completeEnvelope } from "../support/valid-envelope.js";
import Ajv2020 from "ajv/dist/2020.js";
import { createHash } from "node:crypto";

async function schemaValidator() {
  const schema = JSON.parse(await readFile(new URL("../../../../schemas/integrity-envelope.schema.json", import.meta.url), "utf8"));
  return { schema, validate: new Ajv2020({ strict: true, strictRequired: false }).compile(schema) };
}

function validEnvelope(): Record<string, unknown> {
  return {
    protocolVersion: "1-alpha",
    policy: {
      version: 1,
      sources: { allowedRoots: ["sources"] },
      decisions: { path: "decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual"],
        contradictions: "block",
        rejectedDecisions: "block",
        responseMutation: "block",
        replay: "block",
      },
    },
    response: { content: "", sections: [] },
    sources: [],
    decisions: [],
    evidence: [],
    claims: [],
  };
}

describe("strict envelope runtime schema", () => {
  it("blocks unknown fields", () => {
    const envelope = validEnvelope();
    envelope.untrustedOverride = true;
    expect(verifyEnvelope(envelope as never)).toMatchObject({
      status: "BLOCKED",
      findings: [{ code: "checker.failure" }],
    });
  });

  it("blocks permissive or incomplete policy objects", () => {
    const envelope = validEnvelope();
    (envelope.policy as Record<string, unknown>).rules = {
      requireEvidenceFor: [],
      contradictions: "ignore",
      rejectedDecisions: "allow",
      responseMutation: "allow",
      replay: "allow",
    };
    expect(verifyEnvelope(envelope as never).status).toBe("BLOCKED");
  });

  it("blocks mistyped nested fields instead of relying on TypeScript", () => {
    const envelope = validEnvelope();
    envelope.response = {
      content: "claim",
      sections: [{ sectionId: "s1", substantive: "false", byteStart: 0, byteEnd: 1, sha256: "a".repeat(64) }],
    };
    expect(verifyEnvelope(envelope as never).status).toBe("BLOCKED");
  });

  it("blocks oversized collections before verification work", () => {
    const envelope = validEnvelope();
    envelope.sources = Array.from({ length: 10_001 }, (_, index) => ({
      sourceId: `source-${index}`,
      path: `source-${index}.txt`,
      sha256: "0".repeat(64),
      size: 0,
    }));
    expect(verifyEnvelope(envelope as never).status).toBe("BLOCKED");
  });

  it.each([
    ["supporting direct", { role: "supporting", support: "direct" }, true],
    ["supporting default", { role: "supporting" }, true],
    ["supporting disclosed", { role: "supporting", support: "direct", disclosed: true }, false],
    ["contradictory disclosed", { role: "contradictory", disclosed: true }, true],
    ["contradictory support", { role: "contradictory", support: "direct" }, false],
    ["contextual plain", { role: "contextual" }, true],
    ["contextual support", { role: "contextual", support: "ambiguous" }, false],
    ["contextual disclosed", { role: "contextual", disclosed: false }, false],
  ])("keeps JSON Schema and runtime role metadata aligned for %s", async (_name, metadata, expectedValid) => {
    const envelope = completeEnvelope();
    envelope.claims[0]!.evidence[0] = { evidenceId: "evidence-1", ...metadata } as never;
    const { validate } = await schemaValidator();
    expect(validate(envelope), JSON.stringify(validate.errors)).toBe(expectedValid);
    expect(verifyEnvelope(envelope).findings.some((finding) => finding.code === "checker.failure")).toBe(!expectedValid);
  });

  it("documents character-vs-UTF-8-byte limits and enforces the byte limit at runtime", async () => {
    const { schema, validate } = await schemaValidator();
    expect(schema.$defs.response.description).toMatch(/UTF-8 bytes.*cannot express/u);
    expect(schema.$defs.response.properties.content.maxLength).toBeUndefined();
    const envelope = completeEnvelope();
    const content = "é".repeat(8_388_609);
    envelope.response = { content, sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: Buffer.byteLength(content), sha256: createHash("sha256").update(content).digest("hex") }] };
    expect(validate(envelope)).toBe(true);
    expect(verifyEnvelope(envelope).status).toBe("BLOCKED");
  });
});
