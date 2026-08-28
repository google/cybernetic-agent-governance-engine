import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "../../packages/core/src/verify.js";
import type { IntegrityEnvelope, IntegrityStatus } from "../../packages/protocol/src/index.js";

interface Fixture {
  readonly name: string;
  readonly envelope: IntegrityEnvelope;
  readonly expected: { readonly status: IntegrityStatus; readonly findingCodes: readonly string[] };
}

const fixtureDirectory = new URL("./fixtures", import.meta.url).pathname;

describe("language-neutral conformance fixtures", async () => {
  const files = (await readdir(fixtureDirectory)).filter((file) => file.endsWith(".json")).sort();
  for (const file of files) {
    const fixture = JSON.parse(await readFile(join(fixtureDirectory, file), "utf8")) as Fixture;
    it(fixture.name, () => {
      const result = verifyEnvelope(fixture.envelope);
      expect(result.status).toBe(fixture.expected.status);
      expect(result.findings.map((finding) => finding.code)).toEqual(fixture.expected.findingCodes);
      expect(result.envelopeDigest).toMatch(/^[a-f0-9]{64}$/u);
    });
  }
});
