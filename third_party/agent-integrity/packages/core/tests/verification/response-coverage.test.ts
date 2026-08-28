import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "../../src/verify.js";
import { validEnvelope } from "../support/valid-envelope.js";

const digest = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

function section(sectionId: string, byteStart: number, byteEnd: number, bytes: string) {
  return { sectionId, substantive: true, byteStart, byteEnd, sha256: digest(bytes) };
}

describe("exact response-byte coverage", () => {
  it("rejects a non-empty response with zero sections", () => {
    const input = validEnvelope() as any;
    input.response.sections = [];
    input.claims = [];
    expect(verifyEnvelope(input).status).toBe("BLOCKED");
  });

  it("rejects gaps, overlaps, and unbound trailing prose", () => {
    for (const sections of [
      [section("a", 0, 4, "Supp"), section("b", 5, 18, "rted response")],
      [section("a", 0, 10, "Supported "), section("b", 9, 18, " response")],
      [section("a", 0, 9, "Supported")],
    ]) {
      const input = validEnvelope() as any;
      input.response.sections = sections;
      input.claims = sections.map((item, index) => ({ ...input.claims[0], claimId: `claim-${index}`, sectionId: item.sectionId }));
      expect(verifyEnvelope(input).status).toBe("BLOCKED");
    }
  });

  it("rejects a wrong exact-byte digest", () => {
    const input = validEnvelope() as any;
    input.response.sections[0].sha256 = "0".repeat(64);
    expect(verifyEnvelope(input).status).toBe("BLOCKED");
  });

  it("rejects offsets that split a UTF-8 code point", () => {
    const input = validEnvelope() as any;
    input.response.content = "AéB";
    input.response.sections = [section("a", 0, 2, "Aé"), section("b", 2, 4, "B")];
    input.claims = [
      { ...input.claims[0], claimId: "a", sectionId: "a" },
      { ...input.claims[0], claimId: "b", sectionId: "b" },
    ];
    expect(verifyEnvelope(input).status).toBe("BLOCKED");
  });

  it("blocks every unclaimed section, including non-substantive sections", () => {
    const input = validEnvelope() as any;
    input.response.sections = [section("a", 0, 9, "Supported"), { ...section("b", 9, 18, " response"), substantive: false }];
    input.claims = [{ ...input.claims[0], sectionId: "a" }];
    const result = verifyEnvelope(input);
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.some((finding) => finding.code === "claim.section_uncovered")).toBe(true);
  });
});
