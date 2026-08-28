import { describe, expect, it } from "vitest";
import { PROTOCOL_VERSION, type IntegrityResult } from "../src/index.js";

describe("public protocol", () => {
  it("exposes a versioned language-neutral result", () => {
    const result: IntegrityResult = {
      protocolVersion: PROTOCOL_VERSION,
      status: "REVIEW",
      findings: [{ code: "evidence.ambiguous", severity: "review", message: "Inspect evidence" }]
    };

    expect(result).toEqual({
      protocolVersion: "1-alpha",
      status: "REVIEW",
      findings: [{ code: "evidence.ambiguous", severity: "review", message: "Inspect evidence" }]
    });
  });
});
