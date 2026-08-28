import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "../../src/verify.js";

describe("checker failure", () => {
  it("fails closed and emits no envelope digest when input access throws", () => {
    const hostile = Object.defineProperty({}, "protocolVersion", {
      get() { throw new Error("hostile getter"); },
    });
    const result = verifyEnvelope(hostile as never);
    expect(result).toMatchObject({ status: "BLOCKED", findings: [{ code: "checker.failure", severity: "blocked" }] });
    expect(result.envelopeDigest).toBeUndefined();
  });
});
