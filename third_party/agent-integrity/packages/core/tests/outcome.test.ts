import { describe, expect, it } from "vitest";
import { calculateOutcome, checkerFailure } from "../src/index.js";

describe("outcome calculation", () => {
  it("passes with no findings", () => {
    expect(calculateOutcome([]).status).toBe("PASS");
  });

  it("routes uncertainty to review", () => {
    expect(calculateOutcome([{ code: "evidence.ambiguous", severity: "review", message: "Review" }]).status).toBe("REVIEW");
  });

  it("makes blocked outrank review", () => {
    expect(calculateOutcome([
      { code: "evidence.ambiguous", severity: "review", message: "Review" },
      { code: "response.mutated", severity: "blocked", message: "Block" }
    ]).status).toBe("BLOCKED");
  });

  it("fails closed on checker errors", () => {
    const result = checkerFailure(new Error("unexpected state"));
    expect(result.status).toBe("BLOCKED");
    expect(result.findings[0]?.code).toBe("checker.failure");
  });
});
