import { describe, expect, it } from "vitest";
import { parsePolicy } from "../../src/policy/parse-policy.js";

const validPolicy = `
version: 1
sources:
  allowedRoots:
    - docs/
    - policies/
decisions:
  path: integrity/decisions.yaml
rules:
  requireEvidenceFor:
    - factual
    - recommendation
  contradictions: review
  rejectedDecisions: block
  responseMutation: block
  replay: block
`;

describe("parsePolicy", () => {
  it("parses the strict public policy format", () => {
    expect(parsePolicy(validPolicy)).toEqual({
      version: 1,
      sources: { allowedRoots: ["docs/", "policies/"] },
      decisions: { path: "integrity/decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual", "recommendation"],
        contradictions: "review",
        rejectedDecisions: "block",
        responseMutation: "block",
        replay: "block"
      }
    });
  });

  it.each([
    ["duplicate keys", validPolicy.replace("version: 1", "version: 1\nversion: 1")],
    ["aliases", validPolicy.replace("- docs/", "- &root docs/").replace("- policies/", "- *root")],
    ["custom tags", validPolicy.replace("version: 1", "version: !custom 1")],
    ["ambiguous booleans", validPolicy.replace("contradictions: review", "contradictions: yes")],
    ["dates", validPolicy.replace("integrity/decisions.yaml", "2026-08-02")],
    ["unknown fields", `${validPolicy}\nextra: true\n`]
  ])("rejects %s", (_label, input) => {
    expect(() => parsePolicy(input)).toThrow();
  });

  it("rejects empty and duplicate allowed roots", () => {
    expect(() => parsePolicy(validPolicy.replace("    - policies/", "    - docs/"))).toThrow();
    expect(() => parsePolicy(validPolicy.replace("    - policies/", "    - ''"))).toThrow();
  });
});
