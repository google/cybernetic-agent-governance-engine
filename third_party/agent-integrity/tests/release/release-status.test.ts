import { describe, expect, test } from "vitest";
import { evaluateReleaseStatus, validateReleaseManifest } from "../../scripts/release-status-core.mjs";

const manifest = {
  owner: "SimranPabla", repository: "agent-integrity", tag: "v0.1.0-alpha.0",
  commit: "a".repeat(40), mainBranch: "main", workflowFile: "npm-release.yml",
  environment: "npm-release",
  packages: ["protocol", "core", "sdk", "cli"].map((name) => ({ name: `@agent-integrity/${name}`, version: "0.1.0-alpha.0" })),
};

function currentEvidence() {
  return {
    tagCommit: manifest.commit,
    mainContainsCommit: true,
    workflow: { conclusion: "success", headSha: manifest.commit, event: "push" },
    approval: { environment: "npm-release", approved: true, reviewerType: "User" },
    packages: manifest.packages.map((entry) => ({
      ...entry, integrity: `sha512-${Buffer.from("digest").toString("base64")}`, integrityVerified: true,
      provenance: { verified: true, repository: "SimranPabla/agent-integrity", commit: manifest.commit, workflowFile: "npm-release.yml", ref: "refs/tags/v0.1.0-alpha.0" },
    })),
  };
}

describe("public release status", () => {
  test("returns CURRENT only for a completely bound release", () => {
    expect(evaluateReleaseStatus(manifest, currentEvidence())).toMatchObject({ status: "CURRENT", blockers: [] });
  });

  test.each([
    ["tag", (e: any) => { e.tagCommit = "b".repeat(40); }, "tag_commit_mismatch"],
    ["ancestry", (e: any) => { e.mainContainsCommit = false; }, "commit_not_on_main"],
    ["workflow", (e: any) => { e.workflow.conclusion = "failure"; }, "workflow_invalid"],
    ["approval", (e: any) => { e.approval.approved = false; }, "environment_approval_invalid"],
    ["integrity", (e: any) => { e.packages[0].integrityVerified = false; }, "package_integrity_invalid"],
    ["provenance", (e: any) => { e.packages[0].provenance.commit = "b".repeat(40); }, "package_provenance_invalid"],
  ])("blocks %s failure", (_name, mutate, code) => {
    const evidence = currentEvidence(); mutate(evidence);
    expect(evaluateReleaseStatus(manifest, evidence).blockers.map((item) => item.code)).toContain(code);
  });

  test("rejects malformed manifests before evaluating evidence", () => {
    expect(() => validateReleaseManifest({ ...manifest, commit: "HEAD" })).toThrow(/40-character SHA/u);
  });
});
