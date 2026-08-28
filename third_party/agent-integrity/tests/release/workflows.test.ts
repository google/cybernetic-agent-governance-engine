import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";

describe("GitHub release governance", () => {
  test("pull-request CI is exact-head, least-privilege, and complete", async () => {
    const workflow = await readFile(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
    expect(workflow).toContain("pull_request:");
    expect(workflow).toContain("name: exact-head-proof");
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow).toContain("persist-credentials: false");
    for (const command of ["npm ci", "npm audit --audit-level=high", "npm run verify", "npm run release:check", "npm run pack:check"]) {
      expect(workflow).toContain(command);
    }
    expect(workflow).toMatch(/actions\/checkout@[0-9a-f]{40}/u);
    expect(workflow).toMatch(/actions\/setup-node@[0-9a-f]{40}/u);
  });

  test("release proves the immutable tag is on main before publishing", async () => {
    const workflow = await readFile(new URL("../../.github/workflows/npm-release.yml", import.meta.url), "utf8");
    expect(workflow).toContain("fetch-depth: 0");
    expect(workflow).toContain("git merge-base --is-ancestor \"$GITHUB_SHA\" origin/main");
  });
});
