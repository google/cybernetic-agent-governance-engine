import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

describe("release-status CLI", () => {
  test("fails closed without provider credentials and does not expose manifest content", async () => {
    const directory = await mkdtemp(join(tmpdir(), "release-status-cli-"));
    const path = join(directory, "manifest.json");
    const secretMarker = "must-not-be-printed";
    await writeFile(path, JSON.stringify({
      owner: "SimranPabla", repository: "agent-integrity", tag: "v0.1.0-alpha.0",
      commit: "a".repeat(40), mainBranch: "main", workflowFile: "npm-release.yml", environment: secretMarker,
      packages: [{ name: "@agent-integrity/core", version: "0.1.0-alpha.0" }],
    }));
    const environment = { ...process.env }; delete environment.GITHUB_TOKEN;
    const result = spawnSync(process.execPath, [new URL("../../scripts/release-status.mjs", import.meta.url).pathname, path], { encoding: "utf8", env: environment });
    expect(result.status).toBe(2);
    expect(JSON.parse(result.stdout)).toMatchObject({ status: "BLOCKED", blockers: [{ code: "provider_error" }] });
    expect(result.stdout).not.toContain(secretMarker);
    expect(result.stderr).toBe("");
  });
});
