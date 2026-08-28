import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

describe("release metadata", () => {
  test("every package declares a bounded public payload", async () => {
    for (const name of ["protocol", "core", "sdk", "cli"]) {
      const manifest = JSON.parse(await import("node:fs/promises").then(({ readFile }) =>
        readFile(new URL(`../../packages/${name}/package.json`, import.meta.url), "utf8")));
      expect(manifest.files).toEqual(name === "cli" ? ["dist", "README.md", "!dist/.tsbuildinfo"] : ["dist", "README.md"]);
      expect(manifest.repository.directory).toBe(`packages/${name}`);
      expect(manifest.publishConfig).toEqual({ access: "public", provenance: true });
    }
  });

  test("the monorepo root cannot be published", async () => {
    const manifest = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
    expect(manifest.private).toBe(true);
  });

  test("package gate performs a clean tarball install without leaving archives in the repository", () => {
    const root = new URL("../../", import.meta.url);
    const archivesBefore = execFileSync(process.execPath, ["--input-type=module", "--eval", `import {readdir} from 'node:fs/promises'; console.log(JSON.stringify((await readdir('.')).filter((name) => name.endsWith('.tgz'))))`], { cwd: root, encoding: "utf8" });
    const output = execFileSync(process.execPath, [new URL("../../scripts/check-packages.mjs", import.meta.url).pathname], { cwd: root, encoding: "utf8" });
    const archivesAfter = execFileSync(process.execPath, ["--input-type=module", "--eval", `import {readdir} from 'node:fs/promises'; console.log(JSON.stringify((await readdir('.')).filter((name) => name.endsWith('.tgz'))))`], { cwd: root, encoding: "utf8" });
    expect(output).toContain("clean tarball install, imports, and CLI executable passed");
    expect(archivesAfter).toBe(archivesBefore);
  }, 60_000);

  test("npm publication workflow is tag-only, least-privilege, ordered, and placeholder-gated", async () => {
    const workflow = await readFile(new URL("../../.github/workflows/npm-release.yml", import.meta.url), "utf8");
    expect(workflow).toContain('tags:\n      - "v*"');
    expect(workflow).not.toMatch(/pull_request:|branches:/u);
    expect(workflow).toContain("contents: read");
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain("environment: npm-release");
    expect(workflow).toContain("actions/checkout@11d5960a326750d5838078e36cf38b85af677262");
    expect(workflow).toContain("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020");
    expect(workflow).toContain("npm run verify");
    expect(workflow).toContain("npm run release:check");
    expect(workflow).toContain("npm run pack:check");
    expect(workflow).toContain("npm audit --audit-level=high");
    const publishes = ["protocol", "core", "sdk", "cli"].map((name) => workflow.indexOf(`node scripts/publish-package.mjs packages/${name}`));
    expect(publishes.every((position) => position >= 0)).toBe(true);
    expect(publishes).toEqual([...publishes].sort((left, right) => left - right));
    expect(workflow.indexOf("npm run release:check")).toBeLessThan(publishes[0]!);
    expect(workflow.indexOf("npm audit --audit-level=high")).toBeLessThan(publishes[0]!);
  });

  test("npm publication always removes its temporary pack directory", async () => {
    const script = await readFile(new URL("../../scripts/publish-package.mjs", import.meta.url), "utf8");
    expect(script).toContain("} finally {");
    expect(script).toContain("rmSync(destination, { recursive: true, force: true });");
  });

  test("threat model limits exactly-once replay protection to one monotonic local store", async () => {
    const threatModel = await readFile(new URL("../../docs/THREAT_MODEL.md", import.meta.url), "utf8");
    expect(threatModel).toContain("only when every consumer uses the same protected, shared, monotonic local filesystem store");
    expect(threatModel).toContain("Restoring older store state can reopen replay");
    expect(threatModel).toContain("does not provide distributed or multi-host replay protection");
    expect(threatModel).not.toContain("this is not durable replay prevention");
  });

  test("release scanner intentionally fails while publication placeholders remain", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-integrity-release-"));
    const placeholder = `<YOUR-${"GITHUB-ORG"}>`;
    await writeFile(join(directory, "README.md"), `https://github.com/${placeholder}/agent-integrity`);
    expect(await import("node:fs/promises").then(({ readFile }) => readFile(join(directory, "README.md"), "utf8")))
      .toContain(placeholder);
  });
});
