import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { collectSource } from "../../src/sources/collect-source.js";

describe("source path boundary", () => {
  it.each(["../secret.md", "docs/../../secret.md"])("rejects traversal: %s", async (sourcePath) => {
    const root = await mkdtemp(join(tmpdir(), "agent-integrity-boundary-"));
    await mkdir(join(root, "docs"));
    await writeFile(join(root, "secret.md"), "secret");
    await expect(collectSource({ projectRoot: root, allowedRoots: ["docs"], sourcePath }))
      .rejects.toThrow(/relative path|project root|allowed source roots/u);
  });

  it("rejects absolute source paths", async () => {
    const root = await mkdtemp(join(tmpdir(), "agent-integrity-boundary-"));
    await mkdir(join(root, "docs"));
    const sourcePath = join(root, "docs", "source.md");
    await writeFile(sourcePath, "source");
    await expect(collectSource({ projectRoot: root, allowedRoots: ["docs"], sourcePath }))
      .rejects.toThrow(/relative path/u);
  });

  it("rejects absolute and escaping allowed roots", async () => {
    const root = await mkdtemp(join(tmpdir(), "agent-integrity-boundary-"));
    await mkdir(join(root, "docs"));
    await writeFile(join(root, "docs", "source.md"), "source");
    for (const allowedRoot of [join(root, "docs"), "../"]) {
      await expect(collectSource({ projectRoot: root, allowedRoots: [allowedRoot], sourcePath: "docs/source.md" }))
        .rejects.toThrow(/allowed root/u);
    }
  });
});
