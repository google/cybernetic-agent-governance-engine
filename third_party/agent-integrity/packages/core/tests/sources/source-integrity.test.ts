import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { collectSource } from "../../src/sources/collect-source.js";

async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "agent-integrity-source-"));
  await mkdir(join(root, "docs"));
  return root;
}

describe("collectSource", () => {
  it("hashes exact file bytes and returns a normalized relative path", async () => {
    const root = await fixture();
    await writeFile(join(root, "docs", "source.md"), Buffer.from("hello\n", "utf8"));

    await expect(collectSource({ projectRoot: root, allowedRoots: ["docs/"], sourcePath: "docs/source.md" }))
      .resolves.toEqual({
        path: "docs/source.md",
        sha256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
        size: 6
      });
  });

  it("detects byte changes including line endings", async () => {
    const root = await fixture();
    const path = join(root, "docs", "source.md");
    await writeFile(path, Buffer.from("one\ntwo\n", "utf8"));
    const first = await collectSource({ projectRoot: root, allowedRoots: ["docs"], sourcePath: "docs/source.md" });
    await writeFile(path, Buffer.from("one\r\ntwo\r\n", "utf8"));
    const second = await collectSource({ projectRoot: root, allowedRoots: ["docs"], sourcePath: "docs/source.md" });

    expect(second.sha256).not.toBe(first.sha256);
    expect(second.size).toBe(first.size + 2);
  });

  it("hashes arbitrary bytes without text decoding", async () => {
    const root = await fixture();
    await writeFile(join(root, "docs", "bytes.bin"), Buffer.from([0xff, 0x00, 0x61]));
    const result = await collectSource({ projectRoot: root, allowedRoots: ["docs"], sourcePath: "docs/bytes.bin" });
    expect(result.size).toBe(3);
  });

  it("rejects directories", async () => {
    const root = await fixture();
    await expect(collectSource({ projectRoot: root, allowedRoots: ["docs"], sourcePath: "docs" }))
      .rejects.toThrow(/regular file/u);
  });

  it("rejects a symlink whose target escapes the allowed root", async () => {
    const root = await fixture();
    const outside = join(root, "outside.txt");
    await writeFile(outside, "private");
    await symlink(outside, join(root, "docs", "escape.md"));

    await expect(collectSource({ projectRoot: root, allowedRoots: ["docs"], sourcePath: "docs/escape.md" }))
      .rejects.toThrow(/allowed source roots/u);
  });
});
