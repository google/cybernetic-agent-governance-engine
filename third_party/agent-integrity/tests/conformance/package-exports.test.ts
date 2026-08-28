import { access, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const root = new URL("../..", import.meta.url).pathname;

describe("workspace package exports", () => {
  for (const name of ["protocol", "core", "sdk"] as const) {
    it(`${name} exports an emitted JavaScript and declaration file`, async () => {
      const directory = join(root, "packages", name);
      const manifest = JSON.parse(await readFile(join(directory, "package.json"), "utf8")) as {
        exports: string;
        types: string;
      };
      await expect(access(join(directory, manifest.exports))).resolves.toBeUndefined();
      await expect(access(join(directory, manifest.types))).resolves.toBeUndefined();
      expect(dirname(manifest.exports)).toBe(dirname(manifest.types));
    });
  }
});
