import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { resolveAllowedSourcePath } from "./path-boundary.js";

export interface CollectedSource {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface CollectedSourceBytes extends CollectedSource {
  readonly bytes: Buffer;
}

function unchanged(before: Awaited<ReturnType<import("node:fs/promises").FileHandle["stat"]>>, after: Awaited<ReturnType<import("node:fs/promises").FileHandle["stat"]>>): boolean {
  return before.dev === after.dev && before.ino === after.ino && before.size === after.size &&
    before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs;
}

/**
 * Opens the resolved final path with O_NOFOLLOW where Node exposes it, then
 * compares file identity and timestamps before and after reading. Parent-path
 * replacement cannot be made race-free with portable Node APIs; trusted source
 * trees must not be writable by an attacker while collection is running.
 */
export async function collectSourceBytes(options: {
  readonly projectRoot: string;
  readonly allowedRoots: readonly string[];
  readonly sourcePath: string;
  readonly maxBytes?: number;
}): Promise<CollectedSourceBytes> {
  const resolved = await resolveAllowedSourcePath(options);
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(resolved.realPath, constants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error("source path must resolve to a regular file");
    if (options.maxBytes !== undefined && before.size > options.maxBytes) {
      throw new Error(`source exceeds the ${options.maxBytes} byte collection limit`);
    }
    const bytes = await handle.readFile();
    if (options.maxBytes !== undefined && bytes.byteLength > options.maxBytes) {
      throw new Error(`source exceeds the ${options.maxBytes} byte collection limit`);
    }
    const after = await handle.stat();
    if (!unchanged(before, after)) throw new Error("source changed while it was being collected");
    return {
      path: resolved.relativePath,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.byteLength,
      bytes,
    };
  } finally {
    await handle.close();
  }
}

export async function collectSource(options: {
  readonly projectRoot: string;
  readonly allowedRoots: readonly string[];
  readonly sourcePath: string;
}): Promise<CollectedSource> {
  const { bytes: _bytes, ...record } = await collectSourceBytes(options);
  return record;
}
