import { realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

function isInside(parent: string, candidate: string): boolean {
  const pathFromParent = relative(parent, candidate);
  return pathFromParent === "" || (!pathFromParent.startsWith(`..${sep}`) && pathFromParent !== ".." && !isAbsolute(pathFromParent));
}

function assertRelativePath(path: string, label: string): void {
  if (path.trim() === "" || isAbsolute(path)) throw new Error(`${label} must be a non-empty relative path`);
  const normalized = relative(".", path);
  if (normalized === ".." || normalized.startsWith(`..${sep}`)) {
    throw new Error(`${label} must remain inside the project root`);
  }
}

export interface ResolvedSourcePath {
  readonly projectRoot: string;
  readonly realPath: string;
  readonly relativePath: string;
}

export async function resolveAllowedSourcePath(options: {
  readonly projectRoot: string;
  readonly allowedRoots: readonly string[];
  readonly sourcePath: string;
}): Promise<ResolvedSourcePath> {
  if (options.allowedRoots.length === 0) throw new Error("At least one allowed root is required");
  assertRelativePath(options.sourcePath, "source path");
  const projectRoot = await realpath(options.projectRoot);
  const allowedRoots = await Promise.all(options.allowedRoots.map(async (allowedRoot) => {
    assertRelativePath(allowedRoot, "allowed root");
    const resolved = await realpath(resolve(projectRoot, allowedRoot));
    if (!isInside(projectRoot, resolved)) throw new Error("allowed root must remain inside the project root");
    return resolved;
  }));
  const realPath = await realpath(resolve(projectRoot, options.sourcePath));
  if (!allowedRoots.some((allowedRoot) => isInside(allowedRoot, realPath))) {
    throw new Error("source path is outside the allowed source roots");
  }
  const relativePath = relative(projectRoot, realPath).split(sep).join("/");
  return { projectRoot, realPath, relativePath };
}
