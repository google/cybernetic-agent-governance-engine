import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const packageDirectory = process.argv[2];
if (!packageDirectory?.startsWith("packages/")) throw new Error("expected packages/<name>");
const manifest = JSON.parse(readFileSync(join(packageDirectory, "package.json"), "utf8"));
const spec = `${manifest.name}@${manifest.version}`;
const destination = mkdtempSync(join(tmpdir(), "agent-integrity-publish-"));
try {
  const filename = execFileSync("npm", ["pack", packageDirectory, "--pack-destination", destination, "--json"], { encoding: "utf8" });
  const packed = JSON.parse(filename)[0];
  if (!packed?.filename) throw new Error(`npm pack produced no archive for ${spec}`);
  const archive = join(destination, packed.filename);
  const localIntegrity = `sha512-${createHash("sha512").update(readFileSync(archive)).digest("base64")}`;

  let publishedIntegrity;
  try {
    publishedIntegrity = JSON.parse(execFileSync("npm", ["view", spec, "dist.integrity", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  } catch (error) {
    const stderr = String(error?.stderr ?? "");
    if (!stderr.includes("E404")) throw error;
  }

  if (publishedIntegrity !== undefined) {
    if (publishedIntegrity !== localIntegrity) throw new Error(`${spec} already exists with different tarball integrity`);
    console.log(`${spec} already exists with identical integrity; skipping`);
  } else {
    execFileSync("npm", ["publish", archive, "--access", "public", "--provenance", "--tag", "alpha"], { stdio: "inherit" });
  }
} finally {
  rmSync(destination, { recursive: true, force: true });
}
