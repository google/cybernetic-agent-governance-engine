import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const ignored = new Set([".git", "node_modules", "dist", "coverage"]);
const textExtensions = new Set([".json", ".md", ".mjs", ".ts", ".yaml", ".yml"]);
const forbidden = [
  { label: "GitHub owner placeholder", pattern: /<YOUR-GITHUB-ORG>/u },
  { label: "private-review wording", pattern: /private (?:GitHub )?review repository/iu },
  { label: "local OpenClaw path", pattern: /\/home\/[^/]+\/\.openclaw\//u },
  { label: "internal ARC wording", pattern: /\binternal ARC\b/iu },
];

async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (textExtensions.has(extname(entry.name))) files.push(path);
  }
  return files;
}

const failures = [];
for (const path of await walk(root)) {
  if (relative(root, path) === "scripts/pre-release-check.mjs") continue;
  const content = await readFile(path, "utf8");
  for (const rule of forbidden) {
    if (rule.pattern.test(content)) failures.push(`${relative(root, path)}: ${rule.label}`);
  }
}

if (failures.length > 0) {
  console.error("Pre-release check failed:\n" + failures.map((item) => `- ${item}`).join("\n"));
  process.exit(1);
}
console.log("Pre-release check passed: no placeholders, private paths, or internal wording found.");
