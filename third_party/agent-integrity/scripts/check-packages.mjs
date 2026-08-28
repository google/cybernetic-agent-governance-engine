import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packages = ["protocol", "core", "sdk", "cli"];
const workspace = dirname(dirname(fileURLToPath(import.meta.url)));
const staging = await mkdtemp(join(tmpdir(), "agent-integrity-pack-"));

function assertPayload(name, manifest) {
  const paths = manifest.files.map((file) => file.path);
  for (const required of ["package.json", "README.md"]) {
    if (!paths.includes(required)) throw new Error(`${name}: pack is missing ${required}`);
  }
  if (!paths.some((path) => path.startsWith("dist/"))) throw new Error(`${name}: pack is missing dist output`);
  if (paths.some((path) => path.includes("tests/") || path.includes("src/"))) {
    throw new Error(`${name}: pack contains source or test files outside the declared public payload`);
  }
  if (paths.some((path) => path.endsWith(".tsbuildinfo"))) {
    throw new Error(`${name}: pack contains TypeScript incremental build state`);
  }
}

try {
  const tarballs = [];
  for (const name of packages) {
    const output = execFileSync("npm", ["pack", "--json", "--pack-destination", staging, join(workspace, "packages", name)], {
      cwd: staging,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [manifest] = JSON.parse(output);
    assertPayload(name, manifest);
    tarballs.push(join(staging, manifest.filename));
    console.log(`${manifest.name}: ${manifest.files.length} files, ${manifest.size} bytes`);
  }

  const installation = staging;
  await writeFile(join(staging, "package.json"), `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`);
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", ...tarballs], {
    cwd: staging,
    stdio: "pipe",
  });

  const smokeModule = join(staging, "smoke.mjs");
  await writeFile(smokeModule, [
    'import { PROTOCOL_VERSION } from "@agent-integrity/protocol";',
    'import { FileReceiptStore, canonicalJson } from "@agent-integrity/core";',
    'import { AgentIntegritySession, releaseVerifiedResponse } from "@agent-integrity/sdk";',
    'if (PROTOCOL_VERSION !== "1-alpha") throw new Error("protocol export smoke test failed");',
    'if (typeof FileReceiptStore !== "function" || typeof canonicalJson !== "function") throw new Error("core export smoke test failed");',
    'if (typeof AgentIntegritySession !== "function" || typeof releaseVerifiedResponse !== "function") throw new Error("SDK export smoke test failed");',
    'console.log("package imports passed");',
    "",
  ].join("\n"));
  execFileSync(process.execPath, [smokeModule], { cwd: installation, stdio: "inherit" });

  const cli = spawnSync(join(staging, "node_modules", ".bin", "integrity"), ["unknown-command"], {
    cwd: installation,
    encoding: "utf8",
    input: "{}\n",
  });
  if (cli.error !== undefined) throw cli.error;
  if (cli.status !== 1 || !cli.stdout.includes('"code":"cli.unknown_command"')) {
    throw new Error(`CLI smoke test failed (exit ${String(cli.status)}): ${cli.stdout}${cli.stderr}`);
  }
  console.log("clean tarball install, imports, and CLI executable passed");
} finally {
  await rm(staging, { recursive: true, force: true });
}
