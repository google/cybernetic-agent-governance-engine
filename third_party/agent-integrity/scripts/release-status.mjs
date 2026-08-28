#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { evaluateReleaseStatus, validateReleaseManifest } from "./release-status-core.mjs";

const TIMEOUT_MS = 15_000;
const execFileAsync = promisify(execFile);

async function requestJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`${new URL(url).host} returned HTTP ${response.status}`);
  return response.json();
}

function githubHeaders(token) {
  return { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
}

async function githubPages(url, token) {
  const results = [];
  for (let page = 1; page <= 20; page += 1) {
    const separator = url.includes("?") ? "&" : "?";
    const batch = await requestJson(`${url}${separator}per_page=100&page=${page}`, { headers: githubHeaders(token) });
    const values = Array.isArray(batch) ? batch : batch.workflow_runs;
    if (!Array.isArray(values)) throw new Error("GitHub pagination response has an unexpected shape");
    results.push(...values);
    if (values.length < 100) return results;
  }
  throw new Error("GitHub pagination exceeded 20 pages");
}

function decodeStatement(bundle) {
  const encoded = bundle?.dsseEnvelope?.payload;
  if (typeof encoded !== "string") return undefined;
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
}

export function provenanceFrom(attestations, manifest, cryptographicallyVerified) {
  for (const attestation of attestations) {
    const statement = decodeStatement(attestation.bundle);
    const invocation = statement?.predicate?.buildDefinition?.externalParameters?.workflow;
    const repository = invocation?.repository?.replace(/^https:\/\/github\.com\//u, "").replace(/\.git$/u, "");
    const workflowFile = typeof invocation?.path === "string" ? invocation.path.split("/").at(-1) : undefined;
    const ref = invocation?.ref;
    const source = statement?.predicate?.buildDefinition?.resolvedDependencies?.find((dependency) => {
      const uri = dependency?.uri?.replace(/^git\+https:\/\/github\.com\//u, "").replace(/\.git$/u, "");
      return uri === `${manifest.owner}/${manifest.repository}`;
    });
    const commit = source?.digest?.gitCommit;
    if (repository === `${manifest.owner}/${manifest.repository}` && ref === `refs/tags/${manifest.tag}` && workflowFile === manifest.workflowFile && commit === manifest.commit) {
      return { verified: cryptographicallyVerified, repository, commit, workflowFile, ref };
    }
  }
  return undefined;
}

async function verifyNpmAttestations(packages) {
  const directory = await mkdtemp(join(tmpdir(), "agent-integrity-attestations-"));
  try {
    const dependencies = Object.fromEntries(packages.map((entry) => [entry.name, entry.version]));
    await writeFile(join(directory, "package.json"), `${JSON.stringify({ private: true, dependencies }, null, 2)}\n`, { mode: 0o600 });
    await execFileAsync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: directory, timeout: 60_000 });
    await execFileAsync("npm", ["audit", "signatures"], { cwd: directory, timeout: 60_000 });
    return true;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function verifyTarball(url, expected) {
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`npm tarball returned HTTP ${response.status}`);
  const digest = createHash("sha512").update(Buffer.from(await response.arrayBuffer())).digest("base64");
  return `sha512-${digest}` === expected;
}

export async function collectReleaseEvidence(manifestInput, { githubToken = process.env.GITHUB_TOKEN } = {}) {
  const manifest = validateReleaseManifest(manifestInput);
  if (!githubToken) throw new Error("GITHUB_TOKEN is required");
  const api = `https://api.github.com/repos/${encodeURIComponent(manifest.owner)}/${encodeURIComponent(manifest.repository)}`;
  const tag = await requestJson(`${api}/git/ref/tags/${encodeURIComponent(manifest.tag)}`, { headers: githubHeaders(githubToken) });
  let tagCommit = tag.object?.sha;
  if (tag.object?.type === "tag") {
    const annotated = await requestJson(`${api}/git/tags/${tagCommit}`, { headers: githubHeaders(githubToken) });
    tagCommit = annotated.object?.sha;
  }
  const comparison = await requestJson(`${api}/compare/${manifest.commit}...${encodeURIComponent(manifest.mainBranch)}`, { headers: githubHeaders(githubToken) });
  const runs = await githubPages(`${api}/actions/workflows/${encodeURIComponent(manifest.workflowFile)}/runs?event=push`, githubToken);
  const workflow = runs.find((run) => run.head_sha === manifest.commit && run.head_branch === manifest.tag);
  let approval;
  if (workflow) {
    const approvals = await githubPages(`${api}/actions/runs/${workflow.id}/approvals`, githubToken);
    const match = approvals.find((item) => item.state === "approved" && item.environments?.some((environment) => environment.name === manifest.environment));
    approval = match && { environment: manifest.environment, approved: true, reviewerType: match.user?.type };
  }
  const packages = [];
  const attestationsVerified = await verifyNpmAttestations(manifest.packages);
  for (const expected of manifest.packages) {
    const encoded = encodeURIComponent(expected.name);
    const metadata = await requestJson(`https://registry.npmjs.org/${encoded}/${encodeURIComponent(expected.version)}`);
    const attestationResponse = await requestJson(`https://registry.npmjs.org/-/npm/v1/attestations/${encoded}@${encodeURIComponent(expected.version)}`);
    const integrity = metadata.dist?.integrity;
    packages.push({
      name: expected.name,
      version: metadata.version,
      integrity,
      integrityVerified: typeof integrity === "string" && typeof metadata.dist?.tarball === "string" ? await verifyTarball(metadata.dist.tarball, integrity) : false,
      provenance: provenanceFrom(attestationResponse.attestations ?? [], manifest, attestationsVerified),
    });
  }
  return {
    tagCommit,
    mainContainsCommit: ["ahead", "identical"].includes(comparison.status),
    workflow: workflow && { conclusion: workflow.conclusion, headSha: workflow.head_sha, event: workflow.event, id: workflow.id },
    approval,
    packages,
  };
}

async function main() {
  const path = process.argv[2];
  if (!path || process.argv.length !== 3) throw new Error("usage: node scripts/release-status.mjs <manifest.json>");
  const manifest = validateReleaseManifest(JSON.parse(await readFile(path, "utf8")));
  const evidence = await collectReleaseEvidence(manifest);
  const result = evaluateReleaseStatus(manifest, evidence);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.status === "CURRENT" ? 0 : 2;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, status: "BLOCKED", blockers: [{ code: "provider_error", detail: error.message }] }, null, 2)}\n`);
    process.exitCode = 2;
  });
}
