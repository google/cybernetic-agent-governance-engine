const SHA = /^[0-9a-f]{40}$/u;
const INTEGRITY = /^sha512-[A-Za-z0-9+/]+={0,2}$/u;

export function validateReleaseManifest(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("manifest must be an object");
  const required = ["owner", "repository", "tag", "commit", "mainBranch", "workflowFile", "environment", "packages"];
  for (const key of required) if (!(key in value)) throw new Error(`manifest.${key} is required`);
  for (const key of required.slice(0, -1)) if (typeof value[key] !== "string" || value[key].length === 0) throw new Error(`manifest.${key} must be a non-empty string`);
  if (!SHA.test(value.commit)) throw new Error("manifest.commit must be a lowercase 40-character SHA");
  if (!/^v\d/u.test(value.tag)) throw new Error("manifest.tag must start with v and a version");
  if (!Array.isArray(value.packages) || value.packages.length === 0) throw new Error("manifest.packages must be a non-empty array");
  for (const entry of value.packages) {
    if (entry === null || typeof entry !== "object" || typeof entry.name !== "string" || typeof entry.version !== "string") {
      throw new Error("each package requires name and version strings");
    }
  }
  return structuredClone(value);
}

export function evaluateReleaseStatus(manifestInput, evidence) {
  const manifest = validateReleaseManifest(manifestInput);
  const blockers = [];
  const check = (ok, code, detail) => { if (!ok) blockers.push({ code, detail }); };
  check(evidence.tagCommit === manifest.commit, "tag_commit_mismatch", "tag does not resolve to the approved commit");
  check(evidence.mainContainsCommit === true, "commit_not_on_main", "release commit is not reachable from main");
  check(evidence.workflow?.conclusion === "success" && evidence.workflow?.headSha === manifest.commit && evidence.workflow?.event === "push", "workflow_invalid", "tag workflow did not succeed for the approved commit");
  check(evidence.approval?.environment === manifest.environment && evidence.approval?.approved === true && evidence.approval?.reviewerType === "User", "environment_approval_invalid", "protected release environment lacks a human approval");
  for (const expected of manifest.packages) {
    const actual = evidence.packages?.find((item) => item.name === expected.name);
    check(actual?.version === expected.version, "package_version_mismatch", `${expected.name} version is missing or unexpected`);
    check(typeof actual?.integrity === "string" && INTEGRITY.test(actual.integrity) && actual.integrityVerified === true, "package_integrity_invalid", `${expected.name} tarball integrity is invalid`);
    check(actual?.provenance?.verified === true && actual?.provenance?.repository === `${manifest.owner}/${manifest.repository}` && actual?.provenance?.commit === manifest.commit && actual?.provenance?.workflowFile === manifest.workflowFile && actual?.provenance?.ref === `refs/tags/${manifest.tag}`, "package_provenance_invalid", `${expected.name} provenance is missing, unverified, or does not bind to this release`);
  }
  return {
    schemaVersion: 1,
    status: blockers.length === 0 ? "CURRENT" : "BLOCKED",
    checkedCommit: manifest.commit,
    checkedTag: manifest.tag,
    blockers,
  };
}
