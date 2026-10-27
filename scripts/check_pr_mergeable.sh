#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# check_pr_mergeable.sh — verify every required status check on a PR's exact head SHA.
#
# Why this exists
# ---------------
# Until 2026-10-27 the required status checks on `main` shared a ruleset with
# the review rule, and the maintainer's admin merges bypassed both: GitHub's
# rule-suite log shows 163 of 215 pushes went in with required checks not
# passing (POAM-2026-115). The checks now sit in ruleset 25966171, which has
# no bypass actor, so GitHub enforces them. This script is the pre-merge
# double-check and record: it verifies the same required checks on the exact
# head SHA and, with --comment, posts the result on the PR. It does nothing
# for AC-5; no script supplies an independent reviewer.
#
# `gh pr checks` is not a substitute. On PR #546 it listed 48 of the PR's 50
# check-runs and left out the required "OPA Rego Policy Lint and Test" check,
# so a merge decision must not rest on it.
#
# What it does
# ------------
# 1. Asks GitHub which rules apply to the PR's base branch
#    (GET /repos/{owner}/{repo}/rules/branches/{branch}, so ruleset targeting
#    is GitHub's own) and adds any classic branch-protection checks. Finding
#    no required check exits 2: an empty list must never read as a pass.
# 2. Verifies each required check on the exact head SHA through the REST
#    check-runs and commit-status APIs.
# 3. Prints the merge command pinned to that SHA with --match-head-commit.
#    With --comment it first posts the result table on the PR as the
#    pre-merge record.
#
# Where it is stricter than GitHub
# --------------------------------
# - Only "success" passes. "neutral", "skipped" and every other result fail
#   here, even where GitHub would let them through.
# - Every source reporting a required name must pass: the newest check-run in
#   each check suite, and the commit status. A same-name check from another
#   workflow cannot hide a failure. Newest means highest id, so a re-run that
#   is still queued counts as pending.
# - A check pinned to an app (integration_id) counts only that app's
#   check-runs. Commit statuses carry no app id, so they never satisfy it.
#
# Usage
# -----
#   scripts/check_pr_mergeable.sh <pr-number> [--repo OWNER/NAME] [--comment]
#
#   --repo      repository to query (default: the current checkout's GitHub repo)
#   --comment   post the result table on the PR; a failed post fails the run
#
# Exit codes
# ----------
#   0  every required check is present and successful on the head SHA
#   1  a required check is missing, pending or not successful
#   2  usage error, no required checks found, or a GitHub API call failed
set -euo pipefail
export LC_ALL=C

usage() {
  awk '/^# check_pr_mergeable\.sh /{p=1} p && !/^#/{exit} p{sub(/^# ?/, ""); print}' "$0"
}

die() {
  echo "check_pr_mergeable.sh: $*" >&2
  exit 2
}

PR=""
REPO=""
POST_COMMENT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)
      { [ $# -ge 2 ] && [ -n "$2" ]; } || die "--repo needs OWNER/NAME"
      REPO="$2"
      shift 2
      ;;
    --comment)
      POST_COMMENT=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*) die "unknown flag: $1 (see --help)" ;;
    *)
      [ -z "$PR" ] || die "give one PR number, not '$PR' and '$1'"
      PR="$1"
      shift
      ;;
  esac
done

[ -n "$PR" ] || die "usage: check_pr_mergeable.sh <pr-number> [--repo OWNER/NAME] [--comment]"
[[ "$PR" =~ ^[1-9][0-9]*$ ]] || die "the PR number must be a positive integer, not '$PR'"
command -v gh >/dev/null 2>&1 || die "gh (the GitHub CLI) is not on PATH"
if [ -z "$REPO" ]; then
  REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner) ||
    die "could not work out the repository; pass --repo OWNER/NAME"
fi
[[ "$REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "--repo must be OWNER/NAME, not '$REPO'"

NO_MERGE="cannot verify, do not merge"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ------------------------------------------------------------------------ the PR
PR_TSV=$(gh pr view "$PR" --repo "$REPO" --json headRefOid,baseRefName,state,reviewDecision \
  --jq '[.headRefOid, .baseRefName, .state, (.reviewDecision // "")] | @tsv') ||
  die "could not read PR #$PR in $REPO; $NO_MERGE"
IFS=$'\t' read -r SHA BASE PR_STATE REVIEW <<<"$PR_TSV" || true
[[ "${SHA:-}" =~ ^[0-9a-f]{40}$ ]] || die "PR #$PR has no usable head SHA ('${SHA:-}'); $NO_MERGE"
[[ "${BASE:-}" =~ ^[A-Za-z0-9._/-]+$ ]] || die "unsupported base branch name '${BASE:-}'; $NO_MERGE"

# ------------------------------------------------- required checks for the base
# One line per requirement: context, then the app id it is pinned to ("" = any).
gh api --paginate "repos/$REPO/rules/branches/$BASE?per_page=100" \
  --jq '.[] | select(.type == "required_status_checks")
        | .parameters.required_status_checks[]
        | [.context, ((.integration_id // "") | tostring)] | @tsv' \
  >"$TMP/required.raw" || die "could not read the rules for '$BASE'; $NO_MERGE"
gh api "repos/$REPO/branches/$BASE" \
  --jq '(.protection.required_status_checks // {}) as $r
        | if (($r.checks // []) | length) > 0
          then $r.checks[] | [.context, ((.app_id // -1) | if . == -1 then "" else tostring end)]
          else ($r.contexts // [])[] | [., ""]
          end
        | @tsv' \
  >>"$TMP/required.raw" || die "could not read branch protection for '$BASE'; $NO_MERGE"
sort -u "$TMP/required.raw" >"$TMP/required"
[ -s "$TMP/required" ] || die "no required status checks apply to '$BASE'." \
  "An empty list cannot count as a pass: confirm the ruleset before merging."

# ------------------------------------------------------ results on the head SHA
gh api --paginate "repos/$REPO/commits/$SHA/check-runs?filter=all&per_page=100" \
  --jq '.check_runs[]
        | [.id, .name, (.check_suite.id // 0), (.app.id // 0), .status, (.conclusion // "")]
        | @tsv' \
  >"$TMP/runs" || die "could not read the check-runs on $SHA; $NO_MERGE"
gh api --paginate "repos/$REPO/commits/$SHA/status?per_page=100" \
  --jq '.statuses[]? | [.context, .state] | @tsv' \
  >"$TMP/statuses" || die "could not read the commit statuses on $SHA; $NO_MERGE"

# ----------------------------------------------------------------------- compare
# One line per requirement: context, source, number of reports, verdict, detail.
awk -F'\t' -v OFS='\t' -v runs="$TMP/runs" -v statuses="$TMP/statuses" '
  BEGIN {
    # Newest check-run per (name, check suite, app). Ids only grow, so the
    # highest id is the newest run, even one that has not started yet.
    while ((getline line < runs) > 0) {
      split(line, f, "\t")
      k = f[2] SUBSEP f[3] SUBSEP f[4]
      if (!(k in id) || f[1] + 0 > id[k] + 0) {
        id[k] = f[1]; name[k] = f[2]; app[k] = f[4]
        result[k] = (f[5] == "completed") ? f[6] : f[5]
      }
    }
    # The combined-status endpoint already returns the newest status per context.
    while ((getline line < statuses) > 0) {
      split(line, f, "\t")
      status[f[1]] = f[2]
    }
  }
  {
    ctx = $1; want = $2; n = 0; bad = ""
    for (k in id) {
      if (name[k] != ctx || (want != "" && app[k] != want)) continue
      n++
      if (result[k] != "success") bad = bad (bad == "" ? "" : ", ") "check-run " id[k] ": " result[k]
    }
    if (want == "" && (ctx in status)) {
      n++
      if (status[ctx] != "success") bad = bad (bad == "" ? "" : ", ") "status: " status[ctx]
    }
    verdict = (n == 0) ? "missing" : ((bad == "") ? "success" : "failed")
    print ctx, ((want == "") ? "any" : "app " want), n, verdict, bad
  }
' "$TMP/required" >"$TMP/verdicts"
FAILED=$(awk -F'\t' '$4 != "success" { f = 1 } END { print f + 0 }' "$TMP/verdicts")

REQUIRED_N=$(wc -l <"$TMP/required" | tr -d ' ')
RUNS_N=$(wc -l <"$TMP/runs" | tr -d ' ')
STATUSES_N=$(wc -l <"$TMP/statuses" | tr -d ' ')
{
  echo "## Pre-merge required-check verification"
  echo
  echo "- **PR:** #$PR into \`$BASE\` (state: $PR_STATE; review decision: ${REVIEW:-none})"
  echo "- **Head SHA:** \`$SHA\`"
  echo "- **Required checks:** \`GET /repos/$REPO/rules/branches/$BASE\` plus classic branch protection"
  echo "- **Results:** REST \`commits/{sha}/check-runs?filter=all\` and \`commits/{sha}/status\`, not \`gh pr checks\`"
  echo "- **Verified:** $(date -u '+%Y-%m-%dT%H:%M:%SZ') by \`scripts/check_pr_mergeable.sh\`"
  echo
  echo "| Required check | Source | Reports | Result |"
  echo "|---|---|---|---|"
  awk -F'\t' '{
    c = $1; gsub(/\|/, "\\\\|", c)
    if ($4 == "success") r = "success"
    else if ($4 == "missing") r = "**NOT FOUND**"
    else r = "**" $5 "**"
    printf "| `%s` | %s | %s | %s |\n", c, $2, $3, r
  }' "$TMP/verdicts"
  echo
  echo "$REQUIRED_N required check(s), verified against $RUNS_N check-run(s) and $STATUSES_N commit status(es) on this SHA."
  echo
  if [ "$FAILED" -eq 0 ]; then
    echo "**Result: every required check passed on this exact SHA.**"
  else
    echo "**Result: NOT MERGEABLE. A required check is missing, pending or not successful.**"
  fi
} >"$TMP/report.md"

cat "$TMP/report.md"
echo

if [ "$POST_COMMENT" -eq 1 ]; then
  gh pr comment "$PR" --repo "$REPO" --body-file "$TMP/report.md" >/dev/null ||
    die "the result was not posted to PR #$PR, so the pre-merge record is missing"
  echo "Result posted to PR #$PR."
fi

if [ "$FAILED" -ne 0 ]; then
  echo "Do not merge: resolve the above first."
elif [ "$PR_STATE" != "OPEN" ]; then
  echo "PR #$PR is $PR_STATE: nothing to merge."
elif [ "$REVIEW" = "APPROVED" ]; then
  echo "Merge, pinned to the verified SHA:"
  echo "  gh pr merge $PR --repo $REPO --squash --match-head-commit $SHA"
else
  echo "No approving review, so the merge needs --admin, which bypasses the review"
  echo "rule (POAM-2026-115). Merge, pinned to the verified SHA:"
  echo "  gh pr merge $PR --repo $REPO --squash --admin --match-head-commit $SHA"
  [ "$POST_COMMENT" -eq 1 ] || echo "Run again with --comment first, to record this result on the PR."
fi

exit "$FAILED"
