# Probing a Repository Rule Before Relying On It

> **What this is:** the procedure for observing what a GitHub ruleset rule refuses and allows,
> on a disposable ref, before a document states it. POAM-2026-169's detection rule says a
> statement that a control is in force names the observation that showed it, with a date. A
> probe is how a statement about a repository rule gets that observation. Without one, the
> statement says the rule's effect is inferred.
>
> **Audience:** the repository maintainer, or an agent acting with the maintainer's admin token.
>
> **Requires:** `gh` authenticated with a token that can administer rulesets, and `jq`.

---

## 1. When to probe

- Before an evidence document ([`POAM.md`](../POAM.md), `compliance/oscal/`,
  [`.github/branch-protection-rules.md`](../../.github/branch-protection-rules.md)) states what
  a rule refuses or allows.
- Before a new or changed ruleset is applied to a real ref. Create it against a disposable ref
  first, observe it, then retarget it.
- When a document marks a rule's effect as inferred, and the effect can be tested without
  touching a protected ref.

## 2. Ground rules

1. **Never probe on a real ref.** Do not use `main`, a release tag, or any ref that a live
   ruleset covers. Use a disposable branch such as `spike/probe-<topic>`, or a disposable tag
   for a tag rule.
2. **Use the REST API, not a local push.** Every step then returns a response you can record,
   and no local hook or credential helper is involved.
3. **Start no workflows.** Give the probe commit `[skip ci]`, and give it the tree of the commit
   the positive control moves to. Moving the ref back to that commit then changes no files, so
   path-filtered push workflows have nothing to match.
4. **Copy the rule verbatim.** Copy the `rules` of the ruleset under test with `jq` from the
   live ruleset, not by hand. Target only the disposable ref and add no bypass actors, so an
   admin token is held by the copy like any other.
5. **Pair every negative case with a positive control.** The control must be an action that
   differs from the negative case only in the property under test. A refusal without an
   accepted control does not show what caused it.
6. **Record as you go.** Note the UTC time of each step, the probe ruleset's ID, the commit
   SHAs, and the full response text.

## 3. Procedure

```bash
R=repos/<OWNER>/<REPO>
TOPIC=<short-topic>                 # for example, required-checks
P=spike/probe-$TOPIC                # the disposable branch
RULESET=<id of the ruleset whose rule is under test>
OK=<commit the rule should accept>  # the positive control's target
NO=<commit the rule should refuse>  # the negative case's target
```

Pick `OK` and `NO` so that they differ only in what the rule examines. For example,
`93d4bf67` lacks the Terraform check result and its child `f43efeba` has all eight.

### Step 1: Preflight

```bash
gh api "$R/rules/branches/$P"       # expect []: no rule applies to the probe ref yet
gh api "$R/branches/$P"             # expect 404: the ref does not exist
gh api "$R/rulesets" --jq '.[] | "\(.id) \(.name) \(.enforcement)"' > rulesets.before
gh api "$R/rules/branches/main" --jq '[.[] | "\(.type)@\(.ruleset_id)"]' > main-rules.before
```

### Step 2: Create the disposable ref

```bash
TREE=$(gh api "$R/git/commits/$OK" --jq .tree.sha)
C0=$(gh api -X POST "$R/git/commits" -f message="[skip ci] probe: $TOPIC" \
       -f tree="$TREE" -f "parents[]=$OK" --jq .sha)
gh api -X POST "$R/git/refs" -f ref="refs/heads/$P" -f sha="$C0"
```

### Step 3: Copy the rule verbatim

```bash
PROBE=$(gh api "$R/rulesets/$RULESET" \
  | jq --arg ref "refs/heads/$P" --arg name "Probe $TOPIC" \
      '{name: $name, target: .target, enforcement: "active", bypass_actors: [],
        conditions: {ref_name: {include: [$ref], exclude: []}}, rules: .rules}' \
  | gh api -X POST "$R/rulesets" --input - --jq .id)
gh api "$R/rules/branches/$P" --jq '[.[] | "\(.type)@\(.ruleset_id)"]'   # expect only $PROBE
```

To probe a new ruleset instead of an existing one, create it here with the probe ref as its
only target.

### Step 4: Negative case

```bash
gh api -X PATCH "$R/git/refs/heads/$P" -f sha="$NO" -F force=true   # expect 422 and the rule's message
gh api "$R/git/ref/heads/$P" --jq .object.sha                       # expect $C0: the ref did not move
```

### Step 5: Positive control

```bash
gh api -X PATCH "$R/git/refs/heads/$P" -f sha="$OK" -F force=true   # expect 200
```

### Step 6: Clean up

```bash
gh api -X DELETE "$R/rulesets/$PROBE"
gh api -X DELETE "$R/git/refs/heads/$P"
```

To adopt a new ruleset, retarget it to the real ref (`PUT /repos/{owner}/{repo}/rulesets/{id}`
with new `conditions`) before deleting the probe ref, as ruleset 26377312 was. Then the rule
that was seen refusing is the rule that is applied.

### Step 7: Verify the cleanup

```bash
gh api "$R/rulesets" --jq '.[] | "\(.id) \(.name) \(.enforcement)"' | diff rulesets.before -
gh api "$R/rules/branches/main" --jq '[.[] | "\(.type)@\(.ruleset_id)"]' | diff main-rules.before -
gh api "$R/branches/$P"                                 # expect 404
gh api "$R/actions/runs?branch=$P" --jq .total_count    # expect 0: no workflow ran
gh api "$R/commits/$C0/check-runs" --jq .total_count    # expect 0
gh api "$R/activity?ref=refs/heads/$P" \
  --jq '.[] | "\(.timestamp) \(.activity_type) \(.before[0:8]) -> \(.after[0:8])"'
```

Installed GitHub Apps can create empty check suites on the probe commit. Those suites have no
check runs. The probe ref's activity log keeps the creation, the accepted move and the deletion,
but not the refused move.

## 4. Variants

- **Tag rules.** Use a disposable tag (`refs/tags/<probe-tag>`) in Steps 2 to 7. The copy keeps
  the live ruleset's `target: tag`.
- **A live rule whose conditions already cover a disposable ref.** The 2026-10-27 probe of tag
  ruleset 25965917 worked this way: its probe tag matched `refs/tags/v*`. Such a ref keeps the
  rule after the probe, so a `deletion` rule then refuses its removal. Prefer the verbatim copy.

## 5. What to record, and what a probe does not show

In the evidence document, record:
- the date;
- what was refused, with the response text;
- what was accepted;
- the probe ruleset's ID.

In the pull request's claims table, record each step's time and response.

A probe shows the rule's effect on the cases tried, on the day it ran. Other cases stay inferred
until probed, and the document says so. For example, POAM-2026-170 probed a commit with a
missing check result, but not a failed check or a pull request head.

## 6. Recorded probes

| Date | Rule under test | Negative case | Positive control | Record |
|---|---|---|---|---|
| 2026-10-27 | Tag ruleset 25965917 (`deletion`, `update`, `non_fast_forward`), live, on a probe tag inside its conditions | Deleting the tag: refused (`Cannot delete this tag`). Moving it by fast-forward: refused (`Cannot update this protected ref`) | Creating the tag: accepted | POAM-2026-116 |
| 2026-11-02 | Ruleset 26377312 (`non_fast_forward`, `deletion`), created against a probe branch and then retargeted to `main` | Force push and deletion: refused | Force push before the ruleset existed: accepted. Fast-forward under it: accepted | POAM-2026-170, Remediation |
| 2026-11-02 | Verbatim copy of 25966171's `required_status_checks` rule (ruleset 26398326, deleted afterwards) | Force push to `93d4bf67`, which has no Terraform result: refused (`Required status check "Terraform Tests (gcp-gke, mock providers)" is expected.`) | Force push to `f43efeba`, which has all eight: accepted | POAM-2026-170, Description |
