# Skill: git-workflow-standards

Apply the CAGE project's official Git commit message format, branch naming strategy, and pull request process as defined in [`docs/GIT_WORKFLOW_STANDARDS.md`](../../docs/GIT_WORKFLOW_STANDARDS.md).

---

## When to invoke this skill

Use this skill whenever you need to:

- Write or validate a commit message
- Suggest or create a branch name
- Draft a PR title
- Generate CHANGELOG entries from commits
- Advise on the PR lifecycle or merge strategy
- Respond to questions about the project's Git conventions

---

## Step 1 — Commit Message Format

Every commit must follow **Conventional Commits v1.0.0**. The `commit-msg` hook (installed via `bash scripts/setup_git_hooks.sh`) enforces the subject line at commit time.

### Structure

```
<type>(<scope>): <short summary>

[optional body — wrap at 72 chars]

[optional footers]
```

### Valid types (exactly one required)

| Type | When to use |
|---|---|
| `feat` | New feature visible to users or operators |
| `fix` | Corrects a defect in existing behaviour |
| `docs` | Documentation changes only — no code logic altered |
| `style` | Whitespace, formatting — zero logic change |
| `refactor` | Code restructuring — no feature, no bug fix |
| `perf` | Performance improvement without behaviour change |
| `test` | Adding or correcting tests |
| `chore` | Build system, dependency bumps, tooling |
| `ci` | CI/CD pipeline configuration or scripts |
| `revert` | Reverts a previous commit; subject must reference the reverted SHA |

### Valid scopes (optional, exactly one if used)

`gateway` · `compliance` · `infra` · `governance` · `tests` · `docs` · `ci` · `agentsight` · `advisor` · `nemo` · `opa`

### Subject line rules

1. Format: `<type>(<scope>): <summary>` or `<type>: <summary>`
2. Breaking change: append `!` before the colon — `feat(gateway)!: remove legacy endpoint`
3. **Imperative mood** — "add", not "added" or "adds"
4. **≤ 72 characters** total (count every character)
5. **No trailing period**
6. Lowercase first word of summary (unless proper noun/acronym)

### Body rules

- Separate from subject with exactly **one blank line**
- Wrap at **72 characters** per line
- Explain **what** changed and **why** — not how (the diff shows how)
- Do not repeat the subject verbatim

### Footer rules

| Situation | Footer |
|---|---|
| Breaking change | `BREAKING CHANGE: <description>` — **required** when `!` is in subject |
| Closes issue | `Closes #<n>` |
| References issue | `Refs #<n>` |
| Co-author | `Co-authored-by: Name <email>` |

**Coupling rule:** `!` in subject ↔ `BREAKING CHANGE:` footer — both must appear together.

### Self-validation checklist

Before finalising any commit message:

- [ ] Type is one of the 10 allowed values (exact lowercase)
- [ ] Scope, if present, is one of the 11 allowed values (exact lowercase)
- [ ] Subject line ≤ 72 characters
- [ ] Imperative mood (no `-ed`, `-ing`, `-s` verb endings on first verb)
- [ ] No trailing period
- [ ] Subject and body separated by exactly one blank line (if body present)
- [ ] Body lines wrapped at ≤ 72 characters
- [ ] If `!` in subject → `BREAKING CHANGE:` footer present
- [ ] If `BREAKING CHANGE:` footer present → `!` in subject
- [ ] Issue refs use `Closes #n` or `Refs #n` (not `fixes`, `resolves`)

### Valid examples

```
fix(compliance): correct OSCAL component UUID collision on re-export
feat(gateway): add Redis-backed rate limiter for OPA policy calls
chore(ci): pin actions/checkout to SHA for supply-chain hardening
docs(governance): add STPA control structure diagram to ARCHITECTURE.md
```

### Invalid examples

```
Added Redis rate limiter.          ← past tense, trailing period, no type
feat(gateway): Added rate limiter. ← past tense, trailing period
FEAT(GATEWAY): add rate limiter    ← uppercase type and scope
feat: update stuff                 ← vague summary
feat(unknown-scope): add feature   ← scope not in vocabulary
```

---

## Step 2 — Branch Naming

All branch names must use **lowercase kebab-case**. No underscores. No uppercase. No spaces.

### Branch taxonomy

| Purpose | Pattern | Example |
|---|---|---|
| New feature | `feat/<ticket-id>-description` | `feat/42-redis-rate-limiter` |
| Bug fix | `fix/<ticket-id>-description` | `fix/18-oscal-uuid-collision` |
| Documentation | `docs/<description>` | `docs/stpa-control-diagram` |
| Refactor | `refactor/<description>` | `refactor/gateway-middleware` |
| CI / tooling | `ci/<description>` | `ci/pin-actions-sha` |
| Chore | `chore/<description>` | `chore/pin-ci-actions-sha` |
| Hotfix | `hotfix/<ticket-id>-description` | `hotfix/99-redis-timeout` |
| Release candidate | `release/v<X.Y.Z>` | `release/v2.1.0` |
| Experiment / spike | `spike/<description>` | `spike/cbf-formal-proof` |

### Branch naming rules

1. Ticket ID required in `feat/` and `fix/` branches; optional elsewhere
2. Description segment after prefix ≤ **30 characters**
3. Lowercase kebab-case only — `feat/redis-rate-limiter` ✅ — `feat/Redis_RateLimiter` ❌
4. Delete branch after merge — never reuse a merged branch name
5. **Never** suggest committing directly to `main` or `rc-v*`

### Protected branches

| Branch | Rule |
|---|---|
| `main` | No direct push. PR + CI green + ≥1 maintainer approval required. |
| `rc-v*` | No direct push. PR + CI green required. |

CI triggers on `push`/`pull_request` to `main`, `rc-v2.0.0`, and `release/**`.

### Branch self-validation checklist

- [ ] Prefix is one of the allowed types
- [ ] Description is lowercase kebab-case only
- [ ] Description ≤ 30 characters after prefix and slash
- [ ] Hotfix branches include the version number
- [ ] Branch is not `main` or `rc-v*` (protected)

---

## Step 3 — Pull Request Standards

### PR title

The PR title becomes the squash-merge commit message. It **must** follow Conventional Commits format exactly — same rules as a commit subject line.

### PR lifecycle (8 mandatory steps)

1. **Branch** from the integration branch (always `git pull` first)
2. **Atomic commits** — one logical unit per commit; split if you write "and" in the subject
3. **Push** the feature branch
4. **Open PR** — title = valid Conventional Commits subject; template auto-populated from `.github/pull_request_template.md`; complete every section
5. **Pass CI** — License Guard (`.github/workflows/license_guard.yml`) + CI suite (`.github/workflows/ci.yml`) must be green
6. **Obtain ≥1 maintainer approval** — author may not approve own PR
7. **Squash merge** — required strategy for all feature/fix/chore/docs/ci/refactor PRs; merge commits reserved for release branch → `main` merges
8. **Delete branch** — remote (GitHub button) and local (`git branch -d <name>`)

### Prohibited practices

- Direct commits to `main` or `rc-v*`
- Vague commit messages: `WIP`, `fix stuff`, `update`, `misc changes`, `done`
- Skipping `bash scripts/setup_git_hooks.sh` after cloning
- Incomplete PR template (empty Summary, unchecked compliance boxes)
- Force-pushing to shared branches (`--force-with-lease` acceptable on unshared feature branches only)
- Merging with failing CI
- Mega-commits (>~20 files or ~500 lines, excluding generated files)

---

## Quick Reference

```
BRANCH NAMING
─────────────
feat/<ticket-id>-<desc>    fix/<ticket-id>-<desc>    docs/<desc>
refactor/<desc>             ci/<desc>                 chore/<desc>
hotfix/<ticket-id>-<desc>  release/v<X.Y.Z>          spike/<desc>

Rules: lowercase kebab-case · ≤30 chars after prefix · delete after merge
Protected: main, rc-v* → PR required, no direct push

COMMIT FORMAT
─────────────
<type>(<scope>): <imperative summary, ≤72 chars, no trailing period>

<optional body, wrapped at 72 chars, explains what and why>

<optional footers>
BREAKING CHANGE: <description>   ← required if ! used in subject
Closes #<n>
Refs #<n>
Co-authored-by: Name <email>

Types:  feat | fix | docs | style | refactor | perf | test | chore | ci | revert
Scopes: gateway | compliance | infra | governance | tests | docs | ci |
        agentsight | advisor | nemo | opa
```
