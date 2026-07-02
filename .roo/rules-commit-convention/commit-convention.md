# CAGE Commit Convention and Branch Strategy Enforcer

This rule instructs the agent to detect, apply, and self-validate the official
commit message **and branch naming** strategy of the Cybernetic Governance Engine
(CAGE) project. The conventions are defined in `CONTRIBUTING.md` and `.gitmessage`,
and enforced locally by `scripts/setup_git_hooks.sh` via a `commit-msg` hook using
the regex:

```
^(feat|fix|docs|style|refactor|perf|test|chore|ci|revert)(\([a-z0-9/_-]+\))?(!)?: .{1,72}$
```

---

## Step 1 — Detect the Convention

Before writing any commit message, confirm the project uses Conventional Commits
v1.0.0 by checking for `.gitmessage` and `CONTRIBUTING.md` at the repository root.
If both are present, apply all rules below unconditionally.

---

## Step 2 — Apply the Type Taxonomy

The commit type is **required** and must be exactly one of:

| Type       | When to use                                              |
|------------|----------------------------------------------------------|
| `feat`     | New feature visible to users or operators                |
| `fix`      | Bug fix                                                  |
| `docs`     | Documentation only — no logic change                     |
| `style`    | Formatting or whitespace — no logic change               |
| `refactor` | Code restructuring — no feature addition, no bug fix     |
| `perf`     | Performance improvement                                  |
| `test`     | Adding or correcting tests                               |
| `chore`    | Build system, dependency updates, tooling                |
| `ci`       | CI/CD pipeline changes                                   |
| `revert`   | Reverts a previous commit                                |

Do not invent new types. Do not use past-tense variants (e.g., `fixed`, `added`).

---

## Step 3 — Apply the Scope Vocabulary (Optional)

If a scope is included, it must be enclosed in parentheses immediately after the
type and must be exactly one of:

`gateway` | `compliance` | `infra` | `governance` | `tests` | `docs` | `ci` |
`agentsight` | `advisor` | `nemo` | `opa`

Scope is lowercase only. No underscores. No uppercase. No free-form values outside
this list. If the change spans multiple scopes, omit the scope rather than
inventing a compound scope.

---

## Step 4 — Format the Subject Line

The subject line must satisfy all of the following simultaneously:

1. **Structure:** `<type>(<scope>): <summary>` or `<type>: <summary>`
2. **Breaking change marker:** Append `!` before the colon for breaking changes:
   `feat(gateway)!: remove legacy REST endpoint`
3. **Imperative mood:** Write as a command. Use "add", not "added" or "adds".
   Use "fix", not "fixed" or "fixes". Use "remove", not "removed".
4. **Length:** ≤ 72 characters total (including type, scope, colon, space, and
   summary). Count every character.
5. **No trailing period:** The subject line must not end with `.`
6. **Lowercase summary start** unless the first word is a proper noun or acronym.

**Valid examples:**
```
feat(gateway): add Redis-backed rate limiter for OPA policy calls
fix(compliance): correct OSCAL component UUID collision on re-export
chore(ci): pin actions/checkout to SHA for supply-chain hardening
docs(governance): add STPA control structure diagram to ARCHITECTURE.md
refactor(infra): extract GKE node pool into reusable Terraform module
test(opa): add Rego unit tests for fiscal limit enforcement
perf(nemo): cache Colang rail compilation to reduce cold-start latency
```

**Invalid examples (and why):**
```
Added Redis rate limiter.          ← past tense, trailing period, no type
feat(gateway): Added rate limiter. ← past tense, trailing period
FEAT(GATEWAY): add rate limiter    ← uppercase type and scope
feat: update stuff                 ← vague summary
feat(unknown-scope): add feature   ← scope not in vocabulary
fix(compliance): correct the UUID collision issue in the OSCAL re-export pipeline that was causing idempotency failures  ← exceeds 72 chars
```

---

## Step 5 — Write the Body (Optional but Recommended)

- Separate the subject from the body with exactly **one blank line**.
- Wrap body lines at **72 characters**.
- Explain **what** changed and **why** — not how (the diff shows how).
- Reference design decisions, trade-offs, ADRs, or issue links.
- Do not repeat the subject line verbatim in the body.

**Example body:**
```
Implements token-bucket rate limiting at the gateway layer to prevent
OPA from being overwhelmed during burst traffic. Limit is configurable
via GOVERNANCE_THRESHOLDS_PATH. Chosen over leaky-bucket to allow
short bursts while maintaining average rate compliance.
```

---

## Step 6 — Write the Footer (Conditional)

Include footers only when applicable. Each footer token is on its own line,
separated from the body by one blank line.

| Situation | Footer format |
|---|---|
| Breaking change | `BREAKING CHANGE: <description of what breaks and migration path>` |
| Closes an issue | `Closes #<n>` |
| References an issue | `Refs #<n>` |
| Co-author | `Co-authored-by: Name <email@example.com>` |

**Coupling rule:** A `BREAKING CHANGE:` footer is **required** whenever `!`
appears in the subject line, and vice versa — both must be present together.

---

## Step 7 — Self-Validate Before Finalizing

Before outputting or staging the commit message, run through this checklist
internally and correct any failure before proceeding:

- [ ] Type is one of the 10 allowed values (exact lowercase match)
- [ ] Scope, if present, is one of the 11 allowed values (exact lowercase match)
- [ ] Subject line is ≤ 72 characters (count every character including spaces)
- [ ] Subject line uses imperative mood (no `-ed`, `-ing`, `-s` verb endings on
      the first verb unless grammatically required)
- [ ] Subject line does not end with a period
- [ ] Subject line and body are separated by exactly one blank line (if body present)
- [ ] Body lines are wrapped at ≤ 72 characters
- [ ] If `!` is in the subject, `BREAKING CHANGE:` footer is present
- [ ] If `BREAKING CHANGE:` footer is present, `!` is in the subject
- [ ] Issue references use `Closes #n` or `Refs #n` format (not `fixes`,
      `resolves`, `addresses`)

If any check fails, revise the message and re-run the checklist before finalizing.

---

## Step 8 — Apply to All Commit Contexts

Apply these rules in all of the following situations:

- When proposing a commit message for the user to use
- When generating a commit message from a diff or change description
- When amending an existing commit message
- When writing a PR title (PR titles become squash-merge commit messages and must
  also follow this format, per `CONTRIBUTING.md`)
- When generating CHANGELOG entries derived from commit messages
- When suggesting branch names (apply the Branch Strategy rules in Step 9 below)

Do not relax these rules based on commit size, urgency, or informality of the
change. A one-line typo fix still requires `fix(docs): correct typo in README`.

---

## Step 9 — Branch Naming Strategy

Apply these rules whenever creating, suggesting, or validating a branch name.

### Branch Taxonomy

| Purpose | Pattern | Example |
|---|---|---|
| New feature | `feat/<short-description>` | `feat/redis-rate-limiter` |
| Bug fix | `fix/<short-description>` | `fix/oscal-uuid-collision` |
| Documentation | `docs/<short-description>` | `docs/stpa-control-diagram` |
| Refactor | `refactor/<short-description>` | `refactor/gateway-middleware` |
| CI / tooling | `ci/<short-description>` | `ci/pin-actions-sha` |
| Hotfix on release | `hotfix/<version>-<description>` | `hotfix/2.0.1-redis-timeout` |
| Release candidate | `rc-v<semver>` | `rc-v2.1.0` |
| Experiment / spike | `spike/<short-description>` | `spike/cbf-formal-proof` |

### Branch Naming Rules

1. **Prefix must match intent:** Use the same type prefix as the primary commit
   type that will land on the branch (e.g., a branch containing `feat(gateway):`
   commits uses `feat/` prefix).
2. **Lowercase kebab-case only:** No underscores, no uppercase, no spaces.
   `feat/redis-rate-limiter` ✅ — `feat/Redis_RateLimiter` ❌
3. **Description length:** ≤ 30 characters after the prefix (not counting the
   prefix and slash).
4. **Hotfix format:** Must include the version being patched:
   `hotfix/<version>-<description>` e.g., `hotfix/2.0.1-redis-timeout`
5. **Release candidates:** Use exact semver: `rc-v<MAJOR>.<MINOR>.<PATCH>`
   e.g., `rc-v2.1.0`. Do not use `rc-v2.1` (missing patch) or `RC-v2.1.0`
   (uppercase).
6. **Delete after merge:** Always recommend deleting the branch after it is
   merged. Never reuse a merged branch name.
7. **No direct work on protected branches:** Never suggest committing directly
   to `main` or `rc-v*` branches. Always create a feature branch and open a PR.

### Branch-to-Commit Coherence

The branch prefix and the commit type must be coherent:

| Branch prefix | Expected commit types |
|---|---|
| `feat/` | `feat` |
| `fix/` | `fix` |
| `docs/` | `docs` |
| `refactor/` | `refactor` |
| `ci/` | `ci`, `chore` |
| `hotfix/` | `fix` |
| `spike/` | any (experimental) |

If a branch accumulates commits of a different type (e.g., a `feat/` branch
gains `fix` commits), that is acceptable — the branch prefix reflects the
primary intent, not every commit.

### Protected Branch Rules

| Branch | Rule |
|---|---|
| `main` | No direct push. Requires PR + CI green + 1 reviewer approval. |
| `rc-v*` | No direct push. Requires PR + CI green. |

When the user asks to commit or push directly to `main` or `rc-v*`, refuse and
instead suggest creating a feature branch and opening a PR.

### Branch Naming Self-Validation

Before suggesting or creating a branch name, verify:

- [ ] Prefix is one of the 8 allowed types (feat, fix, docs, refactor, ci,
      hotfix, rc-v, spike)
- [ ] Description is lowercase kebab-case only (no underscores, no uppercase)
- [ ] Description is ≤ 30 characters after the prefix and slash
- [ ] Hotfix branches include the version number
- [ ] Release candidate branches use exact `rc-v<semver>` format
- [ ] Branch is not `main` or `rc-v*` (protected — no direct work)

---

## Quick Reference Card

```
BRANCH NAMING
─────────────
feat/<desc>          fix/<desc>           docs/<desc>
refactor/<desc>      ci/<desc>            spike/<desc>
hotfix/<ver>-<desc>  rc-v<semver>

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
```

Types:    feat | fix | docs | style | refactor | perf | test | chore | ci | revert
Scopes:   gateway | compliance | infra | governance | tests | docs | ci |
          agentsight | advisor | nemo | opa
