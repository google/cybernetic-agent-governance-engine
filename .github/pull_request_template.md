## Summary

<!-- One paragraph: what does this PR do and why? -->

## Type of Change

<!-- Check all that apply -->
- [ ] `feat` — new feature
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `refactor` — no feature/fix, code restructuring
- [ ] `perf` — performance improvement
- [ ] `test` — test additions or corrections
- [ ] `chore` — build, deps, tooling
- [ ] `ci` — CI/CD pipeline
- [ ] `BREAKING CHANGE` — existing behaviour changes

## Related Issues / ADRs

<!-- Closes #<n> | Refs #<n> | N/A -->

## Changes Made

<!-- Bullet list of specific files / components changed and why -->
-
-

## Testing

<!-- How was this tested? Check all that apply -->
- [ ] Unit tests added / updated (`pytest tests/`)
- [ ] Integration tests pass (`make test-integration`)
- [ ] Manual smoke test performed (describe below)
- [ ] No tests needed (docs/config only — explain why)

**Manual test steps (if applicable):**
```
# paste commands here
```

## Compliance & Security Checklist

- [ ] No secrets, credentials, or PII in committed files
- [ ] OPA policy changes reviewed for correctness
- [ ] OSCAL/NIST control mappings updated if behaviour changed
- [ ] Lula validation still passes (`lula validate`)
- [ ] Network policy unchanged or reviewed by security owner

## Deployment Notes

<!-- Any migration steps, env var changes, or rollout considerations? -->
N/A

## PR Title Format

> Ensure your PR title follows Conventional Commits: `type(scope): description`
> It will become the squash-merge commit message on the integration branch.
