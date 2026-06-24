# Issue Triage Guide

## Goal
- Process long-open issues consistently while the project is being revived.
- Separate baseline blockers, valid bug reports, and low-signal feature requests.

## Required Statuses
- `baseline-blocked`
- `needs-repro`
- `covered-by-open-pr`
- `obsolete-or-policy-invalid`
- `planned-fast-follow`

## Supplemental Labels
- `future-scope`

## Label Rules
### `future-scope`
- Use when an issue is a legitimate future capability, but it is outside the current maintenance baseline.
- Do not close these as `not planned` if the intent is "later, not now".
- Keep them open with the `future-scope` label so they remain visible without polluting the active maintenance slice.
- Typical cases: recompile/edit workflows, advanced code reconstruction, power-user automation features that are not needed for baseline recovery.

## Decision Rules
### `baseline-blocked`
- Use when the issue cannot be evaluated until the repository builds or tests again.
- Typical cases: parser regressions hidden behind compile failures, Android policy issues blocked by outdated build config.

### `needs-repro`
- Use when the report lacks enough detail to reproduce locally.
- Ask for exact file type, Android version, app version, and minimal steps.
- Do not guess a fix from the title alone.

### `covered-by-open-pr`
- Use when an existing branch or PR already targets the same behavior.
- Review the branch first, then either merge it locally, supersede it, or close the issue with reference.

### `obsolete-or-policy-invalid`
- Use when the request is duplicated, too vague to action after follow-up, incompatible with modern Android policy, or outside the core maintenance scope.
- Record a short reason before closing.

### `planned-fast-follow`
- Use when the issue is valid but intentionally postponed until after baseline recovery.
- This is the default bucket for larger feature requests such as new file formats unless they unblock a critical bug.

## First-Pass Buckets
- Baseline and policy: `#95`, release/build work, storage access regressions.
- Covered by existing branches: `#670`, `#396`, `#348`, release workflow work related to `#719`.
- Needs repro: crash reports without file samples or exact steps.
- Planned fast follow: broad parser support requests such as SWF/OBB/AR/resource format expansion.

## Comment Templates
### Baseline blocked
> This is valid, but it is currently blocked on the maintenance baseline work. I am keeping it open while restoring build/test reliability and modern Android compatibility first.

### Needs repro
> I could not reproduce this from the current report alone. Please share the exact app version, Android version, file type, and a minimal set of steps or a sanitized sample that triggers the issue.

### Covered by open PR
> There is already an open branch/PR covering this behavior. I am reviewing that work first so we do not duplicate fixes.

### Obsolete or policy invalid
> I reviewed this against the current maintenance scope and modern Android constraints. I am closing it because it is either duplicated, too ambiguous to action, or no longer compatible with the supported platform direction.

### Planned fast follow
> This request is in scope, but I am deferring it until the baseline recovery and Android policy modernization work are complete.
