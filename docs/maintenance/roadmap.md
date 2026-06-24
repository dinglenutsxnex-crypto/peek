# Maintenance Roadmap

## Objective
- Restore Android-Disassembler to a state where long-open issues can be handled systematically and the app can be modernized for current Android requirements.

## Wave 1: Baseline Recovery
- Initialize and verify all required submodules.
- Restore deterministic Gradle verification on a clean checkout.
- Add minimal regression tests around `ProjectManager`, hex rendering helpers, and immediate issue fixes.
- Review and absorb the existing local fix branches for launcher visibility, hex layout, and disassembly scroll behavior.

## Wave 2: Android Compatibility
- Replace legacy result APIs with `ActivityResultContracts`.
- Move external file selection toward SAF-first flows.
- Reduce obsolete storage permissions and remove `requestLegacyExternalStorage`.
- Re-evaluate package visibility and keep only the smallest required manifest declarations.

## Wave 3: Issue Backlog Reduction
- Resolve issue buckets in this order:
  1. Existing branch-backed fixes
  2. Reproducible crash reports
  3. Android policy and storage issues
  4. Focused parser and UX improvements
- Close or relabel low-signal issues using the triage guide.

## Wave 4: Release Preparation
- Raise `targetSdkVersion` to current Play requirements.
- Refresh CI to match the verified local build path.
- Update README and support docs to reflect supported Android behavior and privacy notes.
- Decide packaging and release strategy only after the baseline is stable.

## Exit Criteria For The Baseline Wave
- `testDebugUnitTest` passes from a clean checkout with initialized submodules.
- The maintenance docs exist and are internally consistent.
- The three immediate issue-fix branches have been reviewed and either absorbed or superseded.
- Storage modernization has started with concrete code changes, not just TODO notes.
