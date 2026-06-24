# Anonymization And Security Rules

## Scope
- Applies to maintenance docs, issue summaries, release notes drafts, and AI-facing operating docs in this repository.

## Always Remove
- Absolute local file paths
- Usernames from workstation paths
- SDK, NDK, or tool installation directories
- Reporter email addresses, device names, and personal identifiers from crash descriptions
- Raw attachments or sample names that expose a private app or organization

## Allowed Forms
- Repo-relative paths such as `app/src/main/java/...`
- Generic environment references such as `Android SDK`, `local worktree`, or `CI`
- Sanitized examples like `sample.apk`, `target.so`, or `content://...`

## Issue And Crash Handling
- Preserve technical details needed for debugging: exception type, stack frame names, Android API level, file format, and repro steps.
- Remove personal package names unless they are public and required for diagnosis.
- If a sample file is needed, ask for a sanitized sample or a reproducible public test case.

## AI And Automation Notes
- AI guidance files must not embed machine-specific secrets or local environment details.
- Do not assume `google-services.json`, keystores, or signing identities are available outside the local environment unless documented as optional.
- When sharing commands in docs, keep them portable and avoid user-home-specific paths.
