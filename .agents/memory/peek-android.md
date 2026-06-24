---
name: PEEK Android project
description: Key decisions and constraints for the PEEK ARM64 .so analyzer Android project
---

## Key decisions

**No Replit workflow / web preview**
This is a pure Android NDK project. There is no web server component.
Development happens in Replit; builds happen via GitHub Actions.

**Why:** Android APK builds require Android SDK + NDK which are not available in Replit's standard container.

**Capstone 5.x arch constant**
Capstone 5.0 renamed `CS_ARCH_ARM64` → `CS_ARCH_AARCH64`. disassembler.cpp uses a `#if defined(CS_ARCH_AARCH64)` guard to support both.

**SQLite vendoring**
SQLite is pulled via CMake FetchContent (amalgamation ZIP from sqlite.org, no hash check to avoid stale-hash build failures). Android's system libsqlite was not used — version variance across API levels.

**How to apply:** When updating SQLite version, update the URL in `CMakeLists.txt`. Do NOT add back a URL_HASH without verifying it first.

**minSdk = 26**
All mipmap icons use adaptive-icon XML format (no PNG bitmaps needed).
mipmap-anydpi-v26/ is the canonical icon location.

**Gradle wrapper JAR not committed**
`gradle/wrapper/gradle-wrapper.jar` is not in the repo. CI uses `gradle/actions/setup-gradle@v3` which bootstraps it automatically. Local developers must run `gradle wrapper --gradle-version 8.7` once.
