# Power-User Import Mode Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep SAF as the default import path while exposing advanced non-SAF import entry points only when power-user mode is enabled.

**Architecture:** Add a small import entry-point catalog interface, a settings wrapper for the power-user toggle, and gate the advanced chooser behind that toggle. Keep standard imports on direct SAF and leave advanced browsing in `NewFileChooserActivity`.

**Tech Stack:** Android Views preferences, Jetpack Compose, Activity Result API, existing shared preferences, JUnit5.

---

## Chunk 1: Import entry-point boundary

### Task 1: Add failing unit test for entry-point visibility

**Files:**
- Test: `app/src/test/java/com/kyhsgeekcode/disassembler/importing/ImportEntryPointCatalogTest.kt`

- [ ] Step 1: Write failing test for standard mode
- [ ] Step 2: Run `./gradlew testDebugUnitTest --tests com.kyhsgeekcode.disassembler.importing.ImportEntryPointCatalogTest`
- [ ] Step 3: Add `ImportEntryPoint` and `ImportEntryPointCatalog`
- [ ] Step 4: Re-run the test until green

### Task 2: Use catalog in project overview

**Files:**
- Create: `app/src/main/java/com/kyhsgeekcode/disassembler/importing/ImportEntryPointCatalog.kt`
- Modify: `app/src/main/java/com/kyhsgeekcode/disassembler/ui/MainTab.kt`

- [ ] Step 1: Render buttons from visible entry points
- [ ] Step 2: Keep `Select file` on direct SAF
- [ ] Step 3: Add `Advanced import` launch path
- [ ] Step 4: Run `./gradlew testDebugUnitTest assembleDebug`

## Chunk 2: Power-user settings boundary

### Task 3: Add settings wrapper

**Files:**
- Create: `app/src/main/java/com/kyhsgeekcode/disassembler/preference/PowerUserModeSettings.kt`
- Modify: `app/src/main/java/com/kyhsgeekcode/disassembler/preference/SettingsFragment.kt`
- Modify: `app/src/main/res/xml/pref_settings.xml`
- Modify: `app/src/main/res/xml-v30/pref_settings.xml`
- Modify: `app/src/main/res/values/strings.xml`

- [ ] Step 1: Add toggle preference XML
- [ ] Step 2: Add wrapper object for preference reads
- [ ] Step 3: Make `ProjectOverview` refresh setting on resume
- [ ] Step 4: Run `./gradlew testDebugUnitTest assembleDebug`

## Chunk 3: Advanced chooser gating

### Task 4: Gate advanced root items

**Files:**
- Modify: `app/src/main/java/com/kyhsgeekcode/filechooser/NewFileChooserActivity.kt`
- Modify: `app/src/main/java/com/kyhsgeekcode/filechooser/NewFileChooserAdapter.kt`
- Modify: `app/src/main/java/com/kyhsgeekcode/filechooser/model/FileItem.kt`

- [ ] Step 1: Add chooser extra for power-user mode
- [ ] Step 2: Restrict advanced root items to power-user mode
- [ ] Step 3: Keep direct SAF import outside chooser
- [ ] Step 4: Run `./gradlew testDebugUnitTest assembleDebug`

## Chunk 4: Final verification

### Task 5: Verify and commit

**Files:**
- Modify as needed based on verification failures

- [ ] Step 1: Run `JAVA_HOME=$(/usr/libexec/java_home -v 17) ANDROID_HOME=$HOME/Library/Android/sdk ./gradlew testDebugUnitTest assembleDebug`
- [ ] Step 2: Update maintenance docs if behavior changed
- [ ] Step 3: Commit feature in a focused commit

