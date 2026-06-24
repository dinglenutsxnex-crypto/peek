# Continuation v3: layout/inset fixes, import-detection fix, divider/selection polish

This continues the existing PEEK project. I reviewed the actual source for
this round, so the items below point at specific files/lines rather than just
symptoms — please fix root causes, not just visual symptoms.

## Bug 1: Header overlap (root cause confirmed)

In `AnalysisActivity.kt`, the insets listener does:
```kotlin
b.toolbar.updatePadding(top = bars.top)
```
But in `activity_analysis.xml`, the toolbar's height is fixed:
```xml
android:layout_height="?attr/actionBarSize"
```
Adding top padding to a toolbar with a fixed height squeezes its actual
content (title text, back button) into less vertical space and pushes it
toward/behind the status bar — this is the overlap visible in the
screenshots, not a simple "needs more padding" issue.

Fix: change the toolbar's height to `wrap_content`, and give it a minimum
height of `?attr/actionBarSize` via `android:minHeight` instead of
`android:layout_height`, so the status-bar-inset padding added at runtime
increases the toolbar's total height rather than compressing its content.
Apply the same pattern (`minHeight` + `wrap_content`, inset added as padding)
to any other fixed-height top bars in the app (check `tabLayout` in the same
file — `layout_height="44dp"` is also fixed; confirm whether it needs the
same inset treatment or sits below the toolbar safely once the toolbar fix
lands).

Also remove the back arrow from the toolbar (`setDisplayHomeAsUpEnabled(true)`
in `AnalysisActivity.kt` `onCreate`) — set it to `false`, and instead just show
the loaded file name as the toolbar title (this already happens via
`title = intent.getStringExtra(EXTRA_NAME) ?: "PEEK"` — keep that, just drop
the back-arrow nav icon).

## Bug 2: System bars still showing despite edge-to-edge attempt

`WindowCompat.setDecorFitsSystemWindows(window, false)` is already called, and
bottom inset is applied to `bottomBarrier`. But screenshots show the system
status bar / nav area still visibly present and not blending into the app.
Check and fix:
- Confirm `bottomBarrier`'s height ends up correctly sized — it's currently
  `layout_height="0dp"` with no `layout_weight`, meaning the bottom inset
  padding added at runtime is likely the only thing giving it size. Verify
  this actually reserves visible space at the bottom rather than rendering
  as zero-height (check whether content is hidden behind the nav bar — if
  so this is the cause).
- Consider whether status/navigation bar background colors need to be set to
  match the app's dark background explicitly (transparent system bars over a
  light default scrim can look like "system UI still showing" even when
  layout is technically edge-to-edge) — check `themes.xml` for any
  `android:statusBarColor`/`android:navigationBarColor` overrides that might
  be fighting the edge-to-edge setup, and align them with `@color/bg_dark` or
  remove them in favor of fully transparent bars if targeting a high enough
  minSdk for that to look right.
- Apply the same edge-to-edge + inset pattern actually used in
  `AnalysisActivity.kt` to every other Activity in the app
  (`MainActivity`, `DisassemblyActivity`, `XrefActivity`, `SymbolsActivity`,
  `FunctionListActivity`) if they don't already have it — check each for
  consistency, since a mix of edge-to-edge and non-edge-to-edge screens will
  look jarring when navigating between them.

## Bug 3: Imports always empty (root cause confirmed)

In `elf_parser.cpp`, symbol import detection is:
```cpp
ps.is_import = (sym->st_shndx == 0) || is_import_section;
```
And both call sites pass `is_import_section = false`:
```cpp
parse_syms(dynsym_off, dynsym_size, dynstr_off, dynstr_size, false);
parse_syms(symtab_off, symtab_size, strtab_off, strtab_size, false);
```
So `is_import` can only ever become true via `st_shndx == 0` (`SHN_UNDEF`).
On real Android `.so` files, many externally-resolved symbols (libc/bionic
calls, etc.) are represented in `.dynsym` with a defined, non-zero section
index pointing at PLT/GOT-related sections rather than `SHN_UNDEF` — so this
check is too strict and is likely matching nothing in practice, which matches
the "always empty, regardless of file" symptom.

Fix: broaden import detection. A symbol parsed from `.dynsym` should be
considered an import if any of these hold:
- `st_shndx == SHN_UNDEF` (0) — keep this as one signal, not the only one
- The symbol has no corresponding size/definition (e.g. `st_value == 0` for
  a function-type symbol that's still referenced) — cross-check against
  existing logic at line 265 (`if (sym->st_value == 0 && sym->st_size == 0)
  continue;`) to make sure legitimate imports aren't being skipped entirely
  before they even reach the `is_import` check
- The symbol's section, if resolvable, is `.plt` or similarly named
  PLT/stub section — check section name against the parsed `res.sections`
  list (already populated earlier in the same function) by index/address if
  `st_shndx` is non-zero, and treat a match against PLT-like sections as an
  import too
- The symbol is referenced in `.rela.dyn`/`.rela.plt` relocation entries
  without a corresponding local definition — if relocations aren't already
  being parsed elsewhere in `elf_parser.cpp`, this is a heavier addition;
  only do this if the simpler signals above still leave verified-import
  symbols undetected on a real test binary

After the fix, test against the actual binary used in the screenshots
(`libSMGP.so` if available, or any similar real-world Android `.so`) to
confirm imports actually appear — "always empty across every file tried" was
the reported symptom, so verify the fix produces a non-empty, sensible list,
not just that the code compiles.

## UI polish

### Resizable divider between function list and content panel
Currently the divider between the left function panel and right content area
is a static `1dp` `View` with `match_parent` height and no interaction — purely
decorative. Replace it with a draggable divider:
- Increase its touch target (visually can stay slim, e.g. 1-2dp, but wrap it
  in a wider invisible touch area, e.g. 12-16dp, so it's actually grabbable
  with a finger)
- Implement drag-to-resize: dragging it left/right should adjust the function
  panel's width (currently fixed at `160dp` in `activity_analysis.xml`) within
  reasonable min/max bounds (e.g. min ~100dp so it doesn't collapse unusably
  small, max ~50% of screen width so the content panel doesn't get crushed)
- Show a subtle visual affordance on touch/hover (e.g. brief highlight color
  change) so it's discoverable as draggable

### Selected function highlight
In the function list (`FunctionCompactAdapter`/`item_function_compact.xml`),
the currently-selected/open function doesn't visually differ from the rest —
there's no way to tell what's currently loaded in the content panel at a
glance. Add a selected-state background color (a subtle highlight distinct
from the normal row background, consistent with the existing dark theme
palette in `colors.xml`) that updates as the user taps different functions,
and persists correctly when the list scrolls (this needs to be handled via
the adapter tracking a selected position/address and notifying on change, not
just a one-off view background set that breaks on RecyclerView recycling).

### General cleanup
- Audit spacing/padding consistency across the function list, tab bar, and
  content panel now that the header height is fixed — make sure nothing else
  looks cramped or misaligned as a side effect of the header fix
- Keep the existing dark theme/colors as-is — this round is layout/logic
  fixes, not a re-theme

## Out of scope (still)
Decompiler, Python scripting, dump-to-zip, indirect xref resolution, non-ARM64
formats — unchanged from before.

## Deliverable
Header no longer overlaps system status bar and shows only the loaded file
name (no back arrow); edge-to-edge is consistent and system bars don't visibly
intrude anywhere in the app; imports tab shows real data on actual test
binaries; the function-list/content divider is draggable; the selected
function is visually highlighted in the list.
