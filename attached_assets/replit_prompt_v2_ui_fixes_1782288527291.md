# Continuation: UI rework + function-discovery fix

This continues the existing project (ARM64 .so analyzer, C++ analysis core +
Kotlin UI, SQLite cache). v1 is working — disassembly view, function list,
symbol list with EXP tags, and an XREFS button all function correctly. This
round is UI layout changes plus one real logic bug. No new analysis features,
no decompiler, no Python — still out of scope.

## Bug: functions discovered only by symbol, not by analysis

Currently the `functions` table appears to be populated only from symbol-table
entries (`.dynsym`/`.symtab`). This means any function that doesn't have an
exported/imported symbol name never gets a row in `functions` at all — it's
not being filtered out of a view, it was never inserted into the database in
the first place. This is why named functions like `JNI_OnLoad` show up but
nothing IDA-style named `sub_<address>` ever appears, even though the
binary's `.text` section obviously contains far more functions than just the
ones with public symbols.

Fix: add function discovery that doesn't depend on symbols existing.
Specifically, in the C++ analysis core:
- Treat every address that is a branch/call TARGET (from BL, B, B.cond, CBZ,
  CBNZ, TBZ, TBNZ instructions already being scanned for xrefs) as a
  candidate function start, if it isn't already known as one from the symbol
  table.
- For each such candidate start address with no symbol name, create a
  `functions` row and auto-generate the name `sub_<address_hex>` (e.g.
  `sub_4658`), matching IDA's convention. Use the same hex format already
  used elsewhere in the app (looks like uppercase, no `0x` prefix in the
  function list — check existing formatting in the `functions`/instruction
  display code and match it).
- Use prologue patterns as an additional/fallback heuristic if useful (e.g.
  `sub sp, sp, #imm` followed by stp of x29/x30 is a strong ARM64 function
  prologue signal, visible in the JNI_OnLoad example already in the app) —
  but the branch-target method above is the priority since it's already
  buildable from data the xref pass already computes.
- Determine each discovered function's extent (start to end address) using
  the same logic already used for symbol-based functions — don't special-case
  extent calculation for auto-discovered ones if existing logic generalizes.
- Re-run xref detection (or fold it into the same pass) so xrefs correctly
  point at these `sub_` functions too, not just symbol-named ones.

This should substantially increase the function count shown in the function
list — that's expected and correct, not a regression.

## UI rework

### Persistent left panel: function list
Convert the function list from its own separate full-screen destination into
a persistent panel docked to the left side of the main analysis screen. It
should always be visible while analyzing a binary (not a separate screen you
navigate away to). Tapping a function in this panel loads its disassembly in
the right-hand content area, replacing whatever was shown there — similar to
clicking a function in IDA's left-hand "Functions" subview.

Keep the existing search bar from the current Functions screen, just
relocate it to the top of this left panel.

### Top tab bar: Disassembly / Hex / Exports / Imports
Above the right-hand content area, add a horizontal tab bar (or similar
top-level selector — use whatever idiomatic Android component fits, e.g.
TabLayout) with these sections:
- **Disassembly** — the existing instruction listing view (offset/bytes/
  mnemonic/operands), scoped to whichever function is selected in the left
  panel
- **Hex** — a hex view of the binary (raw bytes view) — if this doesn't exist
  yet in any form, a basic hex dump of the current function's byte range is
  sufficient for this iteration; don't build a full standalone hex editor
- **Exports** — reuse the existing Symbols list logic, filtered to exported
  symbols only (the data already distinguishes import/export per the current
  Symbols screen's EXP tags)
- **Imports** — same Symbols data, filtered to imports only

The XREFS button/behavior from the current disassembly view should remain
accessible from within the Disassembly tab — don't remove that functionality,
just keep it inside this new layout.

Remove the now-redundant separate full-screen "Functions" and "Symbols"
destinations as standalone screens — their content moves into the left panel
(functions) and the Exports/Imports tabs (symbols), respectively.

### Full-screen / edge-to-edge layout
The current header bar is oversized and the layout doesn't use Android's
edge-to-edge display support. Fix:
- Enable edge-to-edge display (`WindowCompat.setDecorFitsSystemWindows(window,
  false)` or the current Android edge-to-edge API, whichever is appropriate
  for the project's target/min SDK — check what's already configured)
- Apply proper window insets handling so content isn't obscured by the status
  bar/system bars, but isn't pushed down by an oversized fixed header either
- Shrink the header/app bar to a standard compact toolbar height — the
  current header (showing just a back arrow and title) is taking up far more
  vertical space than that content needs

### Keep the current visual theme
Dark theme, the existing color choices (the blue-ish header color, dark
background, light text) should stay — this is a layout/structure change, not
a re-theme. Don't introduce a new color scheme.

## Out of scope (still)
- Decompiler / pseudocode
- Python scripting
- Dump-to-zip export
- Indirect/computed branch xref resolution
- Any new architecture/format support beyond ARM64 ELF

## Deliverable
The same app, restructured so the main analysis screen has a persistent
left-side function list (now including auto-discovered `sub_` functions, not
just symbol-named ones) and a top tab bar switching between Disassembly / Hex
/ Exports / Imports for the right-hand content, running edge-to-edge with a
properly sized header, same dark visual theme as before.
