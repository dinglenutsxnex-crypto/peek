#!/usr/bin/env bash
# Fetch Ghidra 12.1.2 decompiler C++ source locally.
# Run this once before building: ./scripts/fetch_ghidra_decomp.sh
set -euo pipefail

DEST="app/src/main/cpp/decompiler"
ZIP="/tmp/ghidra_decomp.zip"

echo "Downloading Ghidra 12.1.2 source..."
wget -q "https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/Ghidra_12.1.2_build.zip" -O "$ZIP"

echo "Extracting decompiler source..."
mkdir -p "$DEST"
python3 - << 'PYEOF'
import zipfile, os, sys
prefix = "ghidra-Ghidra_12.1.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/"
dest   = "app/src/main/cpp/decompiler"
os.makedirs(dest, exist_ok=True)
extracted = 0
with zipfile.ZipFile("/tmp/ghidra_decomp.zip") as z:
    for info in z.infolist():
        n = info.filename
        if n.startswith(prefix) and not n.endswith("/"):
            fname = os.path.basename(n)
            with z.open(info) as src, open(f"{dest}/{fname}", "wb") as dst:
                dst.write(src.read())
            extracted += 1
print(f"Extracted {extracted} files to {dest}")
if extracted == 0:
    sys.exit(1)
PYEOF

echo "Applying adjustVma null-deref guard..."
sed -i \
  's/uint4 ws = spaceid->getWordSize();/uint4 ws = (spaceid != (AddrSpace *)0) ? spaceid->getWordSize() : 1;/' \
  "$DEST/loadimage.cc"

rm -f "$ZIP"
echo "Done. Run ./gradlew assembleDebug to build."
