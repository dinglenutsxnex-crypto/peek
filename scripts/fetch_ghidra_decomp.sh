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

echo "Applying patches..."

# Patch 1: RawLoadImage::adjustVma null-deref guard (loadimage.cc).
sed -i \
  's/uint4 ws = spaceid->getWordSize();/uint4 ws = (spaceid != (AddrSpace *)0) ? spaceid->getWordSize() : 1;/' \
  "$DEST/loadimage.cc"

# Patch 2: expose RawBinaryArchitecture::adjustvma (raw_arch.hh).
# In Ghidra 12.1.2, adjustvma is private. Bracket it with public:/private:
# so decompiler_bridge.cpp can set it without modifying the rest of the class.
sed -i \
  's/  long adjustvma;/  public: long adjustvma; private:/' \
  "$DEST/raw_arch.hh"

rm -f "$ZIP"
echo "Done (2 patches applied). Run ./gradlew assembleDebug to build."
