#include "peek_architecture.h"
#include "peek_load_image.h"
#include "peek_scope.h"
#include "decompiler/database.hh"

using namespace ghidra;

PeekArchitecture::PeekArchitecture(const ElfParseResult& elf, std::ostream* errs)
    : SleighArchitecture("peek_elf", "AARCH64:LE:64:v8A", errs),
      elf_(elf) {}

void PeekArchitecture::buildLoader(DocumentStorage&) {
    auto* ldr = new PeekLoadImage(elf_);
    if (patch_bytes_) ldr->setPatch(patch_bytes_, patch_addr_, patch_len_);
    loader = ldr;
}

Scope* PeekArchitecture::buildDatabase(DocumentStorage&) {
    symboltab = new Database(this, false);
    auto* scope = new PeekScope(this, elf_);
    peek_scope_ = scope;
    symboltab->attachScope(scope, nullptr);
    return scope;
}

// Mirror R2Architecture::buildCoreTypes — stdint names instead of Ghidra's
// byte/word/dword/qword so the decompiler emits readable C types.
void PeekArchitecture::buildCoreTypes(DocumentStorage&) {
    types->setCoreType("void",      1,  TYPE_VOID,    false);
    types->setCoreType("bool",      1,  TYPE_BOOL,    false);
    types->setCoreType("bool4",     4,  TYPE_BOOL,    false);
    types->setCoreType("uint8_t",   1,  TYPE_UINT,    false);
    types->setCoreType("uint16_t",  2,  TYPE_UINT,    false);
    types->setCoreType("uint32_t",  4,  TYPE_UINT,    false);
    types->setCoreType("uint64_t",  8,  TYPE_UINT,    false);
    types->setCoreType("int8_t",    1,  TYPE_INT,     false);
    types->setCoreType("int16_t",   2,  TYPE_INT,     false);
    types->setCoreType("int32_t",   4,  TYPE_INT,     false);
    types->setCoreType("int64_t",   8,  TYPE_INT,     false);
    types->setCoreType("float",     4,  TYPE_FLOAT,   false);
    types->setCoreType("double",    8,  TYPE_FLOAT,   false);
    types->setCoreType("float10",   10, TYPE_FLOAT,   false);
    types->setCoreType("float16",   16, TYPE_FLOAT,   false);
    types->setCoreType("char",      1,  TYPE_INT,     true);
    types->setCoreType("wchar",     2,  TYPE_INT,     true);
    types->setCoreType("char16_t",  2,  TYPE_INT,     true);
    types->setCoreType("char32_t",  4,  TYPE_INT,     true);
    types->setCoreType("code",      1,  TYPE_CODE,    false);
    types->setCoreType("uchar",     1,  TYPE_UNKNOWN, false);
    types->setCoreType("ushort",    2,  TYPE_UNKNOWN, false);
    types->setCoreType("uint",      4,  TYPE_UNKNOWN, false);
    types->setCoreType("ulong",     8,  TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
}
