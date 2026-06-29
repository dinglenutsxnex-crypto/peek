/**
 * il2cpp_metadata.cpp — IL2CPP metadata + ELF parser, ported from Il2CppDumper (C#).
 *
 * Supports global-metadata.dat versions 24.2–31 (Unity 2018.3 – Unity 6).
 * ARM64 ELF only (matching PEEK's ABI target).
 *
 * Key outputs: a list of (virtual address → method name) pairs that PEEK
 * uses to rename functions discovered by its normal analysis pipeline.
 */

#include "il2cpp_metadata.h"

#include <android/log.h>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <unordered_map>

#define TAG  "Il2CppParser"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// ELF64 structures (ARM64)
// ---------------------------------------------------------------------------

#pragma pack(push, 1)

struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;   // 0xB7 = AArch64
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Dyn {
    int64_t  d_tag;
    uint64_t d_un;
};

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

#pragma pack(pop)

static const uint32_t PT_LOAD    = 1;
static const uint32_t PT_DYNAMIC = 2;
static const int64_t  DT_NULL    = 0;
static const int64_t  DT_STRTAB  = 5;
static const int64_t  DT_SYMTAB  = 6;
static const int64_t  DT_HASH    = 4;
static const int64_t  DT_GNU_HASH= 0x6ffffef5;

// ---------------------------------------------------------------------------
// Safe memory reader
// ---------------------------------------------------------------------------

struct Reader {
    const uint8_t* data;
    size_t         size;

    template<typename T>
    bool read(uint64_t off, T& out) const {
        if (off + sizeof(T) > size) return false;
        memcpy(&out, data + off, sizeof(T));
        return true;
    }

    const char* str(uint64_t off) const {
        if (off >= size) return "";
        return reinterpret_cast<const char*>(data + off);
    }
};

// ---------------------------------------------------------------------------
// ELF helpers
// ---------------------------------------------------------------------------

struct Segment {
    uint64_t vaddr;
    uint64_t vend;
    uint64_t foff;
    uint64_t fend;
};

static uint64_t vatr(const std::vector<Segment>& segs, uint64_t va) {
    for (auto& s : segs) {
        if (va >= s.vaddr && va < s.vend)
            return s.foff + (va - s.vaddr);
    }
    return UINT64_MAX;
}

template<typename T>
static bool read_va(const Reader& r, const std::vector<Segment>& segs, uint64_t va, T& out) {
    uint64_t off = vatr(segs, va);
    if (off == UINT64_MAX) return false;
    return r.read(off, out);
}

template<typename T>
static bool read_va_array(const Reader& r, const std::vector<Segment>& segs,
                          uint64_t va, uint64_t count, std::vector<T>& out) {
    uint64_t off = vatr(segs, va);
    if (off == UINT64_MAX) return false;
    uint64_t bytes = count * sizeof(T);
    if (off + bytes > r.size) return false;
    out.resize(count);
    memcpy(out.data(), r.data + off, bytes);
    return true;
}

static std::string read_va_str(const Reader& r, const std::vector<Segment>& segs, uint64_t va) {
    uint64_t off = vatr(segs, va);
    if (off == UINT64_MAX) return "";
    if (off >= r.size) return "";
    size_t max_len = r.size - off;
    size_t len = strnlen(reinterpret_cast<const char*>(r.data + off), max_len);
    return std::string(reinterpret_cast<const char*>(r.data + off), len);
}

// ---------------------------------------------------------------------------
// IL2CPP global-metadata.dat header (supports v24.2–31)
// We read the fixed core fields then compute version-adjusted offsets.
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
struct MetaHeader_Core {
    uint32_t sanity;                              // 0xFAB11BAF
    int32_t  version;                             // 16–31
    uint32_t stringLiteralOffset;                 // 8
    int32_t  stringLiteralSize;
    uint32_t stringLiteralDataOffset;
    int32_t  stringLiteralDataSize;
    uint32_t stringOffset;                        // 24
    int32_t  stringSize;
    uint32_t eventsOffset;
    int32_t  eventsSize;
    uint32_t propertiesOffset;
    int32_t  propertiesSize;
    uint32_t methodsOffset;                       // 48
    int32_t  methodsSize;
    uint32_t parameterDefaultValuesOffset;
    int32_t  parameterDefaultValuesSize;
    uint32_t fieldDefaultValuesOffset;
    int32_t  fieldDefaultValuesSize;
    uint32_t fieldAndParameterDefaultValueDataOffset;
    int32_t  fieldAndParameterDefaultValueDataSize;
    int32_t  fieldMarshaledSizesOffset;           // 80
    int32_t  fieldMarshaledSizesSize;
    uint32_t parametersOffset;
    int32_t  parametersSize;
    uint32_t fieldsOffset;
    int32_t  fieldsSize;
    uint32_t genericParametersOffset;
    int32_t  genericParametersSize;
    uint32_t genericParameterConstraintsOffset;
    int32_t  genericParameterConstraintsSize;
    uint32_t genericContainersOffset;             // 120
    int32_t  genericContainersSize;
    uint32_t nestedTypesOffset;
    int32_t  nestedTypesSize;
    uint32_t interfacesOffset;
    int32_t  interfacesSize;
    uint32_t vtableMethodsOffset;
    int32_t  vtableMethodsSize;
    int32_t  interfaceOffsetsOffset;
    int32_t  interfaceOffsetsSize;
    uint32_t typeDefinitionsOffset;               // 160
    int32_t  typeDefinitionsSize;
    // --- version-dependent fields follow ---
};
#pragma pack(pop)

// After typeDefinitionsSize (offset 164):
//   [Version(Max = 24.1)] rgctxEntriesOffset (4) + rgctxEntriesCount (4) → +8
//   imagesOffset (4) + imagesSize (4)
//   assembliesOffset (4) + assembliesSize (4)
//   [Version(Min = 19, Max = 24.5)] metadataUsageListsOffset/Count + metadataUsagePairsOffset/Count → +16
//   [Version(Min = 19)] fieldRefsOffset + fieldRefsSize → +8

// ---------------------------------------------------------------------------
// IL2CPP method definition (v19+, 32 bytes, stable across v24-31)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct Il2CppMethodDef {
    uint32_t nameIndex;
    int32_t  declaringType;   // typeDefinitionIndex
    int32_t  returnType;
    int32_t  parameterStart;
    int32_t  genericContainerIndex;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint16_t parameterCount;
};  // 32 bytes
static_assert(sizeof(Il2CppMethodDef) == 32, "Il2CppMethodDef size");
#pragma pack(pop)

// ---------------------------------------------------------------------------
// IL2CPP type definition — version-dependent layout
// We only need nameIndex, namespaceIndex, methodStart, method_count.
// Offsets computed from version.
// ---------------------------------------------------------------------------

struct TypeDefView {
    uint32_t nameIndex;
    uint32_t namespaceIndex;
    int32_t  methodStart;
    uint16_t method_count;
    size_t   stride;   // sizeof(Il2CppTypeDefinition) for this version
};

static bool parse_typedef(const uint8_t* base, size_t buf_size,
                           uint64_t off, double ver, TypeDefView& out) {
    // nameIndex at 0, namespaceIndex at 4
    if (off + 4 > buf_size) return false;
    memcpy(&out.nameIndex,      base + off + 0, 4);
    if (off + 8 > buf_size) return false;
    memcpy(&out.namespaceIndex, base + off + 4, 4);

    // Extra bytes before declaringTypeIndex:
    //   [Max 24.0]: customAttributeIndex (+4)
    //   [Max 24.5]: byrefTypeIndex       (+4)
    //   [Max 24.1]: rgctxStartIndex + rgctxCount (+8)
    uint32_t extra_pre = 0;
    if (ver <= 24.0) extra_pre += 4;  // customAttributeIndex
    if (ver <= 24.5) extra_pre += 4;  // byrefTypeIndex
    if (ver <= 24.1) extra_pre += 8;  // rgctxStartIndex, rgctxCount

    // Layout after (nameIndex, namespaceIndex, +extra_pre):
    //   byvalTypeIndex(4), declaringTypeIndex(4), parentIndex(4), elementTypeIndex(4),
    //   genericContainerIndex(4), [v<=22: delegate+marshaling fields]
    //   flags(4), fieldStart(4), methodStart(4), ...
    uint32_t extra_delegate = 0;
    if (ver <= 22.0) extra_delegate += 4 + 4; // delegateWrapperFromManagedToNativeIndex, marshalingFunctionsIndex
    if (ver >= 21.0 && ver <= 22.0) extra_delegate += 4 + 4; // ccwFunctionIndex, guidIndex

    uint32_t method_start_off = 8 + extra_pre + 4/*byval*/ + 4/*declaring*/ + 4/*parent*/ + 4/*element*/ + 4/*generic*/ + extra_delegate + 4/*flags*/ + 4/*fieldStart*/;
    if (off + method_start_off + 4 > buf_size) return false;
    memcpy(&out.methodStart, base + off + method_start_off, 4);

    // method_count is 8 fields after fieldStart (event,property,nested,interfaces,vtable,interfaceOffsets = 6×4 = 24 bytes gap)
    uint32_t method_count_off = method_start_off + 4/*methodStart*/ + 4/*eventStart*/ + 4/*propertyStart*/ + 4/*nestedTypesStart*/ + 4/*interfacesStart*/ + 4/*vtableStart*/ + 4/*interfaceOffsetsStart*/;
    if (off + method_count_off + 2 > buf_size) return false;
    memcpy(&out.method_count, base + off + method_count_off, 2);

    // stride = method_count_off + 2(method_count) + 2+2+2+2+2+2+2(6 more uint16) + 4(bitfield) + 4(token)
    out.stride = method_count_off + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4;

    return true;
}

// ---------------------------------------------------------------------------
// IL2CPP CodeRegistration structures (ARM64, 64-bit pointers)
// ---------------------------------------------------------------------------

// v27+
#pragma pack(push, 1)
struct CodeReg_v27 {
    uint64_t reversePInvokeWrapperCount;
    uint64_t reversePInvokeWrappers;
    uint64_t genericMethodPointersCount;
    uint64_t genericMethodPointers;
    uint64_t invokerPointersCount;
    uint64_t invokerPointers;
    uint64_t unresolvedVirtualCallCount;
    uint64_t unresolvedVirtualCallPointers;
    uint64_t interopDataCount;
    uint64_t interopData;
    uint64_t windowsRuntimeFactoryCount;
    uint64_t windowsRuntimeFactoryTable;
    uint64_t codeGenModulesCount;
    uint64_t codeGenModules;
};

// v24.2–24.5 (has methodPointers at start instead of reverse wrappers)
struct CodeReg_v242 {
    // Note: no reversePInvokeWrapper at start for v24.2
    uint64_t genericMethodPointersCount;
    uint64_t genericMethodPointers;
    uint64_t invokerPointersCount;
    uint64_t invokerPointers;
    uint64_t customAttributeCount;
    uint64_t customAttributeGenerators;
    uint64_t unresolvedVirtualCallCount;
    uint64_t unresolvedVirtualCallPointers;
    uint64_t interopDataCount;
    uint64_t interopData;
    uint64_t windowsRuntimeFactoryCount;
    uint64_t windowsRuntimeFactoryTable;
    uint64_t codeGenModulesCount;
    uint64_t codeGenModules;
};

struct Il2CppCodeGenModule {
    uint64_t moduleName;         // pointer to string
    uint64_t methodPointerCount;
    uint64_t methodPointers;     // pointer to array of uint64_t VA
    uint64_t invokerIndices;
    uint64_t reversePInvokeWrapperCount;
    uint64_t reversePInvokeWrapperIndices;
    uint64_t rgctxsCount;
    uint64_t rgctxs;
    uint64_t rgctxRangesCount;
    uint64_t rgctxRanges;
    uint64_t token;
    uint64_t moduleGlobalIndex;
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// MetadataRegistration (for finding it via pattern scan)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct MetaReg_v27 {
    int64_t  genericClassesCount;
    uint64_t genericClasses;
    int64_t  genericInstsCount;
    uint64_t genericInsts;
    int64_t  genericMethodTableCount;
    uint64_t genericMethodTable;
    int64_t  typesCount;
    uint64_t types;
    int64_t  methodSpecsCount;
    uint64_t methodSpecs;
    int64_t  fieldOffsetsCount;
    uint64_t fieldOffsets;
    int64_t  typeDefinitionsSizesCount;
    uint64_t typeDefinitionsSizes;
    uint64_t metadataUsagesCount;
    uint64_t metadataUsages;
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// ELF symbol search helpers
// ---------------------------------------------------------------------------

static uint32_t gnu_hash_symbol_count(const Reader& r, uint64_t hash_off) {
    uint32_t nbuckets = 0, symoffset = 0, bloom_size = 0;
    r.read(hash_off,      nbuckets);
    r.read(hash_off + 4,  symoffset);
    r.read(hash_off + 8,  bloom_size);
    uint64_t buckets_off = hash_off + 16 + 8 * bloom_size;
    uint32_t last_sym = 0;
    for (uint32_t i = 0; i < nbuckets; ++i) {
        uint32_t b = 0;
        r.read(buckets_off + i * 4, b);
        if (b > last_sym) last_sym = b;
    }
    if (last_sym < symoffset) return symoffset;
    uint64_t chains_off = buckets_off + 4 * nbuckets;
    uint32_t idx = last_sym - symoffset;
    while (true) {
        uint32_t chain = 0;
        if (!r.read(chains_off + idx * 4, chain)) break;
        ++last_sym; ++idx;
        if (chain & 1) break;
    }
    return last_sym;
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

Il2CppDumpResult il2cpp_dump(
    const uint8_t* so_data,   size_t so_size,
    const uint8_t* meta_data, size_t meta_size)
{
    Il2CppDumpResult res;
    std::ostringstream log;

    // -----------------------------------------------------------------------
    // 1. Parse global-metadata.dat
    // -----------------------------------------------------------------------

    if (meta_size < sizeof(MetaHeader_Core)) {
        res.error = "global-metadata.dat too small";
        return res;
    }

    MetaHeader_Core hdr;
    memcpy(&hdr, meta_data, sizeof(hdr));

    if (hdr.sanity != 0xFAB11BAFu) {
        res.error = "Invalid global-metadata.dat (bad magic)";
        return res;
    }

    // Encode version as integer * 10 for easy comparison
    // e.g. version 27 → 270, 24.2 is stored as int 24 in file (sub-version detected separately)
    int meta_ver = hdr.version;
    res.metadata_version = meta_ver;
    log << "Metadata version: " << meta_ver << "\n";

    if (meta_ver < 24 || meta_ver > 31) {
        res.error = "Unsupported metadata version " + std::to_string(meta_ver) +
                    " (supported: 24–31)";
        return res;
    }

    // For simplicity, treat all v24.x as v24 (field layout differences handled in parse_typedef)
    double ver_d = static_cast<double>(meta_ver);
    // Sub-version detection for v24: check assembliesSize vs imageDefs.length (approximate)
    // For our purposes, v27+ is the clean path; v24.x works with the extra_pre logic.
    if (meta_ver == 24) ver_d = 24.2; // conservative: assume at least 24.2

    // Read method definitions
    uint32_t methods_off = hdr.methodsOffset;
    int32_t  methods_sz  = hdr.methodsSize;
    if (methods_off + (uint32_t)methods_sz > meta_size || methods_sz < 0) {
        res.error = "methods table out of bounds";
        return res;
    }
    uint64_t method_count = (uint64_t)methods_sz / sizeof(Il2CppMethodDef);
    const Il2CppMethodDef* method_defs =
        reinterpret_cast<const Il2CppMethodDef*>(meta_data + methods_off);
    log << "Method definitions: " << method_count << "\n";

    // Read string table
    uint32_t str_off = hdr.stringOffset;
    int32_t  str_sz  = hdr.stringSize;
    auto get_string = [&](uint32_t idx) -> std::string {
        uint64_t off = str_off + idx;
        if (off >= meta_size) return "<?>"; 
        size_t max_len = meta_size - off;
        size_t len = strnlen(reinterpret_cast<const char*>(meta_data + off), max_len);
        return std::string(reinterpret_cast<const char*>(meta_data + off), len);
    };

    // Read type definitions (for building TypeName::MethodName)
    uint32_t types_off = hdr.typeDefinitionsOffset;
    int32_t  types_sz  = hdr.typeDefinitionsSize;

    // Parse type defs into a vector indexed by typeIndex
    std::vector<TypeDefView> type_views;
    if (types_off + (uint32_t)types_sz <= meta_size && types_sz > 0) {
        // Probe first typedef to get stride
        TypeDefView probe;
        if (parse_typedef(meta_data, meta_size, types_off, ver_d, probe) && probe.stride > 0) {
            uint64_t count = (uint64_t)types_sz / probe.stride;
            type_views.reserve(count);
            for (uint64_t i = 0; i < count; ++i) {
                TypeDefView tv;
                if (parse_typedef(meta_data, meta_size, types_off + i * probe.stride, ver_d, tv))
                    type_views.push_back(tv);
                else
                    break;
            }
            log << "Type definitions: " << type_views.size() << "\n";
        }
    }

    // Build method → owning type name map
    // For each type: type.methodStart … type.methodStart+method_count-1 → TypeName
    std::vector<std::string> method_type_name(method_count);
    for (auto& tv : type_views) {
        if (tv.methodStart < 0) continue;
        auto ns   = get_string(tv.namespaceIndex);
        auto name = get_string(tv.nameIndex);
        std::string full;
        if (!ns.empty()) { full = ns; full += '.'; full += name; }
        else               full = name;
        int end = tv.methodStart + tv.method_count;
        for (int j = tv.methodStart; j < end && (uint64_t)j < method_count; ++j) {
            method_type_name[j] = full;
        }
    }

    // -----------------------------------------------------------------------
    // 2. Parse il2cpp.so ELF
    // -----------------------------------------------------------------------

    Reader so{so_data, so_size};

    Elf64_Ehdr ehdr;
    if (!so.read(0, ehdr)) { res.error = "ELF too small"; return res; }
    if (memcmp(ehdr.e_ident, "\x7f""ELF", 4) != 0) { res.error = "Not an ELF file"; return res; }
    if (ehdr.e_ident[4] != 2) { res.error = "Not a 64-bit ELF"; return res; }
    if (ehdr.e_machine != 0xB7) { res.error = "Not an AArch64 ELF"; return res; }

    // Load program headers → build VA→file_offset segments
    std::vector<Segment> load_segs;
    Segment dyn_seg{};
    bool has_dyn = false;
    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
        Elf64_Phdr ph;
        if (!so.read(ehdr.e_phoff + i * sizeof(Elf64_Phdr), ph)) break;
        if (ph.p_type == PT_LOAD) {
            Segment s;
            s.vaddr = ph.p_vaddr;
            s.vend  = ph.p_vaddr + ph.p_memsz;
            s.foff  = ph.p_offset;
            s.fend  = ph.p_offset + ph.p_filesz;
            load_segs.push_back(s);
        }
        if (ph.p_type == PT_DYNAMIC) {
            dyn_seg.foff = ph.p_offset;
            dyn_seg.fend = ph.p_offset + ph.p_filesz;
            has_dyn = true;
        }
    }
    if (load_segs.empty()) { res.error = "No LOAD segments in ELF"; return res; }

    // Parse dynamic section
    uint64_t dt_strtab = 0, dt_symtab = 0, dt_hash = 0, dt_gnu_hash = 0;
    bool dt_strtab_found = false, dt_symtab_found = false;
    if (has_dyn) {
        for (uint64_t off = dyn_seg.foff; off + sizeof(Elf64_Dyn) <= dyn_seg.fend; off += sizeof(Elf64_Dyn)) {
            Elf64_Dyn dyn;
            if (!so.read(off, dyn)) break;
            if (dyn.d_tag == DT_NULL) break;
            if (dyn.d_tag == DT_STRTAB)   { dt_strtab = dyn.d_un; dt_strtab_found = true; }
            if (dyn.d_tag == DT_SYMTAB)   { dt_symtab = dyn.d_un; dt_symtab_found = true; }
            if (dyn.d_tag == DT_HASH)     { dt_hash    = dyn.d_un; }
            if (dyn.d_tag == DT_GNU_HASH) { dt_gnu_hash= dyn.d_un; }
        }
    }

    // Resolve symbol table
    uint64_t strtab_off = dt_strtab_found ? vatr(load_segs, dt_strtab) : UINT64_MAX;
    uint64_t symtab_off = dt_symtab_found ? vatr(load_segs, dt_symtab) : UINT64_MAX;
    uint32_t sym_count  = 0;
    if (symtab_off != UINT64_MAX) {
        if (dt_hash != 0) {
            uint64_t hoff = vatr(load_segs, dt_hash);
            if (hoff != UINT64_MAX) {
                uint32_t nbucket = 0, nchain = 0;
                so.read(hoff + 4, nchain);
                sym_count = nchain;
            }
        } else if (dt_gnu_hash != 0) {
            uint64_t hoff = vatr(load_segs, dt_gnu_hash);
            if (hoff != UINT64_MAX) sym_count = gnu_hash_symbol_count(so, hoff);
        }
    }
    log << "Dynamic symbols: " << sym_count << "\n";

    // -----------------------------------------------------------------------
    // 3. Symbol search for g_CodeRegistration / g_MetadataRegistration
    // -----------------------------------------------------------------------

    uint64_t va_codereg  = 0;
    uint64_t va_metareg  = 0;

    if (strtab_off != UINT64_MAX && symtab_off != UINT64_MAX && sym_count > 0) {
        for (uint32_t i = 0; i < sym_count; ++i) {
            Elf64_Sym sym;
            if (!so.read(symtab_off + i * sizeof(Elf64_Sym), sym)) break;
            if (sym.st_name == 0 || sym.st_value == 0) continue;
            uint64_t name_off = strtab_off + sym.st_name;
            if (name_off >= so_size) continue;
            const char* name = so.str(name_off);
            if (strcmp(name, "g_CodeRegistration") == 0)   va_codereg = sym.st_value;
            if (strcmp(name, "g_MetadataRegistration") == 0) va_metareg = sym.st_value;
        }
    }

    if (va_codereg && va_metareg)
        log << "Found registrations via symbol table\n";

    // -----------------------------------------------------------------------
    // 4. Pattern scan fallback (stripped libs)
    //    Scans data segments for values that match typeDefinitionsCount,
    //    then validates surrounding pointer structure.
    // -----------------------------------------------------------------------

    if ((!va_codereg || !va_metareg) && !type_views.empty()) {
        log << "Symbols not found, trying pattern scan…\n";
        int64_t type_def_count = (int64_t)type_views.size();

        // Identify exec and data segments
        std::vector<Segment> exec_segs, data_segs;
        for (auto& s : load_segs) {
            // Rough heuristic: exec segs tend to be large and aligned
            exec_segs.push_back(s); // treat all as candidates initially
        }

        auto in_any_seg = [&](uint64_t va) -> bool {
            for (auto& s : load_segs)
                if (va >= s.vaddr && va < s.vend) return true;
            return false;
        };

        // Scan for MetadataRegistration (v27+): has typesCount == typeDefinitionsCount
        if (!va_metareg && meta_ver >= 27) {
            for (auto& seg : load_segs) {
                uint64_t end = seg.fend > so_size ? so_size : seg.fend;
                for (uint64_t off = seg.foff; off + sizeof(MetaReg_v27) <= end; off += 8) {
                    MetaReg_v27 mr;
                    if (!so.read(off, mr)) break;
                    if (mr.typesCount == type_def_count && mr.typesCount > 10 &&
                        mr.typesCount < 1000000 &&
                        mr.genericClassesCount > 0 && mr.genericClassesCount < 500000 &&
                        in_any_seg(mr.types) && in_any_seg(mr.genericInsts)) {
                        // Convert file offset back to VA
                        for (auto& s : load_segs) {
                            if (off >= s.foff && off < s.fend) {
                                va_metareg = s.vaddr + (off - s.foff);
                                log << "MetadataRegistration found by scan at 0x"
                                    << std::hex << va_metareg << std::dec << "\n";
                                break;
                            }
                        }
                        if (va_metareg) break;
                    }
                }
                if (va_metareg) break;
            }
        }

        // Scan for CodeRegistration (v27+): codeGenModulesCount should be small (1-50)
        if (!va_codereg && meta_ver >= 27) {
            for (auto& seg : load_segs) {
                uint64_t end = seg.fend > so_size ? so_size : seg.fend;
                for (uint64_t off = seg.foff; off + sizeof(CodeReg_v27) <= end; off += 8) {
                    CodeReg_v27 cr;
                    if (!so.read(off, cr)) break;
                    if (cr.codeGenModulesCount >= 1 && cr.codeGenModulesCount <= 100 &&
                        cr.genericMethodPointersCount > 0 && cr.genericMethodPointersCount < 500000 &&
                        in_any_seg(cr.codeGenModules) &&
                        in_any_seg(cr.genericMethodPointers)) {
                        for (auto& s : load_segs) {
                            if (off >= s.foff && off < s.fend) {
                                va_codereg = s.vaddr + (off - s.foff);
                                log << "CodeRegistration found by scan at 0x"
                                    << std::hex << va_codereg << std::dec << "\n";
                                break;
                            }
                        }
                        if (va_codereg) break;
                    }
                }
                if (va_codereg) break;
            }
        }
    }

    if (!va_codereg) {
        res.error = "Could not find CodeRegistration (try a non-stripped binary)";
        res.log = log.str();
        return res;
    }

    // -----------------------------------------------------------------------
    // 5. Read CodeRegistration and walk codeGenModules
    // -----------------------------------------------------------------------

    // We support v24.2+ (codeGenModules path)
    uint64_t codegenmodules_va = 0;
    uint64_t codegenmodules_count = 0;

    if (meta_ver >= 27) {
        CodeReg_v27 cr;
        if (!read_va(so, load_segs, va_codereg, cr)) {
            res.error = "Could not read CodeRegistration struct";
            res.log = log.str();
            return res;
        }
        codegenmodules_va    = cr.codeGenModules;
        codegenmodules_count = cr.codeGenModulesCount;
    } else {
        // v24.2–24.5
        CodeReg_v242 cr;
        if (!read_va(so, load_segs, va_codereg, cr)) {
            res.error = "Could not read CodeRegistration (v24) struct";
            res.log = log.str();
            return res;
        }
        codegenmodules_va    = cr.codeGenModules;
        codegenmodules_count = cr.codeGenModulesCount;
    }

    if (codegenmodules_count == 0 || codegenmodules_count > 200) {
        res.error = "Invalid codeGenModulesCount: " + std::to_string(codegenmodules_count);
        res.log = log.str();
        return res;
    }
    log << "codeGenModules: " << codegenmodules_count << "\n";

    // Read array of pointers to codeGenModule structs
    std::vector<uint64_t> module_ptrs;
    if (!read_va_array(so, load_segs, codegenmodules_va, codegenmodules_count, module_ptrs)) {
        res.error = "Could not read codeGenModules pointer array";
        res.log = log.str();
        return res;
    }

    // -----------------------------------------------------------------------
    // 6. Map method pointers → names
    // -----------------------------------------------------------------------

    // Build a method_index→name cache from metadata
    // We iterate modules; each module's methods map to consecutive methodDefs
    // starting at a global method index. We track that index across modules.
    // (The ordering matches Unity's assembly order in global-metadata.dat.)

    uint64_t global_method_idx = 0;
    int mapped_count = 0;

    for (uint64_t m = 0; m < codegenmodules_count; ++m) {
        Il2CppCodeGenModule mod;
        if (!read_va(so, load_segs, module_ptrs[m], mod)) {
            log << "  Module " << m << ": failed to read struct\n";
            global_method_idx += 0; // unknown, can't advance safely
            continue;
        }

        std::string module_name = read_va_str(so, load_segs, mod.moduleName);
        uint64_t method_ptr_count = mod.methodPointerCount;
        uint64_t method_ptrs_va   = mod.methodPointers;

        if (method_ptr_count == 0) {
            log << "  Module [" << module_name << "]: 0 methods\n";
            global_method_idx += method_ptr_count;
            continue;
        }

        if (method_ptr_count > 500000) {
            log << "  Module [" << module_name << "]: suspicious count " << method_ptr_count << ", skipping\n";
            global_method_idx += method_ptr_count;
            continue;
        }

        std::vector<uint64_t> ptrs;
        if (!read_va_array(so, load_segs, method_ptrs_va, method_ptr_count, ptrs)) {
            log << "  Module [" << module_name << "]: failed to read method pointers\n";
            global_method_idx += method_ptr_count;
            continue;
        }

        for (uint64_t j = 0; j < method_ptr_count; ++j) {
            uint64_t addr = ptrs[j];
            if (addr == 0) { ++global_method_idx; continue; }

            uint64_t mdx = global_method_idx + j;
            if (mdx >= method_count) break;

            const Il2CppMethodDef& md = method_defs[mdx];
            std::string mname = get_string(md.nameIndex);
            if (mname.empty() || mname == "<?>") { ++global_method_idx; continue; }

            // Build full name: TypeName::MethodName
            std::string full;
            if (mdx < method_type_name.size() && !method_type_name[mdx].empty())
                full = method_type_name[mdx] + "::" + mname;
            else
                full = mname;

            // Sanitize: replace characters invalid in PEEK function names
            for (char& c : full) {
                if (c == ' ' || c == '<' || c == '>' || c == ',' || c == '`')
                    c = '_';
            }

            Il2CppSymbol sym;
            sym.address = addr;
            sym.name    = "il2cpp_" + full;
            res.methods.push_back(sym);
            ++mapped_count;
        }
        global_method_idx += method_ptr_count;
    }

    log << "Mapped " << mapped_count << " method addresses\n";

    res.log     = log.str();
    res.success = true;
    return res;
}
