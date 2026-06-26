#pragma once

#include "elf_parser.h"
#include "disassembler.h"
#include "xref_detector.h"

#include <sqlite3.h>
#include <cstdint>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Lightweight structs used across the JNI boundary
// ---------------------------------------------------------------------------

struct DbFunction {
    int64_t     id          = -1;
    uint64_t    address     = 0;
    uint64_t    size        = 0;
    std::string name;
    uint64_t    end_address = 0;
    int         kind        = 1;   // 0=local(sub_), 1=named, 2=thunk(j_)
    std::string pseudocode;        // empty until decompiled
};

struct DbInstruction {
    int64_t     id;
    uint64_t    address;
    uint32_t    size;
    std::string bytes_hex;
    std::string mnemonic;
    std::string operands;
};

struct DbSymbol {
    uint64_t    address;
    std::string name;
    std::string type_str;   // "func" / "object" / "other"
    bool        is_import;
};

struct DbXref {
    uint64_t    from_address;
    uint64_t    to_address;
    std::string ref_type;   // "call" / "branch" / "data"
};

// Lightweight cross-function signature record.
// Only metadata — no machine code, no p-code, no lifted bodies.
// Keyed by (binary_id, address); survives across sessions in SQLite.
struct FuncSignature {
    uint64_t    address     = 0;
    std::string name;
    // Simplified type strings understood by decompiler_bridge:
    //   void / bool / int / uint / long / ulong / float / double /
    //   ptr (= void*) / char* / void* / size_t / unknown
    // Empty string means "not known".
    std::string return_type;
    std::string params_csv;   // comma-separated param type strings, or ""
    int         param_count  = -1;   // -1 = unknown
    std::string source;       // "symbol" / "stdlib" / "il2cpp" / "inferred"
};

// ---------------------------------------------------------------------------
// Cache DB
// ---------------------------------------------------------------------------

class AnalysisDb {
public:
    explicit AnalysisDb(const std::string& db_path);
    ~AnalysisDb();

    bool open();
    void close();
    bool is_open() const { return db_ != nullptr; }

    // Returns binary_id if this hash is already cached, -1 otherwise.
    int64_t find_binary(const std::string& file_hash);

    // Insert a new binary record; returns new binary_id.
    int64_t insert_binary(const std::string& file_hash,
                          const std::string& file_path);

    // Bulk-insert parsed data for a binary.
    bool store_functions(int64_t binary_id,
                         const std::vector<ParsedFunction>& fns);

    // Returns function_id → address map; used for instruction insertion.
    bool store_instructions(const std::vector<DisasmInstruction>& insns);

    bool store_symbols(int64_t binary_id,
                       const std::vector<ParsedSymbol>& syms);

    bool store_xrefs(int64_t binary_id,
                     const std::vector<Xref>& xrefs);

    // Query helpers
    std::vector<DbFunction>    get_functions(int64_t binary_id);
    DbFunction                 get_function_by_id(int64_t func_id);
    std::vector<DbInstruction> get_instructions(int64_t function_id,
                                                 int limit,
                                                 int offset);
    std::vector<DbXref>        get_xrefs(int64_t binary_id, uint64_t address);
    std::vector<DbSymbol>      get_symbols(int64_t binary_id);
    int64_t                    get_function_id(int64_t binary_id,
                                               uint64_t address);
    int64_t                    get_instruction_count(int64_t function_id);

    // Returns MAX(address+size) over all Capstone-decoded instructions for
    // the function, i.e. the first byte past the last real instruction.
    // Returns 0 if the function has no instructions in the DB.
    uint64_t                   get_code_end_address(int64_t function_id);

    // Pseudocode cache — empty string means not yet decompiled.
    std::string get_pseudocode(int64_t func_id);
    bool        store_pseudocode(int64_t func_id, const std::string& code);

    // ------------------------------------------------------------------
    // Persistent cross-function signature database
    //
    // FuncSignature records are lightweight — address + name + optional
    // type strings.  They are keyed by (binary_id, address) and survive
    // across sessions.  source values: "symbol" / "stdlib" / "il2cpp" /
    // "inferred" (in ascending trust order for conflict resolution).
    // ------------------------------------------------------------------
    bool store_signature(int64_t binary_id, const FuncSignature& sig);
    bool store_signatures(int64_t binary_id,
                          const std::vector<FuncSignature>& sigs);
    std::vector<FuncSignature> get_signatures(int64_t binary_id);
    // Returns true if a signature already exists for (binary_id, address).
    bool has_signature(int64_t binary_id, uint64_t address);

    std::string last_error() const { return last_error_; }

private:
    bool create_schema();
    bool exec(const char* sql);

    std::string db_path_;
    sqlite3*    db_ = nullptr;
    std::string last_error_;
};
