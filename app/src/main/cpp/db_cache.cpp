#include "db_cache.h"
#include <android/log.h>
#include <sstream>
#include <cstring>

#define TAG "PeekDB"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

AnalysisDb::AnalysisDb(const std::string& db_path) : db_path_(db_path) {}

AnalysisDb::~AnalysisDb() { close(); }

bool AnalysisDb::open() {
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_);
        LOGE("sqlite3_open failed: %s", last_error_.c_str());
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    // WAL mode + generous cache for mobile
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA cache_size=-8000");
    exec("PRAGMA synchronous=NORMAL");
    exec("PRAGMA foreign_keys=ON");
    return create_schema();
}

void AnalysisDb::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool AnalysisDb::exec(const char* sql) {
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        last_error_ = errmsg ? errmsg : "unknown";
        sqlite3_free(errmsg);
        LOGE("SQL exec error: %s\nSQL: %s", last_error_.c_str(), sql);
        return false;
    }
    return true;
}

bool AnalysisDb::create_schema() {
    // Migration for DBs that predate the kind column — silently ignored on new DBs.
    sqlite3_exec(db_,
        "ALTER TABLE functions ADD COLUMN kind INTEGER NOT NULL DEFAULT 1",
        nullptr, nullptr, nullptr);

    const char* ddl = R"SQL(
        CREATE TABLE IF NOT EXISTS binaries (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash            TEXT    NOT NULL UNIQUE,
            file_path            TEXT    NOT NULL,
            last_analyzed_timestamp INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS functions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id    INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
            address      INTEGER NOT NULL,
            size         INTEGER NOT NULL,
            name         TEXT    NOT NULL DEFAULT '',
            end_address  INTEGER NOT NULL,
            kind         INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_functions_binary ON functions(binary_id);
        CREATE INDEX IF NOT EXISTS idx_functions_addr   ON functions(address);
        CREATE TABLE IF NOT EXISTS instructions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
            address     INTEGER NOT NULL,
            size        INTEGER NOT NULL,
            bytes_hex   TEXT    NOT NULL,
            mnemonic    TEXT    NOT NULL,
            operands    TEXT    NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_insn_function ON instructions(function_id);
        CREATE INDEX IF NOT EXISTS idx_insn_address  ON instructions(address);
        CREATE TABLE IF NOT EXISTS symbols (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
            address   INTEGER NOT NULL,
            name      TEXT    NOT NULL,
            type_str  TEXT    NOT NULL DEFAULT 'other',
            is_import INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_symbols_binary ON symbols(binary_id);
        CREATE TABLE IF NOT EXISTS xrefs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id    INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
            from_address INTEGER NOT NULL,
            to_address   INTEGER NOT NULL,
            ref_type     TEXT    NOT NULL DEFAULT 'branch'
        );
        CREATE INDEX IF NOT EXISTS idx_xrefs_binary ON xrefs(binary_id);
        CREATE INDEX IF NOT EXISTS idx_xrefs_to     ON xrefs(to_address);
        CREATE INDEX IF NOT EXISTS idx_xrefs_from   ON xrefs(from_address);
    )SQL";
    return exec(ddl);
}

int64_t AnalysisDb::find_binary(const std::string& file_hash) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id FROM binaries WHERE file_hash = ? LIMIT 1";
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, file_hash.c_str(), -1, SQLITE_STATIC);
    int64_t id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return id;
}

int64_t AnalysisDb::insert_binary(const std::string& file_hash,
                                   const std::string& file_path) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR IGNORE INTO binaries(file_hash, file_path, last_analyzed_timestamp) VALUES(?,?,strftime('%s','now'))";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, file_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return find_binary(file_hash);
}

bool AnalysisDb::store_functions(int64_t binary_id,
                                  const std::vector<ParsedFunction>& fns) {
    exec("BEGIN");
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO functions(binary_id,address,size,name,end_address,kind) VALUES(?,?,?,?,?,?)";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    for (const auto& fn : fns) {
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, binary_id);
        sqlite3_bind_int64(stmt, 2, (int64_t)fn.address);
        sqlite3_bind_int64(stmt, 3, (int64_t)fn.size);
        sqlite3_bind_text (stmt, 4, fn.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, (int64_t)(fn.address + fn.size));
        sqlite3_bind_int  (stmt, 6, fn.kind);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    exec("COMMIT");
    LOGI("Stored %zu functions for binary %lld", fns.size(), (long long)binary_id);
    return true;
}

bool AnalysisDb::store_instructions(const std::vector<DisasmInstruction>& insns) {
    exec("BEGIN");
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO instructions(function_id,address,size,bytes_hex,mnemonic,operands) VALUES(?,?,?,?,?,?)";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    for (const auto& i : insns) {
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, (int64_t)i.function_id);
        sqlite3_bind_int64(stmt, 2, (int64_t)i.address);
        sqlite3_bind_int  (stmt, 3, (int)i.size);
        sqlite3_bind_text (stmt, 4, i.bytes_hex.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 5, i.mnemonic.c_str(),  -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 6, i.operands.c_str(),  -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    exec("COMMIT");
    return true;
}

bool AnalysisDb::store_symbols(int64_t binary_id,
                                const std::vector<ParsedSymbol>& syms) {
    exec("BEGIN");
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO symbols(binary_id,address,name,type_str,is_import) VALUES(?,?,?,?,?)";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    for (const auto& s : syms) {
        const char* type_str = (s.type == STT_FUNC) ? "func" :
                               (s.type == STT_OBJECT) ? "object" : "other";
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, binary_id);
        sqlite3_bind_int64(stmt, 2, (int64_t)s.address);
        sqlite3_bind_text (stmt, 3, s.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 4, type_str,        -1, SQLITE_STATIC);
        sqlite3_bind_int  (stmt, 5, s.is_import ? 1 : 0);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    exec("COMMIT");
    return true;
}

bool AnalysisDb::store_xrefs(int64_t binary_id, const std::vector<Xref>& xrefs) {
    exec("BEGIN");
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO xrefs(binary_id,from_address,to_address,ref_type) VALUES(?,?,?,?)";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    for (const auto& x : xrefs) {
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, binary_id);
        sqlite3_bind_int64(stmt, 2, (int64_t)x.from_address);
        sqlite3_bind_int64(stmt, 3, (int64_t)x.to_address);
        sqlite3_bind_text (stmt, 4, xref_type_str(x.ref_type), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    exec("COMMIT");
    return true;
}

std::vector<DbFunction> AnalysisDb::get_functions(int64_t binary_id) {
    std::vector<DbFunction> result;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id,address,size,name,end_address,kind FROM functions WHERE binary_id=? ORDER BY address";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, binary_id);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DbFunction f;
        f.id          = sqlite3_column_int64(stmt, 0);
        f.address     = (uint64_t)sqlite3_column_int64(stmt, 1);
        f.size        = (uint64_t)sqlite3_column_int64(stmt, 2);
        f.name        = (const char*)sqlite3_column_text(stmt, 3);
        f.end_address = (uint64_t)sqlite3_column_int64(stmt, 4);
        f.kind        = sqlite3_column_int(stmt, 5);
        result.push_back(f);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<DbInstruction> AnalysisDb::get_instructions(int64_t function_id,
                                                          int limit,
                                                          int offset) {
    std::vector<DbInstruction> result;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id,address,size,bytes_hex,mnemonic,operands FROM instructions WHERE function_id=? ORDER BY address LIMIT ? OFFSET ?";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, function_id);
    sqlite3_bind_int  (stmt, 2, limit);
    sqlite3_bind_int  (stmt, 3, offset);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DbInstruction i;
        i.id        = sqlite3_column_int64(stmt, 0);
        i.address   = (uint64_t)sqlite3_column_int64(stmt, 1);
        i.size      = (uint32_t)sqlite3_column_int(stmt, 2);
        i.bytes_hex = (const char*)sqlite3_column_text(stmt, 3);
        i.mnemonic  = (const char*)sqlite3_column_text(stmt, 4);
        i.operands  = (const char*)sqlite3_column_text(stmt, 5);
        result.push_back(i);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<DbXref> AnalysisDb::get_xrefs(int64_t binary_id, uint64_t address) {
    std::vector<DbXref> result;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT from_address,to_address,ref_type FROM xrefs WHERE binary_id=? AND (from_address=? OR to_address=?) ORDER BY from_address";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, binary_id);
    sqlite3_bind_int64(stmt, 2, (int64_t)address);
    sqlite3_bind_int64(stmt, 3, (int64_t)address);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DbXref x;
        x.from_address = (uint64_t)sqlite3_column_int64(stmt, 0);
        x.to_address   = (uint64_t)sqlite3_column_int64(stmt, 1);
        x.ref_type     = (const char*)sqlite3_column_text(stmt, 2);
        result.push_back(x);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<DbSymbol> AnalysisDb::get_symbols(int64_t binary_id) {
    std::vector<DbSymbol> result;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT address,name,type_str,is_import FROM symbols WHERE binary_id=? ORDER BY address";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, binary_id);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DbSymbol s;
        s.address   = (uint64_t)sqlite3_column_int64(stmt, 0);
        s.name      = (const char*)sqlite3_column_text(stmt, 1);
        s.type_str  = (const char*)sqlite3_column_text(stmt, 2);
        s.is_import = sqlite3_column_int(stmt, 3) != 0;
        result.push_back(s);
    }
    sqlite3_finalize(stmt);
    return result;
}

int64_t AnalysisDb::get_function_id(int64_t binary_id, uint64_t address) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id FROM functions WHERE binary_id=? AND address=? LIMIT 1";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, binary_id);
    sqlite3_bind_int64(stmt, 2, (int64_t)address);
    int64_t id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) id = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return id;
}

int64_t AnalysisDb::get_instruction_count(int64_t function_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT COUNT(*) FROM instructions WHERE function_id=?";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, function_id);
    int64_t cnt = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) cnt = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return cnt;
}
