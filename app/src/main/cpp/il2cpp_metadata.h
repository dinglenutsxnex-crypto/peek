#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Il2CppSymbol {
    uint64_t address;
    std::string name;
};

struct Il2CppDumpResult {
    std::vector<Il2CppSymbol> methods;
    int metadata_version = 0;
    std::string log;
    std::string error;
    bool success = false;
};

Il2CppDumpResult il2cpp_dump(
    const uint8_t* so_data,   size_t so_size,
    const uint8_t* meta_data, size_t meta_size
);
