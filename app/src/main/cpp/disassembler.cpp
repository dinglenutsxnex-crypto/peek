#include "disassembler.h"

#include <capstone/capstone.h>
#include <android/log.h>
#include <sstream>
#include <iomanip>

#define TAG "PeekDisasm"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static std::string bytes_to_hex(const uint8_t* bytes, uint16_t size) {
    std::ostringstream oss;
    for (uint16_t i = 0; i < size; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    return oss.str();
}

DisasmResult disassemble_arm64(
    const uint8_t* data,
    size_t         length,
    uint64_t       start_va)
{
    DisasmResult res;

    if (!data || length == 0) {
        res.error = "Empty input";
        return res;
    }

    // Capstone 5.x renamed CS_ARCH_ARM64 → CS_ARCH_AARCH64.
    // Support both via conditional compilation.
#if defined(CS_ARCH_AARCH64)
    constexpr cs_arch kArch = CS_ARCH_AARCH64;
#else
    constexpr cs_arch kArch = CS_ARCH_ARM64;
#endif

    csh handle;
    cs_err err = cs_open(kArch, CS_MODE_LITTLE_ENDIAN, &handle);
    if (err != CS_ERR_OK) {
        res.error = std::string("cs_open failed: ") + cs_strerror(err);
        return res;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        res.error = "cs_malloc failed";
        return res;
    }

    const uint8_t* code   = data;
    size_t         size   = length;
    uint64_t       addr   = start_va;

    while (cs_disasm_iter(handle, &code, &size, &addr, insn)) {
        DisasmInstruction di;
        di.address    = insn->address;
        di.size       = insn->size;
        di.bytes_hex  = bytes_to_hex(insn->bytes, insn->size);
        di.mnemonic   = insn->mnemonic;
        di.operands   = insn->op_str;
        di.function_id = 0;
        res.instructions.push_back(std::move(di));
    }

    cs_free(insn, 1);
    cs_close(&handle);

    LOGI("Disassembled %zu instructions at VA 0x%llx",
         res.instructions.size(), (unsigned long long)start_va);

    res.ok = true;
    return res;
}
