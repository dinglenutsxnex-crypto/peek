#include "peek_load_image.h"
#include <algorithm>
#include <cstring>

void PeekLoadImage::loadFill(uint1* ptr, int4 size, const Address& addr) {
    memset(ptr, 0, size);

    const uint64_t va  = static_cast<uint64_t>(addr.getOffset());
    const uint64_t end = va + static_cast<uint64_t>(size);

    // Apply ELF section data first.
    for (const auto& sec : elf_.sections) {
        if (sec.size == 0) continue;
        const uint64_t sec_end = sec.address + sec.size;
        if (va >= sec_end || end <= sec.address) continue;

        const uint64_t copy_start = std::max(va, sec.address);
        const uint64_t copy_end   = std::min(end, sec_end);
        const uint64_t copy_len   = copy_end - copy_start;
        const uint64_t file_off   = sec.offset + (copy_start - sec.address);

        if (file_off + copy_len > elf_.data.size()) continue;
        memcpy(ptr + (copy_start - va), elf_.data.data() + file_off, copy_len);
    }

    // Overlay patch bytes (tail-call rewrite) on top of section data.
    if (patch_bytes_ && patch_len_ > 0) {
        const uint64_t p_end = patch_addr_ + patch_len_;
        if (!(va >= p_end || end <= patch_addr_)) {
            const uint64_t copy_start = std::max(va, patch_addr_);
            const uint64_t copy_end   = std::min(end, p_end);
            const uint64_t copy_len   = copy_end - copy_start;
            const uint64_t src_off    = copy_start - patch_addr_;
            memcpy(ptr + (copy_start - va), patch_bytes_ + src_off, copy_len);
        }
    }
}
