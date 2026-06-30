#include "peek_scope.h"
#include "peek_architecture.h"
#include "decompiler/funcdata.hh"
#include "decompiler/type.hh"

using namespace ghidra;

PeekScope::PeekScope(PeekArchitecture* arch, const ElfParseResult& elf)
    : Scope(0, "", static_cast<Architecture*>(arch), this),
      peek_arch_(arch),
      cache_(new ScopeInternal(0, "peek-internal",
                               static_cast<Architecture*>(arch), this)),
      elf_(elf) {}

FunctionSymbol* PeekScope::preRegisterFunction(const Address& addr,
                                               const std::string& name) {
    return cache_->addFunction(addr, name);
}

// Query the ELF symbol table for an address and register the result in cache_.
// Returns a Symbol* (FunctionSymbol or a data Symbol), or nullptr if unknown.
Symbol* PeekScope::queryElfAbsolute(uint64_t addr) const {
    AddrSpace* ram = glb->getDefaultCodeSpace();
    Address ghidra_addr(ram, addr);

    // 1. Named ELF functions (from .dynsym / .symtab).
    for (const auto& sym : elf_.symbols) {
        if (sym.address != addr) continue;
        if (sym.type == STT_FUNC) {
            return cache_->addFunction(ghidra_addr, sym.name);
        }
        // Data / object symbol — add as a typed symbol.
        int4 sz = (sym.size > 0 && sym.size <= 8)
                      ? static_cast<int4>(sym.size) : 8;
        Datatype* dt = glb->types->getBase(sz, TYPE_UINT);
        SymbolEntry* entry = cache_->addSymbol(
            sym.name, dt, ghidra_addr, Address());
        if (entry) {
            uint4 attr = Varnode::namelock | Varnode::typelock;
            if (sym.binding == STB_GLOBAL || sym.binding == STB_WEAK)
                attr |= Varnode::typelock;
            cache_->setAttribute(entry->getSymbol(), attr);
            return entry->getSymbol();
        }
        return nullptr;
    }

    // 2. Discovered functions (from disassembly / ELF hints).
    for (const auto& fn : elf_.functions) {
        if (fn.address != addr) continue;
        return cache_->addFunction(ghidra_addr, fn.name);
    }

    return nullptr;
}

SymbolEntry* PeekScope::findAddr(const Address& addr,
                                 const Address& usepoint) const {
    // Check cache first.
    SymbolEntry* entry = cache_->findAddr(addr, usepoint);
    if (entry) {
        return entry->getAddr() == addr ? entry : nullptr;
    }
    // If the address range was already queried but has no symbol at addr,
    // return nullptr without a second r2-style lookup.
    entry = cache_->findContainer(addr, 1, Address());
    if (entry) {
        return nullptr;
    }
    Symbol* sym = queryElfAbsolute(addr.getOffset());
    entry = sym ? sym->getMapEntry(addr) : nullptr;
    return (entry && entry->getAddr() == addr) ? entry : nullptr;
}

SymbolEntry* PeekScope::findContainer(const Address& addr, int4 size,
                                      const Address& usepoint) const {
    SymbolEntry* entry = cache_->findClosestFit(addr, size, usepoint);
    if (!entry) {
        Symbol* sym = queryElfAbsolute(addr.getOffset());
        entry = sym ? sym->getMapEntry(addr) : nullptr;
    }
    if (entry) {
        uintb last = entry->getAddr().getOffset() + entry->getSize() - 1;
        if (last < addr.getOffset() + static_cast<uintb>(size) - 1)
            return nullptr;
    }
    return entry;
}

Funcdata* PeekScope::findFunction(const Address& addr) const {
    // Cache hit?
    Funcdata* fd = cache_->findFunction(addr);
    if (fd) return fd;
    // Address already queried but resolved to a non-function symbol?
    if (cache_->findContainer(addr, 1, Address())) return nullptr;
    // Look up in ELF.
    Symbol* sym = queryElfAbsolute(addr.getOffset());
    FunctionSymbol* fsym = dynamic_cast<FunctionSymbol*>(sym);
    return fsym ? fsym->getFunction() : nullptr;
}

ExternRefSymbol* PeekScope::findExternalRef(const Address& addr) const {
    ExternRefSymbol* sym = cache_->findExternalRef(addr);
    if (sym) return sym;
    if (cache_->findContainer(addr, 1, Address())) return nullptr;
    // PEEK doesn't model external-ref symbols; imports resolve as functions.
    return nullptr;
}

LabSymbol* PeekScope::findCodeLabel(const Address& addr) const {
    return cache_->findCodeLabel(addr);
}

Funcdata* PeekScope::resolveExternalRefFunction(ExternRefSymbol* sym) const {
    return sym ? queryFunction(sym->getRefAddr()) : nullptr;
}
