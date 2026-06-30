#pragma once
#include "decompiler/database.hh"
#include "elf_parser.h"

using namespace ghidra;

class PeekArchitecture;

// Mirrors R2Scope: a Scope subclass that resolves symbols on-demand from
// the ELF symbol table.  An internal ScopeInternal acts as a write-through
// cache so each address is only looked up once per decompile session.
class PeekScope : public Scope {
    PeekArchitecture* peek_arch_;
    ScopeInternal*    cache_;
    const ElfParseResult& elf_;

    Symbol* queryElfAbsolute(uint64_t addr) const;

protected:
    void addSymbolInternal(Symbol*) override {
        throw LowlevelError("PeekScope::addSymbolInternal not supported");
    }
    SymbolEntry* addMapInternal(Symbol*, uint4, const Address&,
                                int4, int4, const RangeList&) override {
        throw LowlevelError("PeekScope::addMapInternal not supported");
    }
    SymbolEntry* addDynamicMapInternal(Symbol*, uint4, uint8,
                                       int4, int4, const RangeList&) override {
        throw LowlevelError("PeekScope::addDynamicMapInternal not supported");
    }
    void removeRange(AddrSpace*, uintb, uintb) override {}

public:
    PeekScope(PeekArchitecture* arch, const ElfParseResult& elf);
    ~PeekScope() override { delete cache_; }

    // Pre-register a function by name into the cache (used for sig injection
    // and for the target function before followFlow is called).
    FunctionSymbol* preRegisterFunction(const Address& addr, const std::string& name);

    // ---- Scope interface: delegate writes/utils to cache ----
    Scope* buildSubScope(uint8 id, const string& nm) override {
        return new ScopeInternal(id, nm, glb);
    }
    void clear() override { cache_->clear(); }
    SymbolEntry* addSymbol(const string& name, Datatype* ct,
                           const Address& addr, const Address& usepoint) override {
        return cache_->addSymbol(name, ct, addr, usepoint);
    }
    string buildVariableName(const Address& addr, const Address& pc,
                             Datatype* ct, int4& index, uint4 flags) const override {
        return cache_->buildVariableName(addr, pc, ct, index, flags);
    }
    string buildUndefinedName() const override { return cache_->buildUndefinedName(); }
    void setAttribute(Symbol* sym, uint4 attr) override    { cache_->setAttribute(sym, attr); }
    void clearAttribute(Symbol* sym, uint4 attr) override  { cache_->clearAttribute(sym, attr); }
    void setDisplayFormat(Symbol* sym, uint4 attr) override { cache_->setDisplayFormat(sym, attr); }
    void adjustCaches() override { cache_->adjustCaches(); }
    void encode(Encoder& enc) const override { cache_->encode(enc); }
    void decode(Decoder&) override { throw LowlevelError("PeekScope::decode not implemented"); }

    // ---- Scope interface: on-demand resolution ----
    SymbolEntry* findAddr(const Address& addr, const Address& usepoint) const override;
    SymbolEntry* findContainer(const Address& addr, int4 size,
                               const Address& usepoint) const override;
    Funcdata*    findFunction(const Address& addr) const override;
    ExternRefSymbol* findExternalRef(const Address& addr) const override;
    LabSymbol*   findCodeLabel(const Address& addr) const override;
    Funcdata*    resolveExternalRefFunction(ExternRefSymbol* sym) const override;

    // ---- Unimplemented — throw to surface misuse ----
    SymbolEntry* findClosestFit(const Address&, int4, const Address&) const override {
        throw LowlevelError("PeekScope::findClosestFit unimplemented");
    }
    bool isNameUsed(const string&, const Scope*) const override {
        throw LowlevelError("PeekScope::isNameUsed unimplemented");
    }
    SymbolEntry* findOverlap(const Address&, int4) const override {
        throw LowlevelError("PeekScope::findOverlap unimplemented");
    }
    SymbolEntry* findBefore(const Address&) const {
        throw LowlevelError("PeekScope::findBefore unimplemented");
    }
    SymbolEntry* findAfter(const Address&) const {
        throw LowlevelError("PeekScope::findAfter unimplemented");
    }
    void findByName(const string&, vector<Symbol*>&) const override {
        throw LowlevelError("PeekScope::findByName unimplemented");
    }
    MapIterator begin() const override { throw LowlevelError("PeekScope::begin unimplemented"); }
    MapIterator end()   const override { throw LowlevelError("PeekScope::end unimplemented"); }
    list<SymbolEntry>::const_iterator beginDynamic() const override {
        throw LowlevelError("PeekScope::beginDynamic unimplemented");
    }
    list<SymbolEntry>::const_iterator endDynamic() const override {
        throw LowlevelError("PeekScope::endDynamic unimplemented");
    }
    list<SymbolEntry>::iterator beginDynamic() override {
        throw LowlevelError("PeekScope::beginDynamic unimplemented");
    }
    list<SymbolEntry>::iterator endDynamic() override {
        throw LowlevelError("PeekScope::endDynamic unimplemented");
    }
    void clearCategory(int4) override          { throw LowlevelError("PeekScope::clearCategory unimplemented"); }
    void clearUnlockedCategory(int4) override  { throw LowlevelError("PeekScope::clearUnlockedCategory unimplemented"); }
    void clearUnlocked() override              { throw LowlevelError("PeekScope::clearUnlocked unimplemented"); }
    void restrictScope(Funcdata*) override     { throw LowlevelError("PeekScope::restrictScope unimplemented"); }
    void removeSymbolMappings(Symbol*) override { throw LowlevelError("PeekScope::removeSymbolMappings unimplemented"); }
    void removeSymbol(Symbol*) override        { throw LowlevelError("PeekScope::removeSymbol unimplemented"); }
    void renameSymbol(Symbol*, const string&) override { throw LowlevelError("PeekScope::renameSymbol unimplemented"); }
    void retypeSymbol(Symbol*, Datatype*) override     { throw LowlevelError("PeekScope::retypeSymbol unimplemented"); }
    string makeNameUnique(const string&) const override { throw LowlevelError("PeekScope::makeNameUnique unimplemented"); }
    void printEntries(ostream&) const override { throw LowlevelError("PeekScope::printEntries unimplemented"); }
    int4 getCategorySize(int4) const override  { throw LowlevelError("PeekScope::getCategorySize unimplemented"); }
    Symbol* getCategorySymbol(int4, int4) const override { throw LowlevelError("PeekScope::getCategorySymbol unimplemented"); }
    void setCategory(Symbol*, int4, int4) override { throw LowlevelError("PeekScope::setCategory unimplemented"); }
};
