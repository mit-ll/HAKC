//
// Created by derrick on 9/8/21.
//
#include "HAKCTypeIdentifier.h"
#include "HAKC-defs.h"
#include "HAKCPass.h"

#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

#include <sstream>

static std::string ARGUMENT_ORIGIN_PREFIX = "argument-";
static std::string UNKNOWN_ORIGIN = "unknown-origin";

hakc::HAKCHash::HAKCHash()
    : result(), hasher(), updated(false), finalized(false) {}

bool hakc::HAKCHash::isFinalized() { return finalized; }

void hakc::HAKCHash::update(StringRef Str) {
    updated = true;
    hasher.update(Str);
}

void hakc::HAKCHash::update(ArrayRef<uint8_t> Data) {
    updated = true;
    hasher.update(Data);
}

std::array<uint8_t, 16> hakc::HAKCHash::Bytes() { return result.Bytes; }

void hakc::HAKCHash::final() {
    if (!updated) {
        errs() << "Hash has not been given data!\n";
        throw std::exception();
    }
    finalized = true;
    hasher.final(result);
}

std::string hakc::HAKCHash::digest() {
    if (!finalized) {
        errs() << "Hash has not been finalized!\n";
        throw std::exception();
    }
    return result.digest().str().str();
}

void hakc::HAKCType::addSubmemberEscape(std::string escaper,
                                        int64_t memberOffset) {
    escapingOffsets.insert(std::make_pair(escaper, memberOffset));
}

const DIType *hakc::HAKCType::getBaseType(const DIType *diType) {
    const DIDerivedType *diDerivedType;
    switch (diType->getTag()) {
        case dwarf::DW_TAG_restrict_type:
        case dwarf::DW_TAG_const_type:
        case dwarf::DW_TAG_typedef:
        case dwarf::DW_TAG_volatile_type:
        case dwarf::DW_TAG_enumeration_type:
            diDerivedType = dyn_cast<DIDerivedType>(diType);
            if (diDerivedType && diDerivedType->getBaseType()) {
                const DIType *baseType = getBaseType(diDerivedType->getBaseType());
                if (baseType) {
                    return baseType;
                }
            }
            /* Purposeful fallthrough */
        default:
            return diType;
    }
}

bool hakc::HAKCType::isStruct(const DIType *type) {
    return type &&
           this->getBaseType(type)->getTag() == dwarf::DW_TAG_structure_type;
}

bool hakc::HAKCType::isInternalStruct() {
    return isStruct() && type->getScope();
}

bool hakc::HAKCType::isStruct() { return isStruct(type); }

bool hakc::HAKCType::isTypeDef() {
    return type->getTag() == dwarf::DW_TAG_typedef;
}

std::string hakc::HAKCType::getStringRepresentation(const DIType *diType,
                                                    bool debug = false) {
    if (!diType) {
        return "void";
    }

    std::string result;
    switch (diType->getTag()) {
        case dwarf::DW_TAG_volatile_type:
        case dwarf::DW_TAG_const_type: {
            const DIDerivedType *diDerivedType = dyn_cast<DIDerivedType>(diType);
            if (diDerivedType->getBaseType()) {
                result = getStringRepresentation(diDerivedType->getBaseType(), debug);
            }
        } break;
        case dwarf::DW_TAG_restrict_type:
        case dwarf::DW_TAG_typedef: {
            const DIDerivedType *diDerivedType = dyn_cast<DIDerivedType>(diType);
            result = getStringRepresentation(diDerivedType->getBaseType(), debug);
        } break;
        case dwarf::DW_TAG_array_type: {
            const DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);

            result = getStringRepresentation(diCompositeType->getBaseType(), debug);
            result += "[]";
        } break;
        case dwarf::DW_TAG_pointer_type: {
            const DIDerivedType *diDerivedType = dyn_cast<DIDerivedType>(diType);
            result = getStringRepresentation(diDerivedType->getBaseType(), debug);
            result += "*";
        } break;
        case dwarf::DW_TAG_enumeration_type: {
            const DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);
            result = getStringRepresentation(diCompositeType->getBaseType(), debug);
        } break;
        case dwarf::DW_TAG_union_type:
        case dwarf::DW_TAG_structure_type: {
            const DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);
            result = diCompositeType->getFilename().str();
            result += std::to_string(diCompositeType->getLine());
        } break;
        default:
            if (const DISubroutineType *diSubroutineType =
                        dyn_cast<DISubroutineType>(diType)) {
                for (unsigned i = 0; i < diSubroutineType->getTypeArray().size(); i++) {
                    result +=
                            getStringRepresentation(diSubroutineType->getTypeArray()[i], debug);
                }
                break;
            } else if (const DIBasicType *diBasicType = dyn_cast<DIBasicType>(diType)) {
                result = diBasicType->getName().str();
                break;
            }
            errs() << "Unhandled DIType: ";
            diType->print(errs());
            errs() << "\n";
            throw std::exception();
    };

    return result;
}

hakc::HAKCType::HAKCType(const DIType *type,
                         hakc::HAKCTypeIdentifier &identifier)
    : type(type), typeHash(), userNames(), associatedType(nullptr),
      otherTypes(), identifier(identifier) {
    updateHash();
}

hakc::HAKCType::HAKCType(const DIType *type, Type *llvmType,
                         hakc::HAKCTypeIdentifier &identifier)
    : type(type), typeHash(), userNames(), associatedType(llvmType),
      otherTypes(), identifier(identifier) {
    updateHash();
}

void hakc::HAKCType::setAssociatedType(Type *type, bool debug) {
    if (this->associatedType && this->associatedType != type) {
        if (debug) {
            errs() << "WARNING: Changing Type from ";
            this->associatedType->print(errs());
            errs() << " to ";
            if (type) {
                type->print(errs());
            } else {
                errs() << "NULL";
            }
            errs() << "\n";
        }
        return;
    }

    if (!this->associatedType) {
        if (debug) {
            errs() << "Setting associated type to ";
            type->print(errs());
            errs() << " for ";
            HAKCTypeIdentifier::printDIType(this->type, 0);
            errs() << "\n";
        }
        this->associatedType = type;
    }
}

Type *hakc::HAKCType::getAssociatedType() { return this->associatedType; }

hakc::HAKCHash hakc::HAKCType::getTypeHash() {
    if (!typeHash.isFinalized()) {
        updateHash();
    }
    if(identifier.debugActive()) {
        auto string = getStringRepresentation(type, false);
        errs() << "getTypeHash: string = " << string << " for\n";
        identifier.printDIType(type, 1);
        errs() << "\n";
    }
    return typeHash;
}

void hakc::HAKCType::updateHash() {
    if (!typeHash.isFinalized()) {
        typeHash.update(getStringRepresentation(type, false));
        typeHash.final();
    }
}

StringRef hakc::HAKCType::getDefinitionFile() { return type->getFilename(); }

StringRef hakc::HAKCType::getDefinitionDirectory() {
    return type->getDirectory();
}

unsigned hakc::HAKCType::getDefinitionLine() { return type->getLine(); }

void hakc::HAKCType::addUser(std::string user) {
    if (!user.empty()) {
        userNames.insert(user);
    }
}

std::set<std::string> hakc::HAKCType::getUsers() { return userNames; }

const DIType *hakc::HAKCType::getType() { return type; }

void hakc::HAKCType::addAdditionalType(Type *type, bool debug) {
    if (!associatedType) {
        if (debug) {
            errs()
                    << "Setting associated type instead of adding additional type for ";
            this->type->print(errs());
            errs() << "\n";
        }
        setAssociatedType(type, debug);
    } else {
        if (debug) {
            errs() << "Adding ";
            type->print(errs());
            errs() << " as an additional type to ";
            associatedType->print(errs());
            errs() << " for ";
            this->type->print(errs());
            errs() << "\n";
        }
        otherTypes.insert(type);
    }
}

bool hakc::HAKCType::isAdditionalType(Type *type, bool debug) {
    return otherTypes.find(type) != otherTypes.end();
}

std::string hakc::HAKCType::getYaml() {
    if (!type) {
        return "";
    }

    std::stringstream out;
    std::string name = getBaseType(type)->getName().str();
    if (name.empty()) {
        name = "type_";
        name += getTypeHash().digest();
    }
    out << "-\n";
    out << "  name: " << name << "\n";
    out << "  directory: " << getDefinitionDirectory().str() << "\n";
    out << "  file: " << getDefinitionFile().str() << "\n";
    out << "  line: " << getDefinitionLine() << "\n";
    out << "  type: " << getTypeHash().digest() << "\n";
    out << "  InternalStruct: ";
    if (isInternalStruct()) {
        out << "true";
    } else {
        out << "false";
    }
    out << "\n";
    out << "  Users:\n";
    for (auto user : getUsers()) {
        out << "    - " << user << "\n";
    }
    out << "  EscapingMembers:\n";
    for (auto escapePair : escapingOffsets) {
        out << "    -\n";
        out << "      escaper: " << escapePair.first << "\n";
        out << "      offset: " << std::to_string(escapePair.second) << "\n";
    }
    if (isStruct() && associatedType && associatedType->isStructTy()) {
        StructType *structType = dyn_cast<StructType>(associatedType);
        const StructLayout *layout =
                identifier.getStructLayout(dyn_cast<StructType>(structType));
        if (structType->getStructNumElements() > 0) {
            out << "  MemberOffsets:\n";
        }
        for (unsigned i = 0; i < structType->getStructNumElements(); i++) {
            Type *t = structType->getStructElementType(i);
            auto hakcType = identifier.getHAKCType(t);
            if (!hakcType) {
                if (identifier.debugActive()) {
                    errs() << "YML: Could not find hakcType for Type " << std::to_string(i)
                           << " of " << name << ": ";
                    t->print(errs());
                    errs() << "\n";
                }
                continue;
            }
            if (identifier.debugActive()) {
                errs() << "YML " << name << " " << std::to_string(i) << " Type: ";
                t->print(errs());
                errs() << "\nhakcType: " << hakcType->getTypeHash().digest() << "\n";
            }
            out << "    -\n";
            out << "      type: " << hakcType->getTypeHash().digest() << "\n";
            out << "      offset: " << std::to_string(layout->getElementOffset(i))
                << "\n";
        }
    } else if (identifier.debugActive()) {
        errs() << name << " is not a struct or is not a StructType\n";
        if (associatedType) {
            errs() << "\t";
            associatedType->print(errs());
            errs() << "\n";
        }
    }

    out << "\n";
    return out.str();
}

hakc::HAKCFunction::HAKCFunction(Function *F, HAKCTypeIdentifier &identifier)
    : F(F), identifier(identifier) {
    if (identifier.debugActive()) {
        errs() << "Finding calls for " << F->getName() << "\n";
    }
    for (auto it = inst_begin(F); it != inst_end(F); ++it) {
        Instruction *inst = &*it;
        if (CallInst *call = dyn_cast<CallInst>(inst)) {
            addCall(call);
        }
    }
}

hakc::HAKCHash hakc::HAKCFunction::hashType(Type *t) {
    hakc::HAKCHash result;
    std::string typeStr;
    raw_string_ostream ostream(typeStr);
    t->print(ostream);
    result.update(ostream.str());
    result.final();
    return result;
}

std::string hakc::HAKCFunction::getYaml() {
    std::stringstream out;
    if(identifier.getHAKCType(F->getType())) {
        out << "-\n";
        out << "  name: " << F->getName().str() << "\n";
        out << "  hash: " << identifier.getHAKCType(F->getType())->getTypeHash().digest() << "\n";
        out << "  is-defined: ";
        if (F->getSubprogram()) {
            out << "y";
        } else {
            out << "n";
        }
        out << "\n";
        out << "  direct-calls:\n";
        for (auto call : directCalls) {
            out << "    - " << call << "\n";
        }
        out << "  indirect-calls:\n";
        for (auto call : indirectCalls) {
            out << "    -\n";
            out << "      type: " << call.first << "\n";
            out << "      origin: " << call.second << "\n";
        }
        out << "  escapes-to:\n";
        for (auto escapingSymbol : escapingSymbols) {
            out << "    - " << escapingSymbol << "\n";
        }
        out << "\n";
    }
    return out.str();
}

const StructLayout *
hakc::HAKCTypeIdentifier::getStructLayout(StructType *structType) {
    return M.getDataLayout().getStructLayout(structType);
}

std::string
hakc::HAKCTypeIdentifier::getStoreOperandOrigin(StoreInst *storeInst) {
    std::string result = getOperandOriginString(storeInst->getPointerOperand());

    if (debug) {
        errs() << "Found origin hash for store ";
        storeInst->print(errs());
        errs() << ": " << result << "\n";
    }
    return result;
}

Value *hakc::HAKCTypeIdentifier::getOperandOrigin(Value *operand) {
    Value *result = nullptr;
    std::vector<Value *> defChain =
            hakc::CommonHAKCAnalysis::findDefChain(operand, true, debug);
    for (Value *v : defChain) {
        if (isa<GetElementPtrInst>(v)) {
            if (debug) {
                errs() << "Found GEP for ";
                operand->print(errs());
                errs() << ": ";
                v->print(errs());
                errs() << "\n";
            }
            result = v;
            break;
        }
    }

    if (!result) {
        result = defChain.front();
    }

    return result;
}

std::set<std::pair<std::string, std::string>>
hakc::HAKCTypeIdentifier::getOperandStringTokens(
        Value *operand, std::shared_ptr<HAKCType> hakcType) {
    std::set<std::pair<std::string, std::string>> result;

    if (hakcType) {
        result.insert(std::make_pair("type", hakcType->getTypeHash().digest()));
        if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(operand)) {
            APInt offset(64, 0, true);
            bool foundOffset =
                    gep->accumulateConstantOffset(M.getDataLayout(), offset);
            if (foundOffset) {
                result.insert(
                        std::make_pair("offset", std::to_string(offset.getSExtValue())));
            }
        } else if (Argument *argument = dyn_cast<Argument>(operand)) {
            result.insert(
                    std::make_pair("argument", std::to_string(argument->getArgNo())));
        } else if (GlobalVariable *gv = dyn_cast<GlobalVariable>(operand)) {
            result.insert(std::make_pair("global-name", gv->getName().str()));
        } else if (Function *f = dyn_cast<Function>(operand)) {
            result.insert(std::make_pair("function-name", f->getName().str()));
        }
    }
    return result;
}

std::string hakc::HAKCTypeIdentifier::combineTokens(
        std::set<std::pair<std::string, std::string>> tokens) {
    std::string result = "";
    if (!tokens.empty()) {
        result = "{ ";
        unsigned idx = 0;
        for (auto it : tokens) {
            result += it.first;
            result += ": ";
            result += it.second;
            idx++;
            if (idx < tokens.size()) {
                result += ", ";
            }
        }
        result += " }";
    }
    return result;
}

std::string
hakc::HAKCTypeIdentifier::getOperandString(Value *operand,
                                           std::shared_ptr<HAKCType> hakcType) {
    std::string result = UNKNOWN_ORIGIN;

    auto tokens = getOperandStringTokens(operand, hakcType);
    if (!tokens.empty()) {
        result = combineTokens(tokens);
    }

    return result;
}

std::string hakc::HAKCTypeIdentifier::getOperandOriginString(Value *operand) {
    Value *def;
    std::string result;

    def = getOperandOrigin(operand);
    auto hakcType = getHAKCType(def->getType());
    result = getOperandString(def, hakcType);

    return result;
}

std::string hakc::HAKCTypeIdentifier::getUseOriginString(
        Use *use, std::shared_ptr<HAKCType> hakcType) {
    std::string result = UNKNOWN_ORIGIN;
    auto tokens = getOperandStringTokens(use->getUser(), hakcType);
    if (!tokens.empty()) {
        if (ConstantStruct *constStruct =
                    dyn_cast<ConstantStruct>(use->getUser())) {
            const StructLayout *layout = getStructLayout(constStruct->getType());
            tokens.insert(std::make_pair(
                    "offset",
                    std::to_string(layout->getElementOffset(use->getOperandNo()))));
        } else if (isa<CallInst>(use->getUser())) {
            tokens.insert(
                    std::make_pair("argument", std::to_string(use->getOperandNo())));
        }

        result = combineTokens(tokens);
    }

    return result;
}

std::string hakc::HAKCTypeIdentifier::getCallOperandOrigin(CallInst *call) {
    std::string result = getOperandOriginString(call->getCalledOperand());

    if (debug) {
        errs() << "Found origin hash for call ";
        call->print(errs());
        errs() << ": " << result << "\n";
    }

    return result;
}

std::shared_ptr<hakc::HAKCType>
hakc::HAKCTypeIdentifier::getHAKCType(Type *type) {
    for (auto t : types) {
        if (t->getAssociatedType() == type || t->isAdditionalType(type, debug)) {
            return t;
        }
    }

    return nullptr;
}

void hakc::HAKCFunction::addEscapingMemberOffset(CallInst *call) {
    if (!call->getCalledFunction()) {
        return;
    }

    for (auto &arg : call->args()) {
        if (isa<PointerType>(arg->getType())) {
            auto defChain = hakc::CommonHAKCAnalysis::findDefChain(arg.get());
            for (auto *V : defChain) {
                if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(V)) {
                    APInt offset(64, 0, true);
                    if (gep->accumulateConstantOffset(call->getModule()->getDataLayout(),
                                                      offset)) {
                        auto hakcType = identifier.getHAKCType(gep->getSourceElementType());
                        if (!hakcType) {
                            if (identifier.debugActive()) {
                                errs() << "Could not find HAKCType for escaping "
                                       << "symbol: ";
                                arg->print(errs());
                                errs() << " in function " << call->getFunction()->getName()
                                       << "\n";
                            }
                            break;
                        }
                        hakcType->addSubmemberEscape(
                                call->getCalledFunction()->getName().str(),
                                offset.getSExtValue());
                    }
                }
            }
        }
    }
}

void hakc::HAKCFunction::addCall(CallInst *call) {
    if (call->isInlineAsm()) {
        return;
    }

    if (call->getCalledFunction()) {
        if (call->getCalledFunction()->isIntrinsic()) {
            return;
        }
        directCalls.insert(call->getCalledFunction()->getName().str());
        addEscapingMemberOffset(call);
    } else {
        if (identifier.debugActive()) {
            errs() << "Call ";
            call->print(errs());
            errs() << " is an indirect call\n";
            errs() << "CalledOperand Type: ";
            call->getCalledOperand()->getType()->print(errs());
            errs() << "\n";
        }

        auto functionHakcType =
                identifier.getHAKCType(call->getCalledOperand()->getType());
        if (!functionHakcType) {
            if (identifier.debugActive()) {
                errs() << "Could not get HAKCType for ";
                call->getCalledOperand()->getType()->print(errs());
                errs() << " for call ";
                call->print(errs());
                errs() << " in function " << F->getName() << "\n";
            }
            return;
        }

        auto origin = identifier.getCallOperandOrigin(call);

        indirectCalls.insert(
                std::make_pair(functionHakcType->getTypeHash().digest(), origin));
    }
}

Function *hakc::HAKCFunction::getFunction() { return F; }

void hakc::HAKCFunction::addEscapingSymbol(std::string escapingSymbol) {
    escapingSymbols.insert(escapingSymbol);
}

bool hakc::HAKCFunction::hasTypeRelevance() {
    return !escapingSymbols.empty() ||
           (F->getSubprogram() && F->getSubprogram()->getScope()->getFilename() ==
                                          F->getParent()->getSourceFileName());
}

bool hakc::HAKCTypeIdentifier::functionShouldBeSkipped(Function *F) {
    return (F->isIntrinsic() || F->hasFnAttribute(Attribute::InlineHint) ||
            F->getName().contains(outside_transfer_prefix));
}

void hakc::HAKCTypeIdentifier::findEscapes() {
    for (auto &F : M.getFunctionList()) {
        if (F.getName().contains(outside_transfer_prefix) || F.isIntrinsic()) {
            continue;
        }

        for (auto &use : F.uses()) {
            std::string symbol;

            if (debug) {
                errs() << F.getName() << " User: ";
                use.getUser()->print(errs());
                errs() << " operand number " << std::to_string(use.getOperandNo())
                       << "\n";
            }
            if (GlobalVariable *gv = dyn_cast<GlobalVariable>(use.getUser())) {
                if (debug) {
                    errs() << "User is a global variable\n";
                }
                Type *gvType = gv->getType()->getPointerElementType();
                auto type = getHAKCType(gvType);
                if (!type) {
                    if (debug) {
                        errs() << "Unexpected HAKCType for global " << gv->getName()
                               << " of type ";
                        gvType->print(errs());
                        errs() << "\n";
                    }
                    continue;
                }
                symbol = getOperandString(gv, type);
            } else if (CallInst *call = dyn_cast<CallInst>(use.getUser())) {
                if (debug) {
                    errs() << "User is a CallInst\n";
                }
                for (auto &arg : call->args()) {
                    if (arg.get() == &F) {
                        if (!call->getCalledFunction()) {
                            errs() << F.getName() << " is used in an indirect call in "
                                   << call->getFunction()->getName() << ": ";
                            call->print(errs());
                            errs() << "\n";
                            continue;
                        }
                        symbol = getOperandString(arg, getHAKCType(F.getType()));
                        break;
                    }
                }
                /* We don't care about the actual invocation of a function */
                if (symbol.empty()) {
                    continue;
                }
            } else if (StoreInst *store = dyn_cast<StoreInst>(use.getUser())) {
                if (debug) {
                    errs() << "User is a StoreInst\n";
                }
                auto def = CommonHAKCAnalysis::getDef(store->getPointerOperand(), false,
                                                      debug);
                symbol = getStoreOperandOrigin(store);

                if (symbol == UNKNOWN_ORIGIN) {
                    if (debug) {
                        errs() << "Unexpected HAKCType for store ";
                        store->print(errs());
                        errs() << " with def ";
                        def->getType()->print(errs());
                        errs() << " in function\n";
                        store->getFunction()->print(errs());
                        errs() << "\n";
                    }
                    continue;
                }
            } else if (ConstantStruct *constant =
                               dyn_cast<ConstantStruct>(use.getUser())) {
                auto type = getHAKCType(constant->getType());
                if (!type) {
                    if (debug) {
                        errs() << "Unexpected HAKCType for constant ";
                        constant->print(errs());
                        errs() << "\n";
                    }
                    continue;
                }
                symbol = getUseOriginString(&use, type);
            }

            if (!symbol.empty()) {
                addEscapingSymbol(&F, symbol);
            } else {
                if (debug) {
                    errs() << "Unhandled use for " << F.getName() << ":\n";
                    use->print(errs());
                    errs() << "\n";
                }
                continue;
            }
        }
    }
}

hakc::HAKCTypeIdentifier::HAKCTypeIdentifier(Module &M)
    : M(M), debug(false), types(), symbols() {

    addNewType(nullptr);
    populateStructTypeLocations();

    for (auto &F : M.getFunctionList()) {
        if (functionShouldBeSkipped(&F)) {
            continue;
        }

        auto symbol = std::make_unique<HAKCFunction>(&F, *this);
        symbols.insert(std::move(symbol));
    }

    //    M.print(errs(), nullptr);
    //    errs() << "\n";
    findEscapes();
}

void hakc::HAKCTypeIdentifier::addEscapingSymbol(Function *F,
                                                 std::string escapingSymbol) {
    bool found = false;
    for (auto &f : symbols) {
        if (f->getFunction() == F) {
            f->addEscapingSymbol(escapingSymbol);
            found = true;
            break;
        }
    }

    if (!found && debug) {
        errs() << "Could not find function " << F->getName() << "\n";
    }
}

std::shared_ptr<hakc::HAKCType>
hakc::HAKCTypeIdentifier::getHAKCType(const DIType *type) {
    for (auto p : types) {
        if (p->getType() == type) {
            return p;
        }
    }

    if (debug) {
        errs() << "Could not get HAKCType for type ";
        printDIType(type, 0);
        errs() << "\n";
    }

    return nullptr;
}

void hakc::HAKCTypeIdentifier::outputTypes(raw_fd_ostream &out) {
    std::error_code err;
    SmallVector<char> sourcePath;
    err = sys::fs::real_path(M.getSourceFileName(), sourcePath, true);
    if (err) {
        errs() << "Could not get real path to " << M.getSourceFileName() << "\n";
        throw std::exception();
    }

    out << "---\n";
    out << "CU: ";
    for (auto p : sourcePath) {
        out << p;
    }
    out << "\n";

    out << "types:\n";
    for (auto t : types) {
        if (t->isStruct() && !t->isTypeDef()) {
            std::string yml = t->getYaml();
            if (yml.empty()) {
                continue;
            }
            StringRef yaml(yml);
            SmallVector<StringRef> lines;
            yaml.split(lines, "\n");
            for (auto line : lines) {
                out << "  " << line << "\n";
            }
        }
    }

    out << "symbols:\n";
    for (auto &it : symbols) {
        if (!it->hasTypeRelevance()) {
            if (debug) {
                errs() << it->getFunction()->getName() << " is not relevant\n";
            }
            continue;
        }
        if (debug) {
            errs() << "Outputting YAML for " << it->getFunction()->getName() << "\n";
        }
        std::string yml = it->getYaml();
        if(yml.empty()) {
            if(debug) {
                errs() << "\tYML empty for "<< it->getFunction()->getName() << "\n";
            }
            continue;
        }
        StringRef yaml(yml);
        SmallVector<StringRef> lines;
        yaml.split(lines, "\n");
        for (auto line : lines) {
            out << "  " << line << "\n";
        }
    }
}

std::shared_ptr<hakc::HAKCType>
hakc::HAKCTypeIdentifier::addNewType(const DIType *diType) {
    std::shared_ptr<hakc::HAKCType> result = getHAKCType(diType);

    if (!result) {
        if (debug) {
            errs() << "New HAKCType for ";
            printDIType(diType, 0);
            errs() << " registered\n";
        }
        result = std::make_shared<HAKCType>(diType, *this);
        types.insert(result);
    } else if (debug) {
        errs() << "Type ";
        printDIType(diType, 0);
        errs() << " already added\n";
    }
    return result;
}

void hakc::HAKCTypeIdentifier::addUserToAllTypes(const DIType *baseType,
                                                 std::string user) {
    if (!baseType) {
        return;
    }
    std::shared_ptr<hakc::HAKCType> hakcType = getHAKCType(baseType);
    if (hakcType) {
        hakcType->addUser(user);
        if (const DIDerivedType *diDerivedType =
                    dyn_cast<DIDerivedType>(baseType)) {
            if (diDerivedType->getBaseType()) {
                addUserToAllTypes(diDerivedType->getBaseType(), user);
            }
        }
    }
}

void hakc::HAKCTypeIdentifier::populateStructTypeLocations() {
    debug = true;
    if (debug) {
        M.print(errs(), nullptr);
    }

    std::shared_ptr<hakc::HAKCType> hakcType;
    for (auto &G : M.getGlobalList()) {
        Metadata *metadata = G.getMetadata(LLVMContext::MD_dbg);
        if (!metadata) {
            if (debug) {
                errs() << "Global " << G.getName() << " is missing metadata!\n";
            }
            continue;
        }
        DIGlobalVariableExpression *digve =
                dyn_cast<DIGlobalVariableExpression>(metadata);
        if (!digve) {
            errs() << "Global " << G.getName() << " has unexpected metadata: ";
            metadata->print(errs());
            errs() << "\n";
            throw std::exception();
        }
        const DIType *diType = digve->getVariable()->getType();
        if (!diType) {
            errs() << "Could not find DIType for global ";
            G.print(errs());
            errs() << "\n";
            throw std::exception();
        }

        if (debug) {
            errs() << "Start type gathering for ";
            G.print(errs());
            errs() << "\n";
        }
        hakcType = addType(diType, G.getValueType());
        if (debug) {
            errs() << "Type gathering returned for " << G.getName() << "\n";
        }
        if (hakcType) {
            hakcType->addUser(G.getName().str());
            hakcType->addAdditionalType(G.getType()->getPointerElementType(), debug);
        }
    }

    for (auto &F : M.getFunctionList()) {
        //                debug = (F.getName().contains("local_bh_enable"));
        if (debug) {
            errs() << "Starting analysis of " << F.getName() << "\n";
            F.print(errs());
        }

        if (functionShouldBeSkipped(&F)) {
            if (debug) {
                errs() << "Skipping\n";
            }
            continue;
        }

        DISubprogram *subprogram = F.getSubprogram();
        if (!subprogram) {
            continue;
        }
        addType(subprogram->getType(), nullptr);
        hakcType = getHAKCType(subprogram->getType());
        hakcType->setAssociatedType(F.getType(), debug);
        hakcType->addAdditionalType(F.getType()->getPointerTo(), debug);
        hakcType->addUser(F.getName().str());
        for (unsigned i = 0; i < subprogram->getType()->getTypeArray().size();
             i++) {
            const DIType *diType = subprogram->getType()->getTypeArray()[i];
            hakcType = getHAKCType(diType);
            hakcType->addUser(F.getName().str());
        }

        for (auto it = inst_begin(F); it != inst_end(F); ++it) {
            Instruction *inst = &*it;

            if (CallInst *call = dyn_cast<CallInst>(inst)) {
                if (debug) {
                    call->print(errs());
                    errs() << "\n";
                }
                if (call->getCalledFunction() &&
                    (call->getCalledFunction()->getIntrinsicID() ==
                             Intrinsic::IndependentIntrinsics::dbg_value ||
                     call->getCalledFunction()->getIntrinsicID() ==
                             Intrinsic::IndependentIntrinsics::dbg_declare)) {
                    ValueAsMetadata *valueAsMetadata = nullptr;
                    if (MetadataAsValue *metaValue =
                                dyn_cast<MetadataAsValue>(call->getArgOperand(0))) {
                        valueAsMetadata =
                                dyn_cast<ValueAsMetadata>(metaValue->getMetadata());
                    }

                    if (!valueAsMetadata) {
                        if (debug) {
                            errs() << "Unexpected argument 0 for ";
                            call->print(errs());
                            errs() << " in function " << F.getName() << "\n";
                        }
                        continue;
                    }

                    const MDNode *typeMetadata = nullptr;
                    if (MetadataAsValue *metaValue =
                                dyn_cast<MetadataAsValue>(call->getArgOperand(1))) {
                        typeMetadata = dyn_cast<const MDNode>(metaValue->getMetadata());
                    }
                    if (!typeMetadata) {
                        errs() << "Unexpected argument 1 for ";
                        call->print(errs());
                        errs() << " in function " << F.getName() << "\n";
                        throw std::exception();
                    }

                    const DIType *diType = getBaseDefinition(typeMetadata);
                    if (!diType) {
                        errs() << "Could not find type associated with ";
                        typeMetadata->print(errs());
                        errs() << "\n";
                        throw std::exception();
                    }
                    if (debug) {
                        errs() << "Start type gathering for ";
                        valueAsMetadata->print(errs());
                        errs() << " in function " << F.getName() << "\n";
                    }
                    if (CallInst *metadataCall =
                                dyn_cast<CallInst>(valueAsMetadata->getValue())) {
                        if (metadataCall->isInlineAsm()) {
                            continue;
                        }
                    }
                    hakcType = addType(diType, valueAsMetadata->getType());
                    if (debug) {
                        errs() << "hakcType returned containing ";
                        printDIType(hakcType->getType(), 0);
                        errs() << "\n";
                        if (hakcType->getAssociatedType()) {
                            errs() << " with associated type ";
                            hakcType->getAssociatedType()->print(errs());
                            errs() << "\n";
                        }
                    }
                    //                    hakcType->addUser(F.getName().str());
                    addUserToAllTypes(diType, F.getName().str());
                } else {
                    if (debug) {
                        errs() << "Continuing\n";
                    }
                    continue;
                }
            }
        }
    }
}

bool hakc::HAKCTypeIdentifier::debugActive() { return debug; }

void hakc::HAKCTypeIdentifier::printDIType(const DIType *type,
                                           unsigned indents = 0) {
    for (unsigned i = 0; i < indents; i++) {
        errs() << "\t";
    }
    type->print(errs());
    if (const DIDerivedType *diDerivedType = dyn_cast<DIDerivedType>(type)) {
        if (diDerivedType->getBaseType()) {
            errs() << "\n";
            printDIType(diDerivedType->getBaseType(), indents + 1);
        }
    }
}

const DIType *
hakc::HAKCTypeIdentifier::getBaseDefinition(const MDNode *metadata) {
    if (!metadata) {
        errs() << "Null metadata!\n";
        throw std::exception();
    }

    if (const DIGlobalVariableExpression *gve =
                dyn_cast<DIGlobalVariableExpression>(metadata)) {
        return getBaseDefinition(gve->getVariable());
    } else if (const DIGlobalVariable *gv =
                       dyn_cast<DIGlobalVariable>(metadata)) {
        return gv->getType();
    } else if (const DIType *type = dyn_cast<DIType>(metadata)) {
        return type;
    } else if (const DILocalVariable *localVariable =
                       dyn_cast<DILocalVariable>(metadata)) {
        return localVariable->getType();
    }

    return nullptr;
}

std::shared_ptr<hakc::HAKCType>
hakc::HAKCTypeIdentifier::addType(const DIType *diType, Type *initialType) {
    std::shared_ptr<hakc::HAKCType> result;
    if (!diType) {
        errs() << "Null diType!\n";
        throw std::exception();
    }

    if (debug) {
        errs() << "Adding ";
        printDIType(diType, 0);
        errs() << "\n";
    }

    result = getHAKCType(diType);
    if (result) {
        if (debug) {
            printDIType(diType, 0);
            errs() << " already added\n";
        }
        return result;
    }

    switch (diType->getTag()) {
        case dwarf::DW_TAG_restrict_type:
        case dwarf::DW_TAG_const_type:
        case dwarf::DW_TAG_typedef:
        case dwarf::DW_TAG_volatile_type: {
            const DIDerivedType *diDerivedType = dyn_cast<DIDerivedType>(diType);
            result = addNewType(diDerivedType);
            if (diDerivedType->getBaseType()) {
                addType(diDerivedType->getBaseType(),
                        initialType ? initialType : result->getAssociatedType());
            }
        } break;
        case dwarf::DW_TAG_array_type: {
            const DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);
            result = addNewType(diCompositeType);
            auto baseType = addType(diCompositeType->getBaseType(), nullptr);
            if (baseType->getAssociatedType()) {
                ArrayType *arrayType = ArrayType::get(baseType->getAssociatedType(), 1);
                result->setAssociatedType(arrayType, debug);
            }
        } break;
        case dwarf::DW_TAG_pointer_type: {
            const DIDerivedType *diDerivedType = dyn_cast<DIDerivedType>(diType);
            result = addNewType(diDerivedType);
            if (diDerivedType->getBaseType()) {
                if (debug) {
                    errs() << "Adding base type ";
                    errs() << " for ";
                    printDIType(diDerivedType, 0);
                    errs() << "\n";
                }
                auto baseType = addType(diDerivedType->getBaseType(), nullptr);
                if (debug) {
                    errs() << "Completed subtype addition of ";
                    diDerivedType->print(errs());
                    errs() << "\n";
                }
                if (!initialType) {
                    if (baseType->getAssociatedType()) {
                        Type *pointerType = baseType->getAssociatedType()->getPointerTo();
                        result->setAssociatedType(pointerType, debug);
                    }
                } else {
                    result->setAssociatedType(initialType, debug);
                }
            }
        } break;
        case dwarf::DW_TAG_enumeration_type: {
            const DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);
            result = addNewType(diCompositeType);
            if (diCompositeType->getBaseType()) {
                auto baseType = addType(diCompositeType->getBaseType(), nullptr);
                result->setAssociatedType(baseType->getAssociatedType(), debug);
            }
        } break;
        case dwarf::DW_TAG_union_type:
        case dwarf::DW_TAG_structure_type: {
            const DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);
            result = addNewType(diCompositeType);
            if (!diCompositeType->getName().empty() &&
                diType->getTag() == dwarf::DW_TAG_structure_type) {
                if (!initialType) {
                    std::string structName = "struct.";
                    structName += diCompositeType->getName().str();
                    StructType *type =
                            StructType::getTypeByName(M.getContext(), structName);
                    result->setAssociatedType(type, debug);
                } else {
                    result->setAssociatedType(initialType, debug);
                }
            }
            /* Forward declarations return null for getElements() */
            if (diCompositeType->getElements()) {
                if (debug) {
                    errs() << "Adding "
                           << std::to_string(
                                      diCompositeType->getElements()->getNumOperands())
                           << " members of ";
                    diCompositeType->print(errs());
                    errs() << "\n";
                }
                for (unsigned diIdx = 0;
                     diIdx < diCompositeType->getElements()->getNumOperands(); diIdx++) {
                    const DIDerivedType *element =
                            dyn_cast<DIDerivedType>(diCompositeType->getElements()[diIdx]);
                    const DIType *subDiType = element->getBaseType();
                    if (debug) {
                        errs() << "Adding member " << std::to_string(diIdx) << "\n";
                    }
                    addType(subDiType, nullptr);
                }
                if (debug) {
                    errs() << "Completed member addition of ";
                    diCompositeType->print(errs());
                    errs() << "\n";
                }
            }
        } break;
        default:
            if (const DISubroutineType *diSubroutineType =
                        dyn_cast<DISubroutineType>(diType)) {
                result = addNewType(diSubroutineType);
                for (unsigned i = 0; i < diSubroutineType->getTypeArray().size(); i++) {
                    const DIType *diType = diSubroutineType->getTypeArray()[i];
                    if (diType) {
                        if (debug) {
                            errs() << "Adding subroutine type " << std::to_string(i) << "\n";
                            printDIType(diType, 0);
                            errs() << "\n";
                        }
                        addType(diType, nullptr);
                    }
                }
                break;
            } else if (const DIBasicType *diBasicType = dyn_cast<DIBasicType>(diType)) {
                if (debug) {
                    errs() << "Adding ";
                    printDIType(diBasicType);
                    errs() << "\n";
                }
                result = addNewType(diBasicType);
                IntegerType *type =
                        IntegerType::get(M.getContext(), diBasicType->getSizeInBits());
                result->addAdditionalType(type, debug);
                break;
            }
            errs() << "Unhandled DIType: ";
            printDIType(diType, 0);
            errs() << "\n";
            throw std::exception();
    }
    return result;
}
