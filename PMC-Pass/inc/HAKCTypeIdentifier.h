//
// Created by derrick on 9/8/21.
//

#ifndef PMC_HAKCTYPEIDENTIFIER_H
#define PMC_HAKCTYPEIDENTIFIER_H

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/MD5.h"

#include <map>
#include <set>

using namespace llvm;

namespace hakc {

    class HAKCTypeIdentifier;
    
    class HAKCHash {
    public:
        HAKCHash();
        bool isFinalized();
        void update(ArrayRef<uint8_t> Data);
        void update(StringRef Str);
        void final();
        std::string digest();
        std::array<uint8_t, 16> Bytes();


    protected:
        MD5::MD5Result result;
        MD5 hasher;
        bool updated, finalized;
    };

    class HAKCType {
    public:
        HAKCType(const DIType *type, HAKCTypeIdentifier &identifier);

        HAKCType(const DIType *type, Type *llvmType, HAKCTypeIdentifier &identifier);

        HAKCHash getTypeHash();

        StringRef getDefinitionFile();

        StringRef getDefinitionDirectory();

        unsigned getDefinitionLine();

        bool isStruct();
	bool isTypeDef();

        bool isInternalStruct();

        void addUser(std::string user);

        std::set<std::string> getUsers();

        const DIType *getType();

        std::string getYaml();

        void setAssociatedType(Type *type, bool debug);

        Type* getAssociatedType();

        void addAdditionalType(Type *type, bool debug);

        bool isAdditionalType(Type *type, bool debug);

	void addSubmemberEscape(std::string escaper, int64_t memberOffset);

    protected:
        const DIType *type;
        HAKCHash typeHash;
        std::set<std::string> userNames;
        Type *associatedType;
        std::set<Type*> otherTypes;
	std::set<std::pair<std::string, int64_t>> escapingOffsets;
	HAKCTypeIdentifier &identifier;

    protected:
        bool isStruct(const DIType *type);

        void updateHash();

        std::string getStringRepresentation(const DIType *diType, bool debug);

        const DIType *getBaseType(const DIType* diType);
    };

    /**
     * @brief Represents a function
     */
    class HAKCFunction {
    public:
        HAKCFunction(Function *F, HAKCTypeIdentifier &identifier);

        std::string getYaml();

        Function *getFunction();

        bool hasTypeRelevance();

        void addEscapingSymbol(std::string escapingSymbol);

    protected:
        Function *F;
        std::set<std::pair<std::string, std::string>> indirectCalls;
        std::set<std::string> directCalls;
        std::set<std::string> escapingSymbols;
        HAKCTypeIdentifier &identifier;

    protected:
        HAKCHash hashType(Type *t);
        void addCall(CallInst *call);
	void addEscapingMemberOffset(CallInst *call);
    };

    class HAKCTypeIdentifier {
    public:
        HAKCTypeIdentifier(Module &M);

        void outputTypes(raw_fd_ostream &out);

        std::shared_ptr<HAKCType> getHAKCType(const DIType *type);

        std::shared_ptr<HAKCType> getHAKCType(Type *type);

	std::string getCallOperandOrigin(CallInst *call);

	std::string getStoreOperandOrigin(StoreInst *storeInst);

        static void printDIType(const DIType *type, unsigned indents);

        bool debugActive();

	const StructLayout* getStructLayout(StructType *structType);

    protected:
        void populateStructTypeLocations();

        const DIType *getBaseDefinition(const MDNode *);

        std::shared_ptr<HAKCType> addNewType(const DIType *diType);

        std::shared_ptr<HAKCType> addType(const DIType *diType, Type *initialType);

        bool functionShouldBeSkipped(Function *F);

        void addEscapingSymbol(Function *F, std::string escapingSymbol);

	Value* getOperandOrigin(Value *operand);

	std::string getOperandString(Value *operand, std::shared_ptr<HAKCType> hakcType);

	std::string getOperandOriginString(Value *operand);

	std::string getUseOriginString(Use *use, std::shared_ptr<HAKCType> hakcType);

        void addUserToAllTypes(const DIType *baseType, std::string user);
	
	void findEscapes();

	std::set<std::pair<std::string, std::string>>
		getOperandStringTokens(Value *operand, std::shared_ptr<HAKCType> hakcType);

	std::string combineTokens(std::set<std::pair<std::string, std::string>> tokens);

    protected:
        Module &M;
        bool debug;
        std::set<std::shared_ptr<HAKCType>> types;
        std::set<std::unique_ptr<HAKCFunction>> symbols;
    };

}


#endif//PMC_HAKCTYPEIDENTIFIER_H
