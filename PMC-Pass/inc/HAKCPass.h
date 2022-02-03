//
// Created by derrick on 3/16/21.
//
/**
 * @brief HAKC Analysis and Transformation pass
 * @file HAKCPass.h
 */

#ifndef PMC_HAKCPASS_H
#define PMC_HAKCPASS_H

#define MODULES_LIMIT 255
#define MASK_COLOR_LIMIT 65535

#include <set>
#include <vector>

#include "HAKC-defs.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Analysis/PostDominators.h"

#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace hakc {
    std::error_code getCorrespondingPathInBuildDirectory(StringRef
                                                         pathToSourceFile, SmallVectorImpl<char> &result);

    std::error_code getRelativeSourcePath(StringRef relativeSourcePath,
                                          SmallVectorImpl<char> &result);

    class HAKCFile;
    class HAKCClique;
    class HAKCCompartment;
    class HAKCSystemInformation;

    class HAKCSymbol {
    protected:
        std::shared_ptr<HAKCClique> clique;
        std::string                 name;
        std::shared_ptr<HAKCFile>   file;

    public:
        HAKCSymbol(std::string name, std::shared_ptr<HAKCClique> clique, std::shared_ptr<HAKCFile> path);
        ConstantInt *getColor();
        ConstantInt *getCompartmentID();
        std::shared_ptr<HAKCCompartment> getCompartment();
        std::shared_ptr<HAKCClique> getClique();
        StringRef getName();
    };

    class HAKCCompartment {
    protected:
        ConstantInt* id;
        ConstantInt* entry_token;
        std::set<std::shared_ptr<HAKCCompartment>> targets;
        std::set<std::shared_ptr<HAKCClique>> cliques;
        // HAKCSystemInformation& hsi;
        // GlobalVariable* target

    public:
        HAKCCompartment(YamlCompartment& compartment, LLVMContext &C);
        void addClique(std::shared_ptr<HAKCClique> clique, std::shared_ptr<HAKCCompartment> compart);
        void addTarget(std::shared_ptr<HAKCCompartment> target);
        std::shared_ptr<HAKCClique> getClique(ConstantInt* color);
        ConstantInt *getID();
        ConstantInt *getEntryToken();
        std::set<std::shared_ptr<HAKCCompartment>> getTargets();
    };
    
    class HAKCClique {
    protected:
        ConstantInt* color;
        ConstantInt* access_token;
        std::shared_ptr<HAKCCompartment> compartment;
        std::set<std::shared_ptr<HAKCSymbol>> symbols;

    public:
        HAKCClique(std::shared_ptr<HAKCCompartment> clique_compartment, ConstantInt* clique_color, ConstantInt* clique_access_token); 
        void setCompartment(std::shared_ptr<HAKCCompartment> compartment);
        void addSymbol(std::shared_ptr<HAKCSymbol> symbol);
        ConstantInt *getAccessToken();
        ConstantInt *getColor();
        ConstantInt *getCompartmentID();
        std::shared_ptr<HAKCCompartment> getCompartment();
    };

    class HAKCFile {
    protected:
        std::string                                  path;
        std::set<std::shared_ptr<HAKCSymbol>>        symbols;
        ConstantInt*                                 guid;
        std::set<std::shared_ptr<HAKCCompartment>>   compartments;

    public:
        HAKCFile(YamlFile& file, LLVMContext &C);
        void addSymbol(std::shared_ptr<HAKCSymbol> symbol);
        void addCompartment(std::shared_ptr<HAKCCompartment> comp);
        ConstantInt *getColor(StringRef name);
        ConstantInt *getCompartmentID(StringRef name);
        ConstantInt *getAccessToken(StringRef name);
        bool hasCompartments();
    };

    class HAKCSystemInformation {
    protected:
        llvm::Module &Module;
        std::map<uint64_t, std::shared_ptr<HAKCCompartment>> compartments;
        std::map<std::string, std::shared_ptr<HAKCFile>> files;

    public:
        HAKCSystemInformation(llvm::Module &M);
        ConstantInt *getElementColor(StringRef file, StringRef element);
        ConstantInt *getElementCompartment(StringRef file, StringRef element);
        ConstantInt *getElementAccessToken(StringRef file, StringRef element);
        ConstantInt *getEntryToken(uint64_t compartment);
        GlobalVariable *getTargets(uint64_t compartment);
        static std::string getColorFromValue(ConstantInt *color);
        bool hasFile(StringRef file);
        std::shared_ptr<HAKCFile> getFile(StringRef file);
        std::shared_ptr<HAKCClique> getClique(uint64_t compartment, ConstantInt *color);
        std::shared_ptr<HAKCCompartment> getCompartment(uint64_t id);
        llvm::Module& getModule();
    };

    class CommonHAKCAnalysis {
    protected:
        /**
        * @brief Set to true to output debugging information
        */
        bool debug_output;
        HAKCSystemInformation &compartmentInfo;

        CommonHAKCAnalysis(bool debug, HAKCSystemInformation &compartmentInfo);
        int getFunctionArgNumber(Value *v);
        bool callIsSafeTransition(CallInst *call);
        bool isHAKCFunction(Function *F);
        bool isSafeTransitionFunction(Function *F);
        bool isIntrinsicNeedingAuthentication(CallInst *);
        bool functionIsAnalysisCandidate(Function *F);
        bool isOutsideTransferFunc(Function *F);
        bool isRegisterRead(Value *v);
        bool isPerCPUPointer(Value *v);
        bool isTransferFunction(StringRef name);
        bool isInHAKCFunctions(StringRef name);
        bool isValidColor(ConstantInt *symbolColor);
        Value *createSizeOf(Type *type, IRBuilder<> *irBuilder, Module *M);
        CallInst *saveColor(Value *operand, IRBuilder<> *irBuilder, Module *M);
        std::tuple<StringRef, int, int> getHAKCFunction(StringRef name);
        ConstantInt *getElementCompartment(StringRef name, StringRef element);
        ConstantInt *getElementColor(StringRef name, StringRef element);
        ConstantInt *getElementAccessToken(StringRef name, StringRef element);

    public:
        HAKCSystemInformation &getCompartmentInfo();
        static Value *getDef(Value *V, bool followLoad = false, bool debug = false);
        static std::vector<Value *> findDefChain(Value *v, bool followLoad = false, bool debug = false);
    };

    class HAKCModuleTransformation : public CommonHAKCAnalysis {
    protected:
        Module &M;
        bool compartmentalized, moduleModified, breakOnMissingTransfer;
        std::map<Function *, std::set<Value *>> authenticatedPointersIn;
        std::map<Function *, std::set<Value *>> authenticatedPointersOut;
        StringRef debugName;
        std::map<Function *, std::set<CallInst *>> missingTransfers;

    private:
        void moveGlobalsToPMCSection();
        void findMismatchedTransfers(Function *F);
        std::set<Value *> findPointerDereferences(Function *F);
        std::set<Value *> findPointerUses(Function *F);
        bool isModuleCompartmentalized(Module &M);
        bool functionNeedsAnalysis(Function *F);
        std::set<Value *> findAuthenticatedPointersAtStart(Function *F);
        bool pointersMatch(Value *aPtr, Function *aFunc, Value *bPtr,
                           Function *bFunc, bool print = false);
        void compartmentalizeModule();
        void removeSignatures();
        void updateCallParameters(std::map<Function *, std::set<CallInst *>> calls_map);
        bool functionEscapes(Function *F);
        std::set<Use*> getEscapingUses(Function *F);
        Function* createTransferFunction(Function *F);
        void addTransferFunctions();

    public:
        unsigned totalDataChecks, totalCodeChecks, totalTransfers;
        std::map<Function *, std::set<CallInst *>> HAKCFunctions;
        HAKCModuleTransformation(Module &Module, HAKCSystemInformation &compartmentInformation);
        bool isCompartmentalized();
        bool isModuleTransformed();
        std::set<Value *> getAuthenticatedPointersIn(Function *F);
        std::set<Value *> getAuthenticatedPointersOut(Function *F);
        void performTransformations();
        bool functionInAnalysisSet(Function *F);
    };

    /**
 * @brief This pass does the following:
 * 1. Find pointers that should be authenticated, add a call to authenticate, and then transform
 * all instructions that dereference the pointer.  Note, that the *actual* dereference might be
 * the result of arbitrary number of GEPs, in which case all intermediate GEP computations are cloned
 * using the authenticated pointer.
 *
 * 2. Insert a validity check for all indirect calls, and add a transfer of all pointer arguments to the
 * target address before the indirect call.  Immediately after the indirect call, the pointer arguments
 * are transferred back to their original clique.
 *
 * 3. Sign global variable pointers passed to functions so that subsequent authentications pass.
 *
 * The current policy is to pass along signed pointers to functions, which could then authenticate pointers
 * which the caller has already authenticated.  This might be redundant, and a source of overhead.
 */
    class HAKCFunctionAnalysis : public CommonHAKCAnalysis {
        /**
 * @brief Indirect function calls which are tested for validity and pointer arguments
 * are then recolored and resigned before invocation. Those arguments are then
 * colored their original color and signed with the current niche id.
 */
        std::map<Value *, std::set<Instruction *>> indirectCalls;

        /**
         * @brief Global variables used as function arguments
         */
        std::map<GlobalValue *, std::set<Instruction *>> globalArgumentUses;
        /**
         * @brief Used for ideal placement of authentication checks and cloned instructions
         */
        DominatorTree dominatorTree;
        IRBuilder<> irBuilder;
        /**
         * @brief Annotated global variables
         */
        ConstantInt *claqueId;
        ConstantInt *currentColor;
        ConstantInt *currentAccessToken;
        /**
         * @brief Mapping of signed pointers that need authentication, and the
         * instructions that dereference the signed pointers.
         */
        std::map<Value *, std::set<Instruction *>> signedPtrsUses;
        /**
         * @brief Mapping of signed pointers and their corresponding authenticated versions
         */
        std::map<Value *, Value *> authenticatedPtrs;

        std::set<CallInst *> safeTransitionCalls;

        std::set<Value *> pointersAlreadyAuthenticated;

        std::map<CallInst *, std::set<Value *>> stackPtrsPassedToFuncs;

        HAKCModuleTransformation &M;

    public:
        unsigned addedDataCheckCount, addedCodeCheckCount, addedCliqueTransferCount, addedClaqueTransferCount;

    protected:
        bool isCompartmentalizedFunction();
        bool valueIsReadonlyPtr(Value *value);
        CallInst *addSignatureCall(Value *operand);
        CallInst *addSignatureWithColorCall(Value *operand);
        CallInst *addCliqueTransferCall(Value *operand, Value *original_color, Value *claque_id);
        Value *addTargetTransfer(Use &operand, Value *address);
        bool userInFunction(Value *user);
        BasicBlock *
        findDominatorUseBlock(Value *ptr, std::set<Instruction *> &users);
        Instruction *findInsertionPoint(Value *v);
        Instruction *
        findUseInsertionPoint(Value *v, std::set<Instruction *> &users);
        void addCodeAuthCheck(Value *indirectCallTarget);
        void addGetSafeCodePtr(Value *indirectCallTarget);
        bool argShouldTransfer(Use &operand);
        void
        addIndirectCallTransfers(CallInst *callInst, Value *target_address);
        Function &getFunction();
        Value *
        addDataAuthCheckAtLocation(Value *signed_ptr, Instruction *location);
        Value *addGetSafePointerAtLocation(Value *signed_ptr, Instruction *location);
        void createAllAuthenticatedPointers();
        void transformPointerDereferences();
        bool argNeedsAuthentication(Use &arg);
        void addAllIndirectTransfers();
        void addStackTransfers();
        bool pointerAuthenticatedAtStart(Value *v);
        bool typeNeedsSigning(Type *type);
        bool needsRecursion(Value *aggregateVal, StructType *structType,
                            unsigned idx);
        Instruction *signStructPointers(Value *value);
        Instruction *signStructPointersRecurse(Value *value,
                                               std::set<Value *> *visited_structs);
        Instruction *signGlobalVariableFunctionPointers(GlobalValue *global);
        void addGlobalClonesAndTransfer(Value *global, Use &arg,
                                        std::map<Value *, Value *> &signed_clones,
                                        Instruction *I);
        bool phiNodeUsesValue(PHINode *phiNode, Value *target,
                              std::set<PHINode *> &visited);
        bool globalNeedsTransferring(GlobalValue *);
        void addAllGlobalTransfers();
        bool isStackAllocatedObject(Value *v);
        bool isSelectOfAuthenticatedPointers(Value *v);
        void handleInstruction(Instruction *I);
        Instruction *getUserInst(User *user);
        bool isPHIofGlobalsOnly(Value *ptr, std::set<PHINode *> &nodes);
        bool pointerShouldBeChecked(Value *ptr);
        void registerPointerDereference(Use &use);
        void handleLoad(LoadInst *load);
        void handleStore(StoreInst *store);
        void handleComparison(CmpInst *compare);
        void handleBinaryOperator(BinaryOperator *binOp);
        bool globalShouldBeTransferred(Use &globalValueArg);
        void handleCall(CallInst *call);
        void getFunctionMTEMetadata();
        Value *addTransferToTarget(Value *value, Value *address);
        std::map<Value *, Instruction *> findAllInsertionLocations();
        GlobalVariable *getValidEntryTokens();

    public:
        HAKCFunctionAnalysis(Function &F, bool debug,
                             HAKCModuleTransformation &M);
        bool modifiedFunction();
        void addCompartmentalization();
        void removeSignatures();
    };
}// namespace

#endif//PMC_HAKCPASS_H
