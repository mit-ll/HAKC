//
// Created by derrick on 3/16/21.
//
/**
 * @brief HAKC Analysis and Transformation pass
 * @file PMCPass.h
 */

#ifndef PMC_PMCPASS_H
#define PMC_PMCPASS_H

#include <set>
#include <vector>

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Analysis/PostDominators.h"

#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {

    class CommonHAKCAnalysis {
    protected:
        /**
        * @brief Set to true to output debugging information
        */
        bool debug_output;

        CommonHAKCAnalysis(bool debug);
        std::vector<Value *> findDefChain(Value *v, bool followLoad = false);
        int getFunctionArgNumber(Value *v);
        Value *getDef(Value *V, bool followLoad = false);
        GlobalVariable *getSymbolColor(Module &M, StringRef symbolName);
        bool callIsSafeTransition(CallInst *call);
        bool isHAKCFunction(Function *F);
        bool isSafeTransitionFunction(Function *F);
        bool isIntrinsicNeedingAuthentication(CallInst*);
        bool functionIsAnalysisCandidate(Function *F);
        bool isManuallyAnnotated(Function *F);
        bool isOutsideTransferFunc(Function *F);
        bool isRegisterRead(Value *v);
        bool isPerCPUPointer(Value *v);
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
        bool isMTETransferFunction(Function *F);
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

    public:
        unsigned totalDataChecks, totalCodeChecks, totalTransfers;
        HAKCModuleTransformation(Module &Module);
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
        LoadInst *claqueId;
        LoadInst *currentColor;
        LoadInst *currentAccessToken;
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

        std::map<CallInst*, std::set<Value*>> stackPtrsPassedToFuncs;

        HAKCModuleTransformation &M;

    public:
        unsigned addedDataCheckCount, addedCodeCheckCount, addedCliqueTransferCount, addedClaqueTransferCount;

    protected:
        bool isCompartmentalizedFunction();
        bool valueIsReadonlyPtr(Value *value);
        CallInst *addSignatureCall(Value *operand);
        CallInst *addSignatureWithColorCall(Value *operand);
        CallInst *addCliqueTransferCall(Value *operand, Value *original_color, Value *claque_id);
        Value *createSizeOf(Type *type);
        Value *addTargetTransfer(Use &operand, Value *address);
        bool userInFunction(Value *user);
        BasicBlock *
        findDominatorUseBlock(Value *ptr, std::set<Instruction *> &users);
        Instruction *findInsertionPoint(Value *v);
        Instruction *
        findUseInsertionPoint(Value *v, std::set<Instruction *> &users);
        CallInst *saveColor(Value *operand);
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
        bool globalNeedsTransferring(GlobalValue*);
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
        Instruction *functionInsertionPoint();
        void getFunctionMTEMetadata();
        Value *addTransferToTarget(Value *value, Value *address);
        std::map<Value*, Instruction*> findAllInsertionLocations();

    public:
        HAKCFunctionAnalysis(Function &F, bool debug,
                             HAKCModuleTransformation &M);
        bool modifiedFunction();
        void addCompartmentalization();
        void removeSignatures();
    };
}// namespace

#endif//PMC_PMCPASS_H

