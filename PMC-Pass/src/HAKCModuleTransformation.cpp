//
// Created by derrick on 8/20/21.
//
#include "HAKCPass.h"

namespace hakc {

    HAKCModuleTransformation::HAKCModuleTransformation(Module &Module, HAKCSystemInformation &compartmentInfo)
        : CommonHAKCAnalysis(false, compartmentInfo), M(Module),
          compartmentalized(isModuleCompartmentalized(Module)),
          moduleModified(false),
          breakOnMissingTransfer(true),
          debugName("inet6_register_protosw"), totalDataChecks(0),
          totalCodeChecks(0), totalTransfers(0) {

        bool sourceShouldBeInstrumented = false;

        for (auto filename : source_files_to_instrument) {
            if (M.getSourceFileName().find(filename.str()) !=
                        std::string::npos &&
                    source_files_to_skip.find(M.getSourceFileName()) ==
                    source_files_to_skip.end()) {
                sourceShouldBeInstrumented = true;
                break;
            }
        }
        if (!sourceShouldBeInstrumented) {
//            errs() << "Skipping " << M.getSourceFileName() << "\n";
            return;
        }

        for (auto &F : M.getFunctionList()) {
            debug_output = (F.getName() == debugName);
            if (functionNeedsAnalysis(&F)) {
                if (debug_output) {
                    F.print(errs());
                }

                std::set<Value *> pointers = findPointerDereferences(&F);
                if (debug_output) {
                    errs() << "Adding " << pointers.size()
                           << " to out list of " << F.getName() << "\n";
                }
                authenticatedPointersOut[&F] = pointers;

                findMismatchedTransfers(&F);
            }
        }

        bool inSetsChanged;
        do {
            inSetsChanged = false;
            for (auto it : authenticatedPointersOut) {
                debug_output = (it.first->getName() == debugName);
                if (debug_output) {
                    errs() << "Updating in pointer list for "
                           << it.first->getName() << "\n";
                }
                std::set<Value *> origInSet = getAuthenticatedPointersIn(
                        it.first);
                std::set<Value *> currInSet = findAuthenticatedPointersAtStart(
                        it.first);
                if (debug_output) {
                    errs() << "origInSet:\n";
                    for (auto *v : origInSet) {
                        errs() << "\t";
                        v->print(errs());
                        errs() << "\n";
                    }
                    errs() << "currInSet:\n";

                    for (auto *v : currInSet) {
                        errs() << "\t";
                        v->print(errs());
                        errs() << "\n";
                    }
                }

                if (origInSet.size() != currInSet.size()) {
                    if (debug_output) {
                        errs()
                                << "Authenticated In Pointer set changed for "
                                << it.first->getName() << "\n";
                    }
                    inSetsChanged = true;
                    authenticatedPointersIn[it.first] = currInSet;
                    for (auto *ptr : currInSet) {
                        authenticatedPointersOut[it.first].insert(ptr);
                    }
                }
            }
        } while (inSetsChanged);

        if (!missingTransfers.empty()) {
            errs() << "There are missing transfers in "
                   << M.getSourceFileName() << ":\n";
            for (auto it : missingTransfers) {
                errs() << it.first->getName() << ":\n";
                for (auto *call : it.second) {
                    errs() << "\t" << call->getCalledFunction()->getName()
                           << " " << call->getDebugLoc().getLine() << "\n";
                }
            }
            assert(!breakOnMissingTransfer);
        }
    }

    /**
        * @brief Moves all global values to the specified HAKC ELF section
        */
    void HAKCModuleTransformation::moveGlobalsToPMCSection() {
        for (auto &global : M.globals()) {
            if (!global.hasInitializer() || global.isExternallyInitialized()) {
                continue;
            } else if (global.hasGlobalUnnamedAddr()) {
                continue;
            } else if (sections_to_skip.find(global.getSection()) != sections_to_skip.end()) {
                continue;
            }

            auto *symbolColor = getElementColor(M.getName(), global.getName());
            if(!symbolColor) {
                errs() << "Global " << global.getName() << " has no color\n";
                throw std::exception();
            }
            if(!isValidColor(symbolColor)) {
                errs() << "Global " << global.getName() << " has an invalid color: " << symbolColor->getZExtValue() << "\n";
                throw std::exception();
            }
            std::string finalName = global.getSection().str();
            if(finalName.empty()) {
                finalName = ".data";
            }

            finalName += section_prepend;
            finalName += HAKCSystemInformation::getColorFromValue(symbolColor);

            if (debug_output) {
                errs() << "Changing section of global ";
                global.print(errs());
                errs() << " to section " << finalName << "\n";
            }

            global.setSection(finalName);
            moduleModified = true;
        }
    }

    bool HAKCModuleTransformation::functionInAnalysisSet(Function *F) {
        return authenticatedPointersOut.find(F) !=
               authenticatedPointersOut.end();
    }

    void HAKCModuleTransformation::findMismatchedTransfers(Function *F) {
        std::set<CallInst *> kernelAllocations;
        std::set<CallInst *> mteTransfers;
        if (!isCompartmentalized()) {
            return;
        }

        for (auto it = inst_begin(F); it != inst_end(F); ++it) {
            Instruction *inst = &*it;
            /* Panic() can cause an unreachable state */
            if (isa<UnreachableInst>(inst->getParent()->getTerminator())) {
                return;
            }

            if (CallInst *call = dyn_cast<CallInst>(inst)) {
                if (kernel_allocation_funcs.find(F->getName()) !=
                    kernel_allocation_funcs.end()) {
                    continue;
                }

                if (call->getCalledFunction()) {
                    if (kernel_allocation_funcs.find(
                                call->getCalledFunction()->getName()) !=
                        kernel_allocation_funcs.end()) {
                        if (debug_output) {
                            errs() << "Kernel allocation: ";
                            call->print(errs());
                            errs() << "\n";
                        }
                        kernelAllocations.insert(call);
                    } else if (isTransferFunction(call->getCalledFunction()->getName())) {
                        if (debug_output) {
                            errs() << "MTE Transfer: ";
                            call->print(errs());
                            errs() << "\n";
                        }
                        mteTransfers.insert(call);
                    }
                }
            }
        }

        for (auto *allocCall : kernelAllocations) {
            bool transferFound = false;
            for (auto *transferCall : mteTransfers) {
                Value *def = getDef(transferCall->getArgOperand(0), false, debug_output);
                if (def == allocCall) {
                    transferFound = true;
                    break;
                } else if (LoadInst *load = dyn_cast<LoadInst>(def)) {
                    for (auto *user : load->getPointerOperand()->users()) {
                        if (StoreInst *store = dyn_cast<StoreInst>(user)) {
                            if (getDef(store->getValueOperand(), false, debug_output) == allocCall) {
                                transferFound = true;
                                break;
                            }
                        }
                    }
                }
            }
            if (!transferFound) {
                missingTransfers[F].insert(allocCall);
            }
        }
    }

    // find every pointer dereferenced by F
    std::set<Value *>
    HAKCModuleTransformation::findPointerDereferences(Function *F) {
        std::set<Value *> dereferencedPointers;

        for (auto it = inst_begin(F); it != inst_end(F); ++it) {
            Instruction *inst = &*it;

            if (LoadInst *load = dyn_cast<LoadInst>(inst)) {
                dereferencedPointers.insert(load->getPointerOperand());
            } else if (StoreInst *store = dyn_cast<StoreInst>(inst)) {
                dereferencedPointers.insert(store->getPointerOperand());
            } else if (AllocaInst *alloca = dyn_cast<AllocaInst>(inst)) {
                dereferencedPointers.insert(alloca);
            }
        }

        return dereferencedPointers;
    }

    std::set<Value *> HAKCModuleTransformation::findPointerUses(Function *F) {
        std::set<Value *> pointerUses = findPointerDereferences(F);

        for (auto it = inst_begin(F); it != inst_end(F); ++it) {
            if (CallInst *call = dyn_cast<CallInst>(&*it)) {
                for (auto &arg : call->args()) {
                    if (arg->getType()->isPointerTy()) {
                        pointerUses.insert(arg.get());
                    }
                }
            }
        }

        return pointerUses;
    }

    bool HAKCModuleTransformation::isModuleCompartmentalized(Module &M) {
        return compartmentInfo.hasFile(M.getName());
    }

    bool HAKCModuleTransformation::functionNeedsAnalysis(Function *F) {
        bool needsAnalysis = !(F->isIntrinsic() ||
                               F->isDeclaration() ||
                               F->doesNotAccessMemory() ||
                               !F->hasExactDefinition() ||
                               isOutsideTransferFunc(F) /*||
                               F->getSubprogram() == nullptr*/
        );
        if (!needsAnalysis) {
            goto out;
        }

        needsAnalysis = (                   /*!isSafeTransitionFunction(F) &&*/
                         !isHAKCFunction(F) /*&&
                         !isManuallyAnnotated(F)*/
        );
        if (!needsAnalysis) {
            goto out;
        }

        for (auto *user : F->users()) {
            if (!isa<CallInst>(user)) {
                /* Function is passed into a global variable */
                needsAnalysis = true;
            }
        }

    out:
        if (debug_output) {
            errs() << F->getName();
            if (!needsAnalysis) {
                errs() << " does not need ";
            } else {
                errs() << " needs ";
            }
            errs() << "analysis\n";
        }

        if (F->getName().contains("static_branch_")) {
            /* These functions call inline assembly that needs to be
             * constant at compile time, so we can't analyze them.
             * We ensure that any pointer passed to these functions have
             * no signature in argNeedsAnalysis.
             */
            needsAnalysis = false;
        }

        return needsAnalysis;
    }

    std::set<Value *>
    HAKCModuleTransformation::findAuthenticatedPointersAtStart(Function *F) {
        std::set<Value *> authenticatedPointers;
        if (!isCompartmentalized()) {
            if (debug_output) {
                errs() << M.getName() << " is not compartmentalized\n";
            }
            return authenticatedPointers;
        }

        if (!F->hasInternalLinkage() ||
            optimization_deny_list.find(F->getName()) != optimization_deny_list.end()) {
            if (debug_output) {
                errs() << F->getName() << " is not internalized linked\n";
            }
            return authenticatedPointers;
        }

        for (auto *ptr : findPointerUses(F)) {
            bool pointerAlwaysAuthenticated = false;
            //            if (debug_output) {
            //                errs() << "Users of " << F->getName() << ":\n";
            //            }
            for (auto *user : F->users()) {
                //                if (debug_output) {
                //                    user->print(errs());
                //                    errs() << "\n";
                //                }
                if (CallInst *call = dyn_cast<CallInst>(user)) {
                    Function *G = call->getFunction();

                    if (G == F) {
                        continue;
                    }

                    //                    if (debug_output) {
                    //                        errs() << "\t" << G->getName() << "\n";
                    //                    }

                    std::set<Value *> gAuthenticatedPointers = getAuthenticatedPointersOut(
                            G);
                    bool foundPtr = false;
                    for (auto *gPtr : gAuthenticatedPointers) {
                        if (pointersMatch(ptr, F, gPtr, G)) {
                            foundPtr = true;
                            if (debug_output) {
                                ptr->print(errs());
                                errs() << " matches ";
                                gPtr->print(errs());
                                errs() << "\n";
                            }
                            break;
                        }
                    }

                    if (!foundPtr) {
                        if (debug_output) {
                            errs() << "Pointer ";
                            ptr->print(errs());
                            errs() << " (";
                            getDef(ptr, false, debug_output)->print(errs());
                            errs() << ")";
                            errs() << " is not authenticated by " << G->getName() << "\n";
                        }
                        pointerAlwaysAuthenticated = false;
                        break;
                    } else {
                        pointerAlwaysAuthenticated = true;
                        /* Continue on to try the next user */
                    }
                }
            }

            if (pointerAlwaysAuthenticated) {
                if (debug_output) {
                    ptr->print(errs());
                    errs() << " in " << F->getName()
                           << " is always authenticated\n";
                }
                authenticatedPointers.insert(ptr);
            }
        }

        /* Find the intersection of provably authenticated pointers
                 * of all called functions, so we can be sure that any pointer argument
                 * passed to a function doesn't check against an authenticated pointer */
        if (!authenticatedPointers.empty()) {
            for (auto it = inst_begin(F); it != inst_end(F); ++it) {
                if (CallInst *call = dyn_cast<CallInst>(&*it)) {
                    if (functionIsAnalysisCandidate(
                                call->getCalledFunction())) {
                        for (auto &use : call->args()) {
                            if (use->getType()->isPointerTy() &&
                                authenticatedPointers.find(use.get()) !=
                                        authenticatedPointers.end()) {
                                bool inAuthFound = false;
                                for (auto *inAuthPtr : getAuthenticatedPointersIn(
                                             call->getCalledFunction())) {
                                    if (pointersMatch(use.get(), F, inAuthPtr,
                                                      call->getCalledFunction())) {
                                        inAuthFound = true;
                                        break;
                                    }
                                }
                                if (!inAuthFound) {
                                    if (debug_output) {
                                        errs() << "Removing ";
                                        use->print(errs());
                                        errs()
                                                << " from authenticated pointers because it is passed to "
                                                << call->getCalledFunction()->getName()
                                                << "\n";
                                        for (auto *inAuthPtr : getAuthenticatedPointersIn(
                                                     call->getCalledFunction())) {
                                            pointersMatch(use.get(), F,
                                                          inAuthPtr,
                                                          call->getCalledFunction(),
                                                          true);
                                        }
                                    }
                                    std::set<Value *> toRemove;
                                    for (auto *ptr : authenticatedPointers) {
                                        if (getDef(ptr, false, debug_output) == getDef(use.get(), false, debug_output)) {
                                            toRemove.insert(ptr);
                                        }
                                    }
                                    for (auto *ptr : toRemove) {
                                        authenticatedPointers.erase(ptr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            if (debug_output) {
                errs() << "authenticatedPointers is empty\n";
            }
        }

        return authenticatedPointers;
    }

    bool HAKCModuleTransformation::pointersMatch(Value *aPtr, Function *aFunc,
                                                 Value *bPtr,
                                                 Function *bFunc, bool print) {
        Value *aDef = getDef(aPtr, false, debug_output);
        Value *bDef = getDef(bPtr, false, debug_output);

        //        if (aDef->getType() != bDef->getType()) {
        //            if (debug_output && print) {
        //                errs() << "1: ";
        //                aDef->print(errs());
        //                errs() << " (Type: ";
        //                aDef->getType()->print(errs());
        //                errs() << ") does not match ";
        //                bDef->print(errs());
        //                errs() << " (Type: ";
        //                bDef->getType()->print(errs());
        //                errs() << ")\n";
        //                errs() << "----- " << findDefChain(bPtr).size() << "\n";
        //                for (auto *v : findDefChain(bPtr)) {
        //                    v->print(errs());
        //                    errs() << "\n";
        //                }
        //                errs() << "-----\n";
        //            }
        //            return false;
        //        }

        if (isa<Argument>(aDef)) {
            Argument *aArg = dyn_cast<Argument>(aDef);
            for (auto it = inst_begin(bFunc); it != inst_end(bFunc); ++it) {
                if (CallInst *call = dyn_cast<CallInst>(&*it)) {
                    if (call->getCalledFunction() == aFunc &&
                        getDef(call->getArgOperand(aArg->getArgNo()), false, debug_output) ==
                                bDef) {
                        if (debug_output) {
                            aPtr->print(errs());
                            errs() << " matches ";
                            bPtr->print(errs());
                            errs() << "\n";
                        }
                        return true;
                    }
                }
            }
        }

        if (isa<Argument>(bDef)) {
            Argument *bArg = dyn_cast<Argument>(bDef);
            for (auto it = inst_begin(aFunc); it != inst_end(aFunc); ++it) {
                if (CallInst *call = dyn_cast<CallInst>(&*it)) {
                    if (call->getCalledFunction() == bFunc &&
                        getDef(call->getArgOperand(bArg->getArgNo()), false, debug_output) ==
                                aDef) {
                        if (debug_output) {
                            aPtr->print(errs());
                            errs() << " matches ";
                            bPtr->print(errs());
                            errs() << "\n";
                        }
                        return true;
                    }
                }
            }
        }

        if (debug_output && print) {
            errs() << "2: ";
            aPtr->print(errs());
            errs() << " (Type: ";
            aPtr->getType()->print(errs());
            errs() << ") does not match ";
            bPtr->print(errs());
            errs() << " (Type: ";
            bPtr->getType()->print(errs());
            errs() << ")\n";
            errs() << "----- " << findDefChain(bPtr).size() << "\n";
            for (auto *v : findDefChain(bPtr)) {
                v->print(errs());
                errs() << "\n";
            }
            errs() << "-----\n";
        }

        return false;
    }

    bool HAKCModuleTransformation::isCompartmentalized() {
        return compartmentalized;
    }

    bool HAKCModuleTransformation::isModuleTransformed() {
        return moduleModified;
    }

    std::set<Value *>
    HAKCModuleTransformation::getAuthenticatedPointersIn(Function *F) {
        std::set<Value *> result;
        if (F) {
            if (authenticatedPointersIn.find(F) !=
                authenticatedPointersIn.end()) {
                result = authenticatedPointersIn[F];
            }
        }

        return result;
    }

    std::set<Value *>
    HAKCModuleTransformation::getAuthenticatedPointersOut(Function *F) {
        std::set<Value *> result;
        if (F) {
            if (authenticatedPointersOut.find(F) !=
                authenticatedPointersOut.end()) {
                result = authenticatedPointersOut[F];
            }
        }

        return result;
    }

    void HAKCModuleTransformation::updateCallParameters(std::map<Function *, std::set<CallInst *>> calls_map) {
        for (auto &pair : calls_map) {
            Function *F = pair.first;

            for (auto &call : pair.second) {
                std::tuple<StringRef, int, int> tup = getHAKCFunction(call->getCalledFunction()->getName());
                if (!std::get<0>(tup).equals("")) {
                    if (std::get<1>(tup) >= 0) {
                        ConstantInt *id = nullptr;
                        StringRef transferTargetName = F->getName();
                        if (isOutsideTransferFunc(F)) {
                            transferTargetName = F->getName().substr(outside_transfer_prefix.size());
                            id = getElementCompartment(F->getParent()->getName(), transferTargetName);
                        } else {
                            id = getElementCompartment(F->getParent()->getName(), F->getName());
                        }
                        if (!id) {
                            errs() << "Could not find Compartment ID for function " << transferTargetName << "\n";
                            throw std::exception();
                        }
                        call->setArgOperand(std::get<1>(tup), id);
                    }

                    if (std::get<2>(tup) >= 0) {
                        ConstantInt *color = nullptr;
                        if (isOutsideTransferFunc(F)) {
                            StringRef transferTargetName = F->getName().substr(outside_transfer_prefix.size());
                            color = getElementColor(F->getParent()->getName(), transferTargetName);
                        } else {
                            color = getElementColor(F->getParent()->getName(), F->getName());
                        }

                        if (!color) {
                            errs() << "Could not find Color for function " << F->getName() << "\n";
                        }
                        assert(color);
                        call->setArgOperand(std::get<2>(tup), color);
                    }
                }
            }
        }
    }

    void HAKCModuleTransformation::performTransformations() {
        if (isCompartmentalized()) {
            compartmentalizeModule();

            /*
             * Use Compartment IDs and Colors from the configuration file,
             * instead of placeholders in the source
             */
            std::map<Function *, std::set<CallInst *>> transferFunctionCalls;
            for (auto &F : M.getFunctionList()) {
                for (auto it = inst_begin(F); it != inst_end(F); ++it) {
                    Instruction *inst = &*it;

                    if (CallInst *call = dyn_cast<CallInst>(inst)) {
                        if (call->getCalledFunction()){
                            if (isTransferFunction(call->getCalledFunction()->getName())) {
                                transferFunctionCalls[&F].insert(call);
                            }
                        }
                    }
                }
            }

            updateCallParameters(transferFunctionCalls);
            updateCallParameters(HAKCFunctions);

        } else {
            removeSignatures();
        }
    }

    void HAKCModuleTransformation::removeSignatures() {
        for (auto it : authenticatedPointersOut) {
            debug_output = (it.first->getName() == debugName);
            if (debug_output) {
                errs() << "Removing signatures from "
                       << it.first->getName()
                       << " with authenticated pointers:\n";
                for (auto *ptr : getAuthenticatedPointersIn(it.first)) {
                    ptr->print(errs());
                    errs() << "\n";
                }
                errs() << "\n\n";
            }

            std::set<Value *> authenticatedPtrs = getAuthenticatedPointersIn(
                    it.first);
            HAKCFunctionAnalysis functionAnalysis(*it.first, debug_output,
                                                  *this);
            functionAnalysis.removeSignatures();
            moduleModified |= functionAnalysis.modifiedFunction();
        }
    }

    bool HAKCModuleTransformation::functionEscapes(Function *F) {
        std::set<Use*> escapingUses = getEscapingUses(F);
        return !escapingUses.empty();
    }

    std::set<Use*> HAKCModuleTransformation::getEscapingUses(Function *F) {
        std::set<Use*> escapingUses;
        
        for (Use &use : F->uses()) {
            /* If F is used in a global variable */
            if (isa<GlobalVariable>(use.getUser())) {
                escapingUses.insert(&use);
            }
            /* If F is stored into a variable */
            else if (isa<StoreInst>(use.getUser())) {
                escapingUses.insert(&use);
            }
        }

        return escapingUses;
    }

    Function* HAKCModuleTransformation::createTransferFunction(Function *F) {
	std::string name = outside_transfer_prefix.str();
	name += F->getName().str();
        FunctionType *ftype = FunctionType::get(F->getReturnType(), F->getFunctionType(), false);
        FunctionCallee fc = M.getOrInsertFunction(name, ftype);
        Function *transfer_function = cast<Function>(fc.getCallee());
        return transfer_function;
    }

    void HAKCModuleTransformation::addTransferFunctions() {
        for (auto &F : M.getFunctionList()) {
            if (functionEscapes(&F)) {
                Function *transferFunc = createTransferFunction(&F);
                IRBuilder<> irBuilder(&transferFunc->getEntryBlock());

                std::vector<Value*> arguments;
                std::vector<CallInst *> originalColors;
                std::vector<Value *> originalArgs;

                Value *color = getElementColor(F.getParent()->getName(), F.getName());
                Value *compartmentId = getElementCompartment(F.getParent()->getName(), F.getName());

                if (color ==  nullptr || compartmentId == nullptr) {
                    continue;
                }

                FunctionType *ftype = FunctionType::get(irBuilder.getInt8PtrTy(),
                                                {irBuilder.getInt8PtrTy(),
                                                 irBuilder.getInt64Ty(),
                                                 irBuilder.getInt32Ty(),
                                                 irBuilder.getInt32Ty(),
                                                 irBuilder.getInt1Ty()},
                                                false);

                FunctionCallee transfer_call = M.getOrInsertFunction(claque_transfer_name, ftype);
                assert(transfer_call && "Could not get HAKC transfer function");

                for (auto arg = F.arg_begin(); arg != F.arg_end(); arg++) {
                    if(!isa<PointerType>(arg->getType())) {
                        arguments.push_back(arg);
                        originalColors.push_back(nullptr);
                        originalArgs.push_back(arg);
                        continue;
                    }

                    CallInst *originalColor = saveColor(arg, &irBuilder, &M);
                    originalColors.push_back(originalColor);
                    originalArgs.push_back(arg);

                    Value *size = createSizeOf(arg->getType()->getPointerElementType(), &irBuilder, &M);
                    CallInst *transfer = irBuilder.CreateCall(transfer_call, {arg, size, compartmentId, color, irBuilder.getFalse()});
                    arguments.push_back(transfer);
                }

                CallInst *targetCall = irBuilder.CreateCall(&F, arguments);
                irBuilder.CreateRet(targetCall);


                FunctionCallee color_addr = M.getOrInsertFunction("hakc_color_address", ftype);
                assert(color_addr && "Could not get hakc_color_address");
                
                for (unsigned i = originalArgs.size()-1; i >= 0; i--) {
                    auto orig_arg = originalArgs[i];
                    auto arg = arguments[i];
                    if(!isa<PointerType>(arg->getType())) {
                        continue;
                    }

                    Value *original_color = originalColors[i];
                    Value *size = createSizeOf(arg->getType()->getPointerElementType(), &irBuilder, &M);
                    irBuilder.CreateCall(color_addr, {arg, original_color, size});
                    arg = orig_arg;
                }

                for (auto use : getEscapingUses(&F)) { 
                    /* replace F with transfer in user */
                    use->getUser()->setOperand(use->getOperandNo(), transferFunc);
                }
            }
        }
    }

    void HAKCModuleTransformation::compartmentalizeModule() {
        if (!isCompartmentalized()) {
            return;
        }

        moveGlobalsToPMCSection();

        for (auto it : authenticatedPointersOut) {
            debug_output = (it.first->getName() == debugName);
            if (debug_output) {
                errs() << "Adding instrumentation to "
                       << it.first->getName()
                       << " with authenticated pointers:\n";
                for (auto *ptr : getAuthenticatedPointersIn(it.first)) {
                    ptr->print(errs());
                    errs() << "\n";
                }
                errs() << "\n\n";
            }
            std::set<Value *> authenticatedPtrs = getAuthenticatedPointersIn(
                    it.first);
            //                authenticatedPtrs.clear();
            HAKCFunctionAnalysis functionAnalysis(*it.first, debug_output,
                                                  *this);
            functionAnalysis.addCompartmentalization();
            moduleModified |= functionAnalysis.modifiedFunction();

            totalCodeChecks += functionAnalysis.addedCodeCheckCount;
            totalDataChecks += functionAnalysis.addedDataCheckCount;
            totalTransfers += functionAnalysis.addedClaqueTransferCount +
                              functionAnalysis.addedCliqueTransferCount;
        }

        addTransferFunctions();
    }
}// namespace hakc
