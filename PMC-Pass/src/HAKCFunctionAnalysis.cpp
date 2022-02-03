//
// Created by derrick on 8/20/21.
//
#include "HAKCPass.h"

namespace hakc {
    bool HAKCFunctionAnalysis::valueIsReadonlyPtr(Value *value) {
        bool result = isa<PointerType>(value->getType()) &&
                      isa<FunctionType>(
                              value->getType()->getPointerElementType());
        //            if (!result) {
        //                if (GlobalVariable *gv = dyn_cast<GlobalVariable>(value)) {
        //                    result = (!gv->getSection().empty() && gv->getSection().contains("read_mostly"));
        //                }
        //            }

        return result;
    }

    CallInst *HAKCFunctionAnalysis::addSignatureCall(Value *operand) {
        if (!operand->getType()->isPointerTy()) {
            errs() << "Clique transfer target ";
            operand->print(errs());
            errs() << " is not a pointer but of type ";
            operand->getType()->print(errs());
            errs() << "\n";
        }
        assert(operand->getType()->isPointerTy() ||
               operand->getType()->isIntegerTy(64));

        bool isData = !valueIsReadonlyPtr(getDef(operand, false, debug_output));

        FunctionType *ftype = FunctionType::get(irBuilder.getInt8PtrTy(),
                                                {irBuilder.getInt8PtrTy(),
                                                 irBuilder.getInt32Ty(),
                                                 irBuilder.getInt32Ty(),
                                                 irBuilder.getInt1Ty()},
                                                false);
        FunctionCallee signature_call = getFunction().getParent()->getOrInsertFunction(
                sign_ptr_name, ftype);
        assert(signature_call && "Could not get signature call");

        Value *addr_cast = irBuilder.CreateBitCast(operand,
                                                   ftype->getParamType(0));
        CallInst *result = irBuilder.CreateCall(signature_call, {addr_cast,
                                                                 claqueId,
                                                                 currentColor,
                                                                 isData
                                                                         ? irBuilder.getFalse()
                                                                         : irBuilder.getTrue()});
        return result;
    }

    CallInst *HAKCFunctionAnalysis::addSignatureWithColorCall(Value *operand) {
        if (!operand->getType()->isPointerTy() ||
            operand->getType()->isIntegerTy(64)) {
            errs() << "Clique transfer target ";
            operand->print(errs());
            errs() << " is not a pointer but of type ";
            operand->getType()->print(errs());
            errs() << " in function " << getFunction().getName() << "\n";
        }
        assert(operand->getType()->isPointerTy() ||
               operand->getType()->isIntegerTy(64));

        bool isData = !valueIsReadonlyPtr(getDef(operand, false, debug_output));

        FunctionType *ftype = FunctionType::get(irBuilder.getInt8PtrTy(),
                                                {irBuilder.getInt8PtrTy(),
                                                 irBuilder.getInt32Ty(),
                                                 irBuilder.getInt1Ty()},
                                                false);
        FunctionCallee signature_call = getFunction().getParent()->getOrInsertFunction(
                sign_ptr_with_color_name, ftype);
        assert(signature_call && "Could not get signature call");

        Value *addr_cast = irBuilder.CreateBitCast(operand,
                                                   ftype->getParamType(0));
        CallInst *result = irBuilder.CreateCall(signature_call, {addr_cast,
                                                                 claqueId,
                                                                 isData
                                                                         ? irBuilder.getFalse()
                                                                         : irBuilder.getTrue()});
        return result;
    }

    /**
         * @brief Transfers a pointer argument back to its original color after an indirect call returns
         * @param operand Indirect call argument
         * @param original_color The color the argument was prior to the indirect call
         * @return The call to the kernel resigning operation
         */
    CallInst *HAKCFunctionAnalysis::addCliqueTransferCall(Value *operand,
                                                          Value *original_color,
                                                          Value *claque_id = nullptr) {
        if (!operand->getType()->isPointerTy()) {
            errs() << "Clique transfer target ";
            operand->print(errs());
            errs() << " is not a pointer but of type ";
            operand->getType()->print(errs());
            errs() << "\n";
        }
        assert(operand->getType()->isPointerTy());

        bool isData = !valueIsReadonlyPtr(getDef(operand, false, debug_output));

        FunctionType *ftype = FunctionType::get(irBuilder.getInt8PtrTy(),
                                                {irBuilder.getInt8PtrTy(),
                                                 irBuilder.getInt64Ty(),
                                                 irBuilder.getInt32Ty(),
                                                 irBuilder.getInt32Ty(),
                                                 irBuilder.getInt1Ty()},
                                                false);
        FunctionCallee transfer_call = getFunction().getParent()->getOrInsertFunction(
                claque_transfer_name, ftype);
        assert(transfer_call && "Could not get back transfer call");

        Value *addr_cast = irBuilder.CreateBitCast(operand,
                                                   ftype->getParamType(0));
        Value *size = createSizeOf(
                operand->getType()->getPointerElementType(), &irBuilder, getFunction().getParent());
        CallInst *result = irBuilder.CreateCall(transfer_call, {addr_cast,
                                                                size,
                                                                (claque_id ==
                                                                                 nullptr
                                                                         ? claqueId
                                                                         : claque_id),
                                                                original_color,
                                                                isData
                                                                        ? irBuilder.getFalse()
                                                                        : irBuilder.getTrue()});
        addedClaqueTransferCount++;
        if (debug_output) {
            errs() << "Created transfer for ";
            if (!isData) {
                errs() << operand->getName();
            } else {
                operand->print(errs());
            }
            errs() << ": ";
            result->print(errs());
            errs() << "\n";
        }
        return result;
    }

    Value *
    HAKCFunctionAnalysis::addTransferToTarget(Value *value, Value *address) {
        FunctionType *ftype = FunctionType::get(irBuilder.getInt8PtrTy(),
                                                {irBuilder.getInt8PtrTy(),
                                                 irBuilder.getInt8PtrTy(),
                                                 irBuilder.getInt64Ty(),
                                                 irBuilder.getInt1Ty()},
                                                false);
        FunctionCallee transfer_call = getFunction().getParent()->getOrInsertFunction(
                transfer_name, ftype);
        assert(transfer_call && "Could not get transfer call");

        bool isCode = valueIsReadonlyPtr(getDef(value, false, debug_output));

        Value *target_cast = irBuilder.CreateBitCast(address,
                                                     ftype->getParamType(
                                                             0));
        Value *operand_cast = irBuilder.CreateBitCast(value,
                                                      ftype->getParamType(
                                                              1));
        if (value->getType()->getPointerElementType() == nullptr) {
            errs() << "Type ";
            value->getType()->print(errs());
            errs() << " of operand ";
            value->print(errs());
            errs() << " returns null getPointerElementType()\n";
        }
        assert(value->getType()->getPointerElementType());
        Value *size = createSizeOf(
                value->getType()->getPointerElementType(), &irBuilder, getFunction().getParent());
        CallInst *result = irBuilder.CreateCall(transfer_call, {target_cast,
                                                                operand_cast,
                                                                size,
                                                                isCode
                                                                        ? irBuilder.getTrue()
                                                                        : irBuilder.getFalse()});
        addedCliqueTransferCount++;
        return irBuilder.CreateBitCast(result, value->getType());
    }

    /**
         * @brief Transfers a pointer argument of an indirect call to the target address
         * @param operand The argument to transfer
         * @param address The target of the indirect call
         * @return The call to the kernel transfer operation
         */
    Value *
    HAKCFunctionAnalysis::addTargetTransfer(Use &operand, Value *address) {
        assert(argShouldTransfer(operand));
        return addTransferToTarget(operand.get(), address);
    }

    /**
         * @brief Checks if a user is in the current function
         * @param user
         * @return True if the user is in the current function
         */
    bool HAKCFunctionAnalysis::userInFunction(Value *user) {
        Function &F = getFunction();
        if (Instruction *I = dyn_cast<Instruction>(user)) {
            return &F == I->getFunction();
        } else {
            errs() << "Unexpected user: ";
            user->print(errs());
            errs() << "\n";
            assert(false);
            return false; /* Shut up the compiler */
        }
    }

    /**
         * @brief Finds the dominating BasicBlock among users and ptr
         * @param ptr
         * @param users
         * @return
         */
    BasicBlock *
    HAKCFunctionAnalysis::findDominatorUseBlock(Value *ptr,
                                                std::set<Instruction *> &users) {
        Function &F = getFunction();
        BasicBlock *dominator = nullptr;
        if (Instruction *I = dyn_cast<Instruction>(ptr)) {
            if (!isa<AllocaInst>(ptr)) {
                dominator = I->getParent();
            }
        }

        for (auto *user : users) {
            if (!userInFunction(user)) {
                continue;
            }
            if (isa<PHINode>(user)) {
                continue;
            }
            if (dominator == nullptr) {
                dominator = user->getParent();
            } else {
                BasicBlock *tmp = dominatorTree.findNearestCommonDominator(
                        dominator, user->getParent());
                dominator = tmp;
            }
        }

        if (!dominator) {
            dominator = &F.getEntryBlock();
        }

        return dominator;
    }

    /**
         * @brief Finds the insertion point for a signed pointer
         * @param v The signed pointer
         * @return
         */
    Instruction *HAKCFunctionAnalysis::findInsertionPoint(Value *v) {
        return findUseInsertionPoint(v, signedPtrsUses[v]);
    }

    /**
         * @brief Finds an insertion point for new instructions.
         * @param v The Value for which we want to insert a new Instruction
         * @param users The users of v
         * @return The location at which to insert a new Instruction
         */
    Instruction *
    HAKCFunctionAnalysis::findUseInsertionPoint(Value *v,
                                                std::set<Instruction *> &users) {
        if (PHINode *phi = dyn_cast<PHINode>(v)) {
            return phi->getParent()->getFirstNonPHIOrDbgOrLifetime();
        }
        if (debug_output) {
            errs() << "Finding insertion point for ";
            if (v->getName().empty()) {
                v->print(errs());
            } else {
                errs() << v->getName();
            }
            errs() << "\n";
        }

        BasicBlock *dominator_block = findDominatorUseBlock(v, users);
        if (!dominator_block) {
            errs() << "Could not find block for ";
            v->print(errs());
            errs() << "\n";
            getFunction().print(errs());
        }
        assert(dominator_block);
        for (Instruction &I : *dominator_block) {
            if (&I == v) {
                return I.getNextNonDebugInstruction();
            } else if (users.find(&I) != users.end()) {
                return &I;
            }
        }

        return dominator_block->getTerminator();
    }

    void HAKCFunctionAnalysis::addGetSafeCodePtr(Value *indirectCallTarget) {
        Instruction *insertionPoint = findUseInsertionPoint(
                indirectCallTarget, indirectCalls[indirectCallTarget]);
        assert(insertionPoint);
        Value *safeCodePtr = addGetSafePointerAtLocation(indirectCallTarget,
                                                         insertionPoint);
        for (auto *I : indirectCalls[indirectCallTarget]) {
            CallInst *call = dyn_cast<CallInst>(I);
            assert(call);
            if (functions_to_add_transfers.find(getFunction().getName()) !=
                functions_to_add_transfers.end()) {
                addIndirectCallTransfers(call, indirectCallTarget);
            }
            call->setCalledOperand(safeCodePtr);
        }
    }

    GlobalVariable *HAKCFunctionAnalysis::getValidEntryTokens() {
        Function &F = getFunction();
        ConstantInt *compartment = getElementCompartment(F.getParent()->getName(), F.getName());
        return this->compartmentInfo.getTargets(compartment->getZExtValue());
    }

    /**
         * @brief Adds a validity check for an indirect call
         * @param indirectCall The indirect call to check
         */
    void HAKCFunctionAnalysis::addCodeAuthCheck(Value *indirectCallTarget) {
        Value *auth_call;
        Function &F = getFunction();

        Instruction *insertionPoint = findUseInsertionPoint(
                indirectCallTarget, indirectCalls[indirectCallTarget]);
        assert(insertionPoint);

        irBuilder.SetInsertPoint(insertionPoint);

        if (debug_output) {
            errs() << "Adding check for ";
            indirectCallTarget->print(errs());
            errs() << " at ";
            insertionPoint->print(errs());
            errs() << "\n";
        }

        GlobalVariable *exitTokens = getValidEntryTokens();

        assert(exitTokens && "Exit token global is null!");
        assert(isa<ArrayType>(
                       exitTokens->getType()->getPointerElementType()) &&
               "exit tokens are not an array type");

        Value *gep = irBuilder.CreateGEP(exitTokens, {irBuilder.getInt64(0),
                                                      irBuilder.getInt64(
                                                              0)});
        Type *auth_check_types[] = {
                irBuilder.getInt8PtrTy(), /* target address */
                irBuilder.getInt64Ty(),   /* claque access token */
                gep->getType(),           /* valid targets */
                irBuilder.getInt64Ty(),   /* Number of targets */
        };

        FunctionType *auth_check_type = FunctionType::get(
                irBuilder.getInt8PtrTy(), auth_check_types, false);

        FunctionCallee auth_check = F.getParent()->getOrInsertFunction(
                code_check_name, auth_check_type);
        assert(auth_check && "Could not get code access auth function");

        Value *target_address = irBuilder.CreateBitCast(indirectCallTarget,
                                                        auth_check_types[0]);
        Value *args[] = {
                target_address,
                currentAccessToken,
                gep,
                ConstantInt::get(auth_check_types[2],
                                 exitTokens->getType()->getPointerElementType()->getArrayNumElements(),
                                 false)};
        Value *auth_result = irBuilder.CreateCall(auth_check, args);
        auth_call = irBuilder.CreateBitCast(auth_result,
                                            indirectCallTarget->getType());
        addedCodeCheckCount++;

        for (auto *I : indirectCalls[indirectCallTarget]) {
            CallInst *call = dyn_cast<CallInst>(I);
            assert(call);
            addIndirectCallTransfers(call, target_address);
            call->setCalledOperand(auth_call);
        }
    }

    /**
         * @brief Returns true if the indirect call operand should be transferred
         * @param operand
         * @return
         */
    bool HAKCFunctionAnalysis::argShouldTransfer(Use &operand) {
        return operand->getType()->isPointerTy() &&
               !isa<ConstantPointerNull>(operand.get());
    }

    /**
         * @brief Transfers all pointers to the target address of an indirect call
         * @param callInst The indirect call
         * @param target_address The target of the indirect call
         */
    void
    HAKCFunctionAnalysis::addIndirectCallTransfers(CallInst *callInst,
                                                   Value *target_address) {
        std::vector<Value *> newOperands;
        std::vector<CallInst *> originalColors;
        std::vector<Value *> originalOperands;

        irBuilder.SetInsertPoint(callInst);
        if (!target_address) {
            target_address = irBuilder.CreateBitCast(
                    callInst->getCalledOperand(), irBuilder.getInt8PtrTy());
        }

        for (unsigned i = 0; i < callInst->getNumArgOperands(); i++) {
            Use &operand = callInst->getArgOperandUse(i);
            if (!argShouldTransfer(operand)) {
                newOperands.push_back(operand.get());
                continue;
            }

            CallInst *originalColor = saveColor(operand.get(), &irBuilder, getFunction().getParent());
            originalColors.push_back(originalColor);
            originalOperands.push_back(operand.get());
            Value *newOperand = addTargetTransfer(operand, target_address);
            newOperands.push_back(newOperand);
        }

        for (unsigned i = 0; i < newOperands.size(); i++) {
            Use &operand = callInst->getOperandUse(i);
            if (argShouldTransfer(operand)) {
                callInst->setOperand(i, newOperands[i]);
            }
        }
        irBuilder.SetInsertPoint(callInst->getNextNonDebugInstruction());

        unsigned color_idx = 0;
        Value *claque_id = nullptr;
        if (!isCompartmentalizedFunction()) {
            claque_id = ConstantInt::get(irBuilder.getInt32Ty(), 0);
        }
        for (unsigned i = 0; i < newOperands.size(); i++) {
            Use &operand = callInst->getArgOperandUse(i);
            if (argShouldTransfer(operand)) {
                Value *original_color = originalColors[color_idx];
                irBuilder.SetInsertPoint(
                        addCliqueTransferCall(originalOperands[color_idx++],
                                              original_color, claque_id)
                                ->getNextNonDebugInstruction());
            }
        }
    }

    /**
         * @brief Returns the current Function
         * @return
         */
    Function &HAKCFunctionAnalysis::getFunction() {
        return *dominatorTree.getRoot()->getParent();
    }

    /**
         * @brief Adds a check of a signed pointer which checks for valid data access
         * @param signed_ptr The pointer to check
         * @param location The location at which to place the check
         * @return The result of the transfer
         */
    Value *
    HAKCFunctionAnalysis::addDataAuthCheckAtLocation(Value *signed_ptr,
                                                     Instruction *location) {
        assert(signed_ptr);
        assert(!isa<ConstantPointerNull>(signed_ptr));

        if (!location) {
            errs() << "No location for ";
            signed_ptr->print(errs());
            errs() << "\n";
            getFunction().print(errs());
        }
        assert(location);

        if (isa<PHINode>(location)) {
            errs() << "Trying to insert data auth check at ";
            location->print(errs());
            errs() << " for ";
            signed_ptr->print(errs());
            errs() << "\n";
            getFunction().print(errs());
        }
        assert(!isa<PHINode>(location));

        Function &F = getFunction();

        irBuilder.SetInsertPoint(location);

        Type *argTypes[] = {
                Type::getInt8PtrTy(F.getContext()), /* signed ptr */
                Type::getInt64Ty(F.getContext()),   /* Access Token value */
        };
        FunctionType *auth_check_type = FunctionType::get(
                Type::getInt8PtrTy(F.getContext()), argTypes, false);

        FunctionCallee auth_check = F.getParent()->getOrInsertFunction(
                data_check_name, auth_check_type);
        Value *s_ptr = irBuilder.CreateBitCast(signed_ptr, argTypes[0]);

        CallInst *auth_call = irBuilder.CreateCall(auth_check, {s_ptr,
                                                                currentAccessToken});
        Value *bitcast = irBuilder.CreateBitCast(auth_call,
                                                 signed_ptr->getType());

        addedDataCheckCount++;
        return bitcast;
    }

    Value *
    HAKCFunctionAnalysis::addGetSafePointerAtLocation(Value *signed_ptr,
                                                      Instruction *location) {
        assert(signed_ptr);
        assert(!isa<ConstantPointerNull>(signed_ptr));

        if (!location) {
            errs() << "No location for ";
            signed_ptr->print(errs());
            errs() << "\n";
            getFunction().print(errs());
        }
        assert(location);

        if (isa<PHINode>(location)) {
            errs() << "Trying to insert data auth check at ";
            location->print(errs());
            errs() << " for ";
            signed_ptr->print(errs());
            errs() << "\n";
            getFunction().print(errs());
        }
        assert(!isa<PHINode>(location));

        irBuilder.SetInsertPoint(location);
        Value *voidCast = irBuilder.CreateBitCast(signed_ptr,
                                                  irBuilder.getInt8PtrTy());
        Value *maxUserAddr = irBuilder.CreateIntToPtr(
                ConstantInt::get(irBuilder.getInt64Ty(), 0x0000ffffffffffff),
                voidCast->getType());
        Value *addrCheck = irBuilder.CreateICmpUGT(voidCast, maxUserAddr);
        Value *ptrToInt = irBuilder.CreatePtrToInt(voidCast,
                                                   irBuilder.getInt64Ty());
        Value *orValue = irBuilder.CreateOr(ptrToInt, 0xFFFF000000000000);
        Value *orCast = irBuilder.CreateIntToPtr(orValue,
                                                 signed_ptr->getType());

        return irBuilder.CreateSelect(addrCheck, orCast, signed_ptr);
    }

    std::map<Value *, Instruction *>
    HAKCFunctionAnalysis::findAllInsertionLocations() {
        std::map<Value *, Instruction *> authenticationLocations;
        for (auto &it : signedPtrsUses) {
            Value *signed_ptr = it.first;
            Instruction *location = findInsertionPoint(signed_ptr);
            if (debug_output) {
                errs() << "Inserting check for ";
                signed_ptr->print(errs());
                errs() << " at ";
                location->print(errs());
                errs() << "\n\n";
            }
            authenticationLocations[signed_ptr] = location;
        }

        return authenticationLocations;
    }

    /**
         * @brief Creates all authenticated pointers, and clones any intermediate pointer arithmetic
         * between authentication and dereference
         */
    void HAKCFunctionAnalysis::createAllAuthenticatedPointers() {
        std::map<Instruction *, Instruction *> clonedInstLocations;
        std::set<Instruction *> clonedInsts;

        std::map<Value *, Instruction *> authenticationLocations = findAllInsertionLocations();

        for (auto &it : signedPtrsUses) {
            for (auto *use : it.second) {
                for (auto &operand : use->operands()) {
                    Value *def = getDef(operand.get(), false, debug_output);
                    if (def != it.first) {
                        continue;
                    }

                    auto defChain = findDefChain(operand.get(), false, debug_output);
                    if (debug_output) {
                        use->print(errs());
                        errs() << ":";
                        for (auto *def : defChain) {
                            errs() << "\n\t";
                            def->print(errs());
                        }
                        errs() << "\n";
                    }

                    for (auto *dc : defChain) {
                        if (dc == def) {
                            continue;
                        }
                        if (Instruction *I = dyn_cast<Instruction>(dc)) {
                            if (clonedInsts.find(I) == clonedInsts.end()) {
                                clonedInstLocations[I] = I->clone();
                                clonedInsts.insert(I);
                                if (debug_output) {
                                    errs() << "Created clone for ";
                                    dc->print(errs());
                                    errs() << "\n";
                                }
                            }
                        }
                    }
                }
            }
        }

        for (auto &it : clonedInstLocations) {
            it.second->insertBefore(it.first);
            authenticatedPtrs[it.first] = it.second;
        }

        for (auto &it : authenticationLocations) {
            Value *authenticatedPtr;
            if (isCompartmentalizedFunction()) {
                authenticatedPtr = addDataAuthCheckAtLocation(it.first,
                                                              it.second);
            } else {
                authenticatedPtr = addGetSafePointerAtLocation(it.first,
                                                               it.second);
            }
            authenticatedPtrs[it.first] = authenticatedPtr;
        }

        for (auto &it : signedPtrsUses) {
            for (auto *use : it.second) {
                for (auto &operand : use->operands()) {
                    Value *def = getDef(operand.get(), false, debug_output);
                    if (def != it.first) {
                        continue;
                    }

                    auto defChain = findDefChain(operand.get(), false, debug_output);

                    for (int i = defChain.size() - 2; i >= 0; i--) {
                        Value *dc = defChain[i];
                        Value *prev = defChain[i + 1];

                        if (!prev) {
                            errs()
                                    << "Could not find previous in def chain to ";
                            operand->print(errs());
                            errs() << " for ";
                            use->print(errs());
                            errs() << "\n";
                            getFunction().print(errs());
                        }
                        assert(prev);

                        Instruction *auth_ptr = dyn_cast<Instruction>(
                                authenticatedPtrs[prev]);
                        Value *clone = authenticatedPtrs[dc];
                        if (!auth_ptr) {
                            errs() << "Could not find auth ptr for ";
                            prev->print(errs());
                            errs() << "\n";
                            getFunction().print(errs());
                        }
                        assert(auth_ptr);
                        if (!clone) {
                            errs() << "Could not find clone for ";
                            dc->print(errs());
                            errs() << "\n";
                            getFunction().print(errs());
                        }
                        assert(clone);

                        if (Instruction *I = dyn_cast<Instruction>(clone)) {
                            for (unsigned j = 0; j < I->getNumOperands();
                                 j++) {
                                Value *operand = I->getOperand(j);
                                if (operand == prev) {
                                    I->setOperand(j, auth_ptr);
                                }
                            }
                            if (!dominatorTree.dominates(auth_ptr, I)) {
                                I->moveAfter(auth_ptr);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
         * @brief Replace signed pointer dereferences with authenticated dereferences
         */
    void HAKCFunctionAnalysis::transformPointerDereferences() {
        for (auto &it : signedPtrsUses) {
            for (auto *use : it.second) {
                for (unsigned i = 0; i < use->getNumOperands(); i++) {
                    Use &operand = use->getOperandUse(i);
                    if (argNeedsAuthentication(operand) &&
                        (it.first == getDef(operand.get(), false, debug_output) ||
                         it.first == operand.get())) {
                        Value *auth_ptr = authenticatedPtrs[operand.get()];
                        if (!auth_ptr) {
                            errs() << "Could not find auth ptr for ";
                            operand->print(errs());
                            errs() << "\n";
                            getFunction().print(errs());
                        }
                        assert(auth_ptr);
                        if (debug_output) {
                            errs() << "Replacing ";
                            operand->print(errs());
                            errs() << " with ";
                            auth_ptr->print(errs());
                            errs() << " in instruction ";
                            use->print(errs());
                            errs() << "\n\n";
                        }
                        use->setOperand(i, auth_ptr);
                    }
                }
            }
        }
    }

    /**
         * @brief Returns true if an argument should be authenticated
         * @param arg The function argument to check
         * @return
         */
    bool HAKCFunctionAnalysis::argNeedsAuthentication(Use &arg) {
        if (StoreInst *store = dyn_cast<StoreInst>(arg.getUser())) {
            if (arg.getOperandNo() != store->getPointerOperandIndex()) {
                /* Stored values do not need authentication */
                return false;
            }
        } else if (CallInst *call = dyn_cast<CallInst>(arg.getUser())) {
            if (InlineAsm *inlineAsm = dyn_cast<InlineAsm>(
                        call->getCalledOperand())) {
                if (debug_output) {
                    errs() << "Arg ";
                    arg->print(errs());
                    errs() << " of ";
                    call->print(errs());
                    errs() << " is argument " << arg.getOperandNo() << "\n";
                }
                /* The RCU protected double-link list generates this assembly, and we want
                     * to store authenticated pointers. So ensure that authenticated pointers
                     * are the values getting stored.  See __list_add_rcu for an example.
                     * Perhaps a better way to handle this is to use Capstone to analyze the
                     * inline assembly string, and figure out the stored value in an
                     * architectural independent way. But that's way down the road. */
                if (inlineAsm->getAsmString() == "stlr $1, $0") {
                    if (arg.getOperandNo() == 1) {
                        return false;
                    } /*else if (arg.getOperandNo() == 0) {
                        return true;
                    }*/
                }
            } else if (call->getCalledFunction()) {
                if (debug_output) {
                    errs() << "arg.getOperandNo() = " << arg.getOperandNo()
                           << "\n";
                }
                for (auto *inArg : M.getAuthenticatedPointersIn(
                             call->getCalledFunction())) {
                    auto inArgNum = getFunctionArgNumber(inArg);
                    if (debug_output) {
                        errs() << "inArgNum = " << inArgNum << " for ";
                        inArg->print(errs());
                        errs() << "\n";
                    }
                    if (inArgNum >= 0 &&
                        (unsigned) inArgNum == arg.getOperandNo()) {
                        return !isa<AllocaInst>(getDef(arg.get(), false, debug_output));
                    }
                }
                return ((arg->getType()->isPointerTy() ||
                         isa<PtrToIntInst>(arg.get()))) &&
                       (isSafeTransitionFunction(call->getCalledFunction()) ||
                        isIntrinsicNeedingAuthentication(call) ||
                        call->getCalledFunction()->getName().contains(
                                "static_branch_"));
            }
        }
        return (arg->getType()->isPointerTy() ||
                isa<PtrToIntInst>(arg.get()) || isa<IntToPtrInst>(arg.get())) &&
               !isa<Function>(arg) && pointerShouldBeChecked(arg.get());
    }

    /**
         * @brief Adds transfers of all indirect function arguments
         */
    void HAKCFunctionAnalysis::addAllIndirectTransfers() {
        for (auto &it : indirectCalls) {
            if (isCompartmentalizedFunction()) {
                addCodeAuthCheck(it.first);
            } else {
                addGetSafeCodePtr(it.first);
            }
        }
    }

    bool HAKCFunctionAnalysis::typeNeedsSigning(Type *type) {
        return isa<PointerType>(
                type) /*&& isa<FunctionType>(type->getPointerElementType())*/;
    }

    bool HAKCFunctionAnalysis::needsRecursion(Value *aggregateVal,
                                              StructType *structType,
                                              unsigned idx) {
        static std::set<StringRef> noRecurseTypeNames = {"struct.module"};
        bool result = false;
        if (isa<StructType>(structType->getStructElementType(idx))) {
            result = noRecurseTypeNames.find(
                             structType->getStructElementType(
                                               idx)
                                     ->getStructName()) ==
                     noRecurseTypeNames.end();
        }
        if (!result && isa<GlobalVariable>(aggregateVal)) {
            GlobalVariable *gv = dyn_cast<GlobalVariable>(aggregateVal);
            if (gv->hasInitializer()) {
                Constant *initializer = gv->getInitializer();
                Constant *structMember = initializer->getAggregateElement(
                        idx);
                if (PointerType *ptrType = dyn_cast<PointerType>(
                            structMember->getType())) {
                    result =
                            ptrType->getPointerElementType()->isStructTy() &&
                            noRecurseTypeNames.find(
                                    ptrType->getPointerElementType()->getStructName()) ==
                                    noRecurseTypeNames.end();
                }
            }
        }

        return result;
    }

    Instruction *HAKCFunctionAnalysis::signStructPointers(Value *value) {
        std::set<Value *> visited_structs;
        return signStructPointersRecurse(value, &visited_structs);
    }

    /**
         * @brief Signs all pointers of struct members
         * @param value The struct needing function signatures
         * @return
         */
    Instruction *HAKCFunctionAnalysis::signStructPointersRecurse(Value *value,
                                                                 std::set<Value *> *visited_structs) {
        Instruction *result = nullptr;
        Type *type = value->getType();
        if (isa<PointerType>(type)) {
            type = type->getPointerElementType();
        } else {
            return nullptr;
        }

        Constant *initializer = nullptr;
        if (GlobalVariable *gv = dyn_cast<GlobalVariable>(value)) {
            if (gv->hasInitializer()) {
                initializer = gv->getInitializer();
            }
        }

        if (StructType *structType = dyn_cast<StructType>(type)) {
            if (visited_structs->find(value) != visited_structs->end()) {
                return nullptr;
            }
            visited_structs->insert(value);

            if (debug_output) {
                errs() << "Signing function members of " << value->getName()
                       << "\n";
            }

            for (unsigned i = 0;
                 i < structType->getStructNumElements(); i++) {
                Type *currType = structType->getStructElementType(i);
                if (initializer && initializer->getAggregateElement(i) &&
                    isa<ConstantPointerNull>(
                            initializer->getAggregateElement(i))) {
                    if (debug_output) {
                        errs() << "Initializer " << i
                               << " is null, so skipping\n";
                    }
                    continue;
                }
                bool recurse = needsRecursion(value, structType, i);

                if (typeNeedsSigning(currType)) {
                    if (debug_output) {
                        errs() << "Member " << i << " (type ";
                        currType->print(errs());
                        errs() << ") needs signing\n";
                    }
                    Value *structMember = irBuilder.CreateStructGEP(value,
                                                                    i);
                    //                    Value *color = saveColor(structMember);
                    LoadInst *load = irBuilder.CreateLoad(structMember);
                    CallInst *transferCall = addSignatureWithColorCall(load);
                    result = irBuilder.CreateStore(transferCall,
                                                   structMember);
                    if (debug_output) {
                        errs() << "Created transfer for member " << i
                               << " (";
                        structType->getTypeAtIndex(i)->print(errs());
                        errs() << "): \n";
                        result->print(errs());
                        errs() << "\n";
                    }
                }
                if (recurse) {
                    if (debug_output) {
                        errs() << "Type ";
                        currType->print(errs());
                        errs() << " needs recursion\n";
                    }
                    Value *structMember;
                    if (initializer) {
                        structMember = initializer->getAggregateElement(i);
                    } else {
                        structMember = irBuilder.CreateStructGEP(value, i);
                    }
                    assert(structMember);
                    if (debug_output) {
                        errs() << "Created GEP to struct member " << i
                               << ": ";
                        structMember->print(errs());
                        errs() << "\n";
                    }
                    Instruction *i = signStructPointersRecurse(structMember,
                                                               visited_structs);
                    if (i) {
                        result = i;
                    }
                }
            }
        } else if (debug_output) {
            errs() << "Value ";
            if (Function *f = dyn_cast<Function>(value)) {
                errs() << f->getName();
            } else {
                value->print(errs());
            }
            errs() << " does not need recursive signing\n";
        }
        return result;
    }

    Instruction *HAKCFunctionAnalysis::signGlobalVariableFunctionPointers(
            GlobalValue *global) {
        return signStructPointers(global);
    }

    void
    HAKCFunctionAnalysis::addGlobalClonesAndTransfer(Value *global, Use &arg,
                                                     std::map<Value *, Value *> &signed_clones,
                                                     Instruction *I) {
        assert(isa<GlobalValue>(global));
        auto def_chain = findDefChain(arg.get());
        if (def_chain.size() == 1 &&
            signed_clones.find(global) == signed_clones.end()) {
            irBuilder.SetInsertPoint(I);
            auto *signed_ptr = addSignatureWithColorCall(global);
            signed_clones[global] = signed_ptr;
            return;
        }
        if (debug_output) {
            errs() << "Def chain for ";
            arg->print(errs());
            errs() << ":\n";
            for (auto *c : def_chain) {
                errs() << "\t";
                c->print(errs());
                errs() << "\n";
            }
        }
        for (int j = def_chain.size() - 2; j >= 0; j--) {
            if (isa<Instruction>(def_chain[j]) ||
                isa<GEPOperator>(def_chain[j]) ||
                isa<BitCastOperator>(def_chain[j])) {
                Value *prev = def_chain[j + 1];

                if (!prev) {
                    errs() << "Could not find previous in def chain to ";
                    arg->print(errs());
                    errs() << " for ";
                    arg.getUser()->print(errs());
                    errs() << "\n";
                    getFunction().print(errs());
                }
                assert(prev);
                /* Often global variables are accessed like &global_foo.array[bar]
                     * (see raw6_local_deliver() for an example), which translates to a
                     * GEP of a GEPOperator. Instead of creating a new instruction for the
                     * GEPOperator, just transfer the result of the GEP */
                if (prev == global &&
                    signed_clones.find(global) == signed_clones.end()) {
                    irBuilder.SetInsertPoint(I);
                    auto *signed_ptr = addSignatureWithColorCall(global);
                    signed_clones[global] = signed_ptr;
                }

                Instruction *link;
                if (isa<Instruction>(def_chain[j])) {
                    link = dyn_cast<Instruction>(def_chain[j]);
                } else {
                    auto *expr = dyn_cast<ConstantExpr>(def_chain[j]);
                    assert(expr);
                    link = expr->getAsInstruction();
                    assert(link);
                    irBuilder.SetInsertPoint(I);
                    irBuilder.Insert(link);
                }
                Value *transferred = signed_clones[prev];
                if (!transferred) {
                    if (debug_output) {
                        errs()
                                << "Could not find previous transferred value for ";
                        prev->print(errs());
                        errs() << "\nCreating transfer of ";
                        def_chain[j]->print(errs());
                        errs() << "\n";
                    }
                    irBuilder.SetInsertPoint(link);
                    CallInst *transfer = addSignatureWithColorCall(
                            def_chain[j]);
                    if (!dominatorTree.dominates(transfer, I)) {
                        transfer->moveBefore(I);
                    }
                    signed_clones[def_chain[j]] = transfer;
                    if (def_chain[j] == arg.get()) {
                        signed_clones[global] = transfer;
                    }
                    continue;
                }
                assert(transferred);

                if (debug_output) {
                    errs() << "Creating clone of ";
                    def_chain[j]->print(errs());
                    errs() << "\n";
                }
                Instruction *clone = link->clone();
                for (unsigned clone_idx = 0;
                     clone_idx < clone->getNumOperands(); clone_idx++) {
                    Value *operand = clone->getOperand(clone_idx);
                    if (operand == prev) {
                        clone->setOperand(clone_idx, transferred);
                    }
                }

                if (signed_clones[global] &&
                    dominatorTree.dominates(link, I)) {
                    irBuilder.SetInsertPoint(I);
                } else {
                    irBuilder.SetInsertPoint(link);
                }
                irBuilder.Insert(clone);
                signed_clones[def_chain[j]] = clone;
            }
        }
    }

    /**
         * @brief Returns true if the PHINode uses the specified target
         * @param phiNode
         * @param target
         * @return
         */
    bool HAKCFunctionAnalysis::phiNodeUsesValue(PHINode *phiNode, Value *target,
                                                std::set<PHINode *> &visited) {
        visited.insert(phiNode);
        for (auto &val : phiNode->incoming_values()) {
            Value *def = getDef(val.get(), true, debug_output);
            if (val.get() == target || def == target) {
                return true;
            } else if (PHINode *phi = dyn_cast<PHINode>(def)) {
                if (visited.find(phi) != visited.end()) {
                    continue;
                }
                if (phiNodeUsesValue(phi, target, visited)) {
                    return true;
                }
            }
        }
        return false;
    }

    bool HAKCFunctionAnalysis::globalNeedsTransferring(GlobalValue *global) {
        bool ret = false;
        for (auto *use : globalArgumentUses[global]) {
            if (!(isa<LoadInst>(use) /* && (
                                                use->getType()->isIntegerTy() ||
                                                use->getType()->isStructTy()
                                                )*/
                  )) {
                ret = true;
            }
        }

        return ret;
    }

    /**
         * Transfer all global variables passed as function arguments to the current clique, so
         * authentication checks will pass
         */
    void HAKCFunctionAnalysis::addAllGlobalTransfers() {
        std::map<Value *, Value *> signed_clones;
        for (auto &it : globalArgumentUses) {
            if (debug_output) {
                errs() << "Global " << it.first->getName() << " uses:\n";
                for (auto *user : it.second) {
                    user->print(errs());
                    errs() << "\n";
                }
            }

            if (!globalNeedsTransferring(it.first)) {
                if (debug_output) {
                    errs() << it.first->getName()
                           << " does not need transferring\n";
                }
                continue;
            }

            Instruction *I = findUseInsertionPoint(it.first, it.second);
            assert(I);
            if (debug_output) {
                errs() << "Adding transfer for global "
                       << it.first->getName() << " at ";
                I->print(errs());
                errs() << "\n";
            }
            irBuilder.SetInsertPoint(I);
            Instruction *functionSigning = signGlobalVariableFunctionPointers(
                    it.first);
            if (functionSigning) {
                I = functionSigning->getNextNonDebugInstruction();
                irBuilder.SetInsertPoint(I);
            }

            for (auto *user : it.second) {
                if (CallInst *call = dyn_cast<CallInst>(user)) {
                    for (unsigned idx = 0;
                         idx < call->getNumArgOperands(); idx++) {
                        Use &arg = call->getArgOperandUse(idx);
                        Value *def = getDef(arg.get(), false, debug_output);
                        if (def == it.first) {
                            addGlobalClonesAndTransfer(it.first, arg,
                                                       signed_clones, I);
                            if (!signed_clones[it.first]) {
                                errs() << "Could not create transfer for ";
                                it.first->print(errs());
                                errs() << " in function "
                                       << getFunction().getName() << "\n";
                            }
                            assert(signed_clones[it.first]);
                        } /*else if (PHINode *phiNode = dyn_cast<PHINode>(def)) {
                            std::set<PHINode *> visited;
                            if (!phiNodeUsesValue(phiNode, it.first, visited)) {
                                continue;
                            }
                            if (debug_output) {
                                phiNode->print(errs());
                                errs() << " uses " << it.first->getName()
                                       << "\n";
                            }
                            irBuilder.SetInsertPoint(phiNode->getParent()->getFirstNonPHIOrDbgOrLifetime());
                            auto *signed_ptr = addSignatureWithColorCall(phiNode);
                            signed_clones[phiNode] = signed_ptr;
                        }*/
                    }
                } else if (StoreInst *store = dyn_cast<StoreInst>(user)) {
                    Value *def = getDef(store->getValueOperand(), false, debug_output);
                    assert(def == it.first && "Unexpected global use");
                    Use &arg = store->getOperandUse(0);
                    addGlobalClonesAndTransfer(it.first, arg, signed_clones, I);
                    if (!signed_clones[it.first]) {
                        errs() << "Could not create transfer for ";
                        it.first->print(errs());
                        errs() << " in function "
                               << getFunction().getName() << "\n";
                    }
                    assert(signed_clones[it.first]);
                } else if (isa<LoadInst>(user)) {
                    continue;
                                        // assert(getDef(load->getPointerOperand()) == it.first && "Unexpected global use");
                                        // Use &arg = load->getOperandUse(0);
                                        // addGlobalClonesAndTransfer(it.first, arg, signed_clones, I);
                                        // if (!signed_clones[it.first]) {
                                        //     errs() << "Could not create transfer for ";
                                        //     it.first->print(errs());
                                        //     errs() << " in function "
                                        //            << getFunction().getName() << "\n";
                                        // }
                                        // assert(signed_clones[it.first]);
                }
                else if (PHINode *phi = dyn_cast<PHINode>(user)) {
                    bool found = false;
                    for (unsigned i = 0; i < phi->getNumIncomingValues(); i++) {
                        if (getDef(phi->getIncomingValue(i), false, debug_output) == it.first) {
                            Use &arg = phi->getOperandUse(i);
                            addGlobalClonesAndTransfer(it.first, arg,
                                                       signed_clones, I);
                            found = true;
                            if (!signed_clones[it.first]) {
                                errs() << "Could not create transfer for ";
                                it.first->print(errs());
                                errs() << " in function "
                                       << getFunction().getName() << "\n";
                            }
                            assert(signed_clones[it.first]);
                        }
                    }
                    assert(found);
                } else {
                    errs() << "Unhandled global handling\n";
                    assert(false);
                }
            }
        }

        for (auto &it : globalArgumentUses) {
            for (auto *user : it.second) {
                for (unsigned i = 0; i < user->getNumOperands(); i++) {
                    Use &operand = user->getOperandUse(i);
                    if (signed_clones.find(operand.get()) !=
                        signed_clones.end()) {
                        if (debug_output) {
                            errs() << "Setting operand " << i << " ("
                                   << operand->getName()
                                   << ") of ";
                            user->print(errs());
                            errs() << " to ";
                            signed_clones[operand.get()]->print(errs());
                            errs() << "\n";
                        }
                        user->setOperand(i, signed_clones[operand.get()]);
                    }
                }
            }
        }
    }

    /**
         * @brief Returns true if a pointer is from a object allocated on the Function's stack
         * @param v
         * @return
         */
    bool HAKCFunctionAnalysis::isStackAllocatedObject(Value *v) {
        Value *def = getDef(v, false, debug_output);
        return isa<AllocaInst>(def) /*&&
               !def->getType()->getPointerElementType()->isPointerTy()*/
                ;
    }

    /**
         * @brief Perform analysis of an Instruction
         * @param I
         */
    void HAKCFunctionAnalysis::handleInstruction(Instruction *I) {
        if (CallInst *call = dyn_cast<CallInst>(I)) {
            handleCall(call);
        } else if (LoadInst *load = dyn_cast<LoadInst>(I)) {
            handleLoad(load);
        } else if (StoreInst *store = dyn_cast<StoreInst>(I)) {
            handleStore(store);
        } else if (CmpInst *compare = dyn_cast<CmpInst>(I)) {
            handleComparison(compare);
        } else if (BinaryOperator *binOp = dyn_cast<BinaryOperator>(I)) {
            handleBinaryOperator(binOp);
        }
    }

    /**
         * @brief Retrieves the Instruction of a User
         * @param user
         * @return
         */
    Instruction *HAKCFunctionAnalysis::getUserInst(User *user) {
        if (Instruction *inst = dyn_cast<Instruction>(user)) {
            return inst;
        } else if (isa<BitCastOperator>(user) || isa<GEPOperator>(user)) {
            return getUserInst(*user->user_begin());
        } else {
            errs() << "Unexpected user: ";
            user->print(errs());
            errs() << "\n";
            assert(false && "getUserInst");
            return nullptr; /* Shut up the compiler */
        }
    }

    /**
         * @brief Returns true of ptr is a PHINode consisting only of global variables
         * @param ptr
         * @param nodes
         * @return
         */
    bool HAKCFunctionAnalysis::isPHIofGlobalsOnly(Value *ptr,
                                                  std::set<PHINode *> &nodes) {
        if (PHINode *phiNode = dyn_cast<PHINode>(ptr)) {
            if (nodes.find(phiNode) != nodes.end()) {
                return true;
            }
            if (debug_output) {
                errs() << "Examining PHI Node ";
                phiNode->print(errs());
                errs() << " for Globals (" << nodes.size() << ")\n";
            }
            nodes.insert(phiNode);
            for (auto &val : phiNode->incoming_values()) {
                Value *def = getDef(val.get(), false, debug_output);
                if (debug_output) {
                    errs() << "\tPHI Node value: ";
                    val->print(errs());
                    errs() << "\n\t\tDef: ";
                    def->print(errs());
                    errs() << "\n";
                }
                if (!isa<GlobalValue>(def)) {
                    if (isa<PHINode>(def)) {
                        if (isPHIofGlobalsOnly(def, nodes)) {
                            continue;
                        }
                    }
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    bool HAKCFunctionAnalysis::isSelectOfAuthenticatedPointers(Value *v) {
        if (SelectInst *select = dyn_cast<SelectInst>(v)) {
            if (debug_output) {
                errs() << "Checking if Value is a select statement of pointers that need checking: ";
            }
            return !pointerShouldBeChecked(select->getFalseValue()) && !pointerShouldBeChecked(select->getTrueValue());
        }

        return false;
    }

    /**
         * @brief Returns true if a pointer should be authenticated
         * @param ptr
         * @return
         */
    bool HAKCFunctionAnalysis::pointerShouldBeChecked(Value *ptr) {
        std::set<PHINode *> nodes;

        if (CallInst *call = dyn_cast<CallInst>(ptr)) {
            if (debug_output) {
                errs() << "Value ";
                ptr->print(errs());
                errs() << " is a CallInst\n";
            }
            if (call->getCalledFunction() &&
                call->getCalledFunction()->getName() == get_safe_ptr_name) {
                return false;
            } else if (call->isInlineAsm()) {
                /* These are usually the result of reading a register value */
                return false;
            } else if (call->getCalledFunction() &&
                       call->getCalledFunction()->isIntrinsic() &&
                       call->getCalledFunction()->getIntrinsicID() ==
                               Intrinsic::IndependentIntrinsics::read_register) {
                return false;
            }
        } else if (isa<Constant>(ptr)) {
            return false;
        } else if (!ptr->getType()->isPointerTy() &&
                   !ptr->getType()->isArrayTy()) {
            if (debug_output) {
                ptr->print(errs());
                errs() << " is not a pointer\n";
            }
            return false;
        }

        bool shouldBeChecked = !isStackAllocatedObject(ptr) &&
                               !isa<ConstantPointerNull>(ptr) &&
                               !isa<GlobalValue>(ptr) &&
                               !isPHIofGlobalsOnly(ptr, nodes) &&
                               !isSelectOfAuthenticatedPointers(ptr);


        if (shouldBeChecked) {
            for (auto *authPtr : pointersAlreadyAuthenticated) {
                if (debug_output) {
                    errs() << "Checking ";
                    getDef(ptr, false, debug_output)->print(errs());
                    errs() << " against ";
                    getDef(authPtr, false, debug_output)->print(errs());
                    errs() << "\n";
                }
                if (getDef(authPtr, false, debug_output) == getDef(ptr, false, debug_output)) {
                    return false;
                }
            }
        }

        return shouldBeChecked;
    }

    /**
         * @brief Adds a signed pointer dereference to the list if the source pointer should be authenticated
         * @param use
         */
    void HAKCFunctionAnalysis::registerPointerDereference(Use &use) {
        Value *definition = getDef(use.get(), false, debug_output);
        if ((isa<StoreInst>(use.getUser()) && isa<IntToPtrInst>(use.get())) ||
            (definition->getType()->isIntegerTy(64))) {
            bool registerUse = false;
            if (CallInst *call = dyn_cast<CallInst>(definition)) {
                registerUse = isRegisterRead(call);
            }
            if (!registerUse) {
                if (debug_output) {
                    errs() << "Using ";
                    use->print(errs());
                    errs() << " instead of ";
                    definition->print(errs());
                    errs() << "\n";
                }
                definition = use.get();
            }
        }
        if (debug_output) {
            errs() << "Checking if ";
            use->print(errs());
            errs() << " should be registered\n";
        }

        if (pointerShouldBeChecked(definition)) {
            if (isa<IntToPtrInst>(use.get())) {
                /* per-cpu pointers will sometimes use inline assembly to get
                * their pointers, so use the value after offset is added
                */
                //                if (CallInst *call = dyn_cast<CallInst>(use.getUser())) {
                //                    if (isRegisterRead(call)) {
                //                        if (debug_output) {
                //                            errs() << "Detected per-cpu pointer: ";
                //                            use->print(errs());
                //                            errs() << "\nDef chain:\n";
                //                            for (auto *v : findDefChain(use.get())) {
                //                                errs() << "\t";
                //                                v->print(errs());
                //                                errs() << "\n";
                //                            }
                //                        }
                //                        definition = use.get();
                //                    }
                //                } else {
                bool is_percpu_ptr = isPerCPUPointer(use.get());
                //                    for (auto *v : findDefChain(use.get())) {
                //                        if (!isa<IntToPtrInst>(v) && !isa<AddOperator>(v) &&
                //                            !isa<PtrToIntInst>(v) && !isa<LoadInst>(v)) {
                //                            is_percpu_ptr = false;
                //                            break;
                //                        }
                //                    }

                if (is_percpu_ptr) {
                    if (debug_output) {
                        errs() << "Detected per-cpu pointer: ";
                        use->print(errs());
                        errs() << "\nDef chain:\n";
                        for (auto *v : findDefChain(use.get())) {
                            errs() << "\t";
                            v->print(errs());
                            errs() << "\n";
                        }
                    }
                    definition = use.get();
                }
                //                }
            }
            if (debug_output) {
                errs() << "Definition ";
                if (Function *f = dyn_cast<Function>(definition)) {
                    errs() << f->getName() << " ";
                } else {
                    definition->print(errs());
                }
                errs() << " from ";
                use.getUser()->print(errs());
                errs() << " is registered\n";
            }
            auto *inst = getUserInst(use.getUser());
            if (CallInst *call = dyn_cast<CallInst>(use.getUser())) {
                if (callIsSafeTransition(call)) {
                    safeTransitionCalls.insert(call);
                }
            }
            signedPtrsUses[definition].insert(inst);
        } else {
            if (debug_output) {
                errs() << "Definition ";
                if (Function *f = dyn_cast<Function>(definition)) {
                    errs() << f->getName() << " ";
                } else {
                    definition->print(errs());
                }
                errs() << " from ";
                use.getUser()->print(errs());
                errs() << " should not be checked\n";
            }
        }
    }

    /**
         * @brief Process a LoadInst for analysis
         * @param load
         */
    void HAKCFunctionAnalysis::handleLoad(LoadInst *load) {
        auto *def = getDef(load->getPointerOperand(), false, debug_output);
        if (isa<AllocaInst>(def) && def == load->getPointerOperand()) {
            return;
        }
        registerPointerDereference(
                load->getOperandUse(load->getPointerOperandIndex()));
        if (GlobalValue *globalValue = dyn_cast<GlobalValue>(def)) {
            //            if (globalShouldBeTransferred(load->getOperandUse(0))) {
            globalArgumentUses[globalValue].insert(load);
            //            }
        } else if (PHINode *phi = dyn_cast<PHINode>(def)) {
            for (unsigned i = 0; i < phi->getNumIncomingValues(); i++) {
                if (GlobalValue *globalValue = dyn_cast<GlobalValue>(
                            getDef(phi->getIncomingValue(i), false, debug_output))) {
                    //                    if (globalShouldBeTransferred(phi->getOperandUse(i))) {
                    globalArgumentUses[globalValue].insert(phi);
                    //                    }
                }
            }
        }
    }

    /**
         * @brief Process a StoreInst for analysis
         * @param store
         */
    void HAKCFunctionAnalysis::handleStore(StoreInst *store) {
        auto *def = getDef(store->getPointerOperand(), false, debug_output);
        if (isa<AllocaInst>(def) && def == store->getPointerOperand()) {
            return;
        }
        registerPointerDereference(
                store->getOperandUse(store->getPointerOperandIndex()));

        if (GlobalValue *globalValue = dyn_cast<GlobalValue>(
                    store->getValueOperand())) {
            if (globalShouldBeTransferred(store->getOperandUse(0))) {
                globalArgumentUses[globalValue].insert(store);
            }
        }
    }

    bool HAKCFunctionAnalysis::pointerAuthenticatedAtStart(Value *v) {
        Value *def = getDef(v, false, debug_output);
        for (auto *ptr : pointersAlreadyAuthenticated) {
            if (getDef(ptr, false, debug_output) == def) {
                return true;
            }
        }
        return false;
    }

    /**
         * @brief Ensures that authenticated pointers are used in comparisons for correctness
         * @param compare
         */
    void HAKCFunctionAnalysis::handleComparison(CmpInst *compare) {
        if (debug_output) {
            errs() << "Checking comparison ";
            compare->print(errs());
            errs() << "\n";
        }
        //        if(isa<ConstantPointerNull>(compare->getOperand(0)) ||
        //           isa<ConstantPointerNull>(compare->getOperand(1))) {
        //            if(debug_output) {
        //                errs() << "BinaryOp ";
        //                compare->print(errs());
        //                errs() << " is a comparison with NULL, and is not registered\n";
        //            }
        //            return;
        //        } else {
        //            if(debug_output) {
        //                errs() << "BinaryOp ";
        //                compare->print(errs());
        //                errs() << " is not a comparison with NULL\n";
        //            }
        //        }

        if (isa<ConstantPointerNull>(compare->getOperand(0)) ||
            isa<ConstantPointerNull>(compare->getOperand(1))) {
            if (debug_output) {
                errs()
                        << "\tComparisons with null do not need authentication\n";
            }
            return;
        }

        if (isCompartmentalizedFunction()) {
            bool arg0NeedsAuth =
                    argNeedsAuthentication(compare->getOperandUse(0)) &&
                    !isa<GlobalValue>(getDef(compare->getOperand(0), false, debug_output));
            bool arg1NeedsAuth =
                    argNeedsAuthentication(compare->getOperandUse(1)) &&
                    !isa<GlobalValue>(getDef(compare->getOperand(1), false, debug_output));
            if (debug_output) {
                if (arg0NeedsAuth) {
                    errs() << "Argument 0 needs auth\n";
                } else {
                    errs() << "Argument 0 does not need auth\n";
                }
                if (arg1NeedsAuth) {
                    errs() << "Argument 1 needs auth\n";
                } else {
                    errs() << "Argument 1 does not need auth\n";
                }
            }
            if (arg0NeedsAuth && arg1NeedsAuth) {
                if (debug_output) {
                    errs() << "Both operands should be checked\n";
                }
                registerPointerDereference(compare->getOperandUse(0));
                registerPointerDereference(compare->getOperandUse(1));
            } else {
                if (arg0NeedsAuth /*&& pointerAuthenticatedAtStart(compare->getOperand(1))*/) {
                    if (debug_output) {
                        errs() << "Registering argument 0\n";
                    }
                    registerPointerDereference(compare->getOperandUse(0));
                } else {
                    if (debug_output && arg0NeedsAuth) {
                        errs() << "Argument 1 (";
                        compare->getOperand(1)->print(errs());
                        errs() << " ) already authenticated\n";
                    }
                }
                if (arg1NeedsAuth /* && pointerAuthenticatedAtStart(compare->getOperand(0))*/) {
                    if (debug_output) {
                        errs() << "Registering argument 1\n";
                    }
                    registerPointerDereference(compare->getOperandUse(1));
                }
            }
        } else {
            if (argNeedsAuthentication(compare->getOperandUse(0))) {
                registerPointerDereference(compare->getOperandUse(0));
            }
            if (argNeedsAuthentication(compare->getOperandUse(1))) {
                registerPointerDereference(compare->getOperandUse(1));
            }
        }
    }

    /**
     * @brief BinaryOperators (like bitwise OR) should use authenticated values
     * @param binOp
     */
    void HAKCFunctionAnalysis::handleBinaryOperator(BinaryOperator *binOp) {
        if (debug_output) {
            errs() << "Checking binary op ";
            binOp->print(errs());
            errs() << "\n";
        }
        if (argNeedsAuthentication(binOp->getOperandUse(0)) &&
            argNeedsAuthentication(binOp->getOperandUse(1))) {
            registerPointerDereference(binOp->getOperandUse(0));
            registerPointerDereference(binOp->getOperandUse(1));
        }
    }


    /**
         * @brief Returns true if a GlobalValue should be transferred
         * @param globalValue
         * @return
         */
    bool HAKCFunctionAnalysis::globalShouldBeTransferred(Use &globalValueArg) {
        /* Don't transfer to printk */
        if (GlobalValue *globalValue = dyn_cast<GlobalValue>(
                    getDef(globalValueArg.get(), false, debug_output))) {
            /* Don't transfer THIS_MODULE */
            if (globalValue->getName() == "__this_module") {
                return false;
            }

            if (CallInst *call = dyn_cast<CallInst>(
                        globalValueArg.getUser())) {
                if (!functionIsAnalysisCandidate(call->getCalledFunction())) {
                    return false;
                }
            }

            /* Ignore constant string arrays */
            if (globalValue->getValueType()->isArrayTy() &&
                globalValue->getValueType()->getArrayElementType()->isIntegerTy(
                        8)) {
                return false;
            }

            //            if (!globalValue->getValueType()->isPointerTy() &&
            //                !globalValue->getValueType()->isArrayTy()) {
            //                return false;
            //            }

            return true;
        }

        if (debug_output) {
            errs() << "Arg " << globalValueArg.getOperandNo() << " (";
            globalValueArg->print(errs());
            errs() << " ) is not a GlobalValue\n";
        }
        return false;
    }

    bool HAKCFunctionAnalysis::isCompartmentalizedFunction() {
        return (M.isCompartmentalized() &&
                !isOutsideTransferFunc(&getFunction()));
    }

    /**
         * @brief Processes a function call for analysis
         * @param call
         */
    void HAKCFunctionAnalysis::handleCall(CallInst *call) {
        if (call->getCalledFunction() &&
            (call->getCalledFunction()->isDebugInfoForProfiling() ||
             intrinsics_to_skip.find(call->getIntrinsicID()) !=
                     intrinsics_to_skip.end())) {
            return;
        }

        bool needsAuthenticatedArgs = (call->isInlineAsm() ||
                                       (M.functionInAnalysisSet(
                                                call->getCalledFunction()) &&
                                        !isOutsideTransferFunc(
                                                call->getCalledFunction()) &&
                                        !M.getAuthenticatedPointersIn(
                                                  call->getCalledFunction())
                                                 .empty()) ||
                                       callIsSafeTransition(call));

        if (isa<IntrinsicInst>(call)) {
            needsAuthenticatedArgs = isIntrinsicNeedingAuthentication(call);
        }

        if (debug_output) {
            call->print(errs());
            if (needsAuthenticatedArgs) {
                errs() << " needs authenticated args\n";
            } else {
                errs() << " does not need authenticated args\n";
                //                errs() << "call->isInlineAsm(): " << call->isInlineAsm() << "\n"
                //                       << "M.functionInAnalysisSet(call->getCalledFunction()): " << M.functionInAnalysisSet(call->getCalledFunction()) << "\n"
                //                       << "M.getAuthenticatedPointersIn(call->getCalledFunction()).empty(): " << M.getAuthenticatedPointersIn(call->getCalledFunction()).empty() << "\n"
                //                       << "callIsSafeTransition(call): " << callIsSafeTransition(call) << "\n";
            }
        }

        if (call->isIndirectCall()) {
            if (debug_output) {
                errs() << "Indirect call: ";
                call->print(errs());
                errs() << "\n";
            }
            indirectCalls[call->getCalledOperand()].insert(call);
        } else if (needsAuthenticatedArgs) {
            for (auto &arg : call->args()) {
                if (argNeedsAuthentication(arg)) {
                    registerPointerDereference(arg);
                } else if (debug_output) {
                    errs() << "Argument ";
                    arg->print(errs());
                    errs() << " for ";
                    call->print(errs());
                    errs() << " does not need authentication\n";
                }

                //                Value *def = getDef(arg.get());
                //                if (isa<AllocaInst>(def)) {
                //                    if (!functionIsAnalysisCandidate(call->getCalledFunction())) {
                //                        if (debug_output) {
                //                            errs() << "Function called by ";
                //                            call->print(errs());
                //                            errs() << " is not an analysis candidate\n";
                //                        }
                //                        continue;
                //                    }
                //                    if (!argNeedsAuthentication(arg)) {
                //                        if (debug_output) {
                //                            errs() << "Registering argument " << arg.getOperandNo()
                //                                   << " (";
                //                            arg->print(errs());
                //                            errs() << " ) for call ";
                //                            call->print(errs());
                //                            errs() << "\n";
                //                        }
                //                        stackPtrsPassedToFuncs[call].insert(arg.get());
                //                    } else {
                //                        if (debug_output) {
                //                            errs() << "Argument ";
                //                            arg->print(errs());
                //                            errs() << " for call ";
                //                            call->print(errs());
                //                            errs() << " does not need signing\n";
                //                        }
                //                    }
                //                }
            }
        } else if (!callIsSafeTransition(call)) {
            for (auto &arg : call->args()) {
                Value *def = getDef(arg.get(), false, debug_output);
                if (GlobalValue *glob = dyn_cast<GlobalValue>(def)) {
                    if (globalShouldBeTransferred(arg)) {
                        if (debug_output) {
                            errs() << "Global " << glob->getName()
                                   << " used by ";
                            call->print(errs());
                            errs() << "\n";
                        }
                        globalArgumentUses[glob].insert(call);
                    } else if (debug_output) {
                        errs() << "Global " << glob->getName()
                               << " should not be transferred to ";
                        call->print(errs());
                        errs() << "\n";
                    }
                } else if (PHINode *phiNode = dyn_cast<PHINode>(def)) {
                    for (auto &val : phiNode->incoming_values()) {
                        Value *valDef = getDef(val.get(), false, debug_output);
                        if (GlobalValue *glob = dyn_cast<GlobalValue>(
                                    valDef)) {
                            if (globalShouldBeTransferred(val)) {
                                if (debug_output) {
                                    errs() << "Global " << glob->getName()
                                           << " used by ";
                                    call->print(errs());
                                    errs() << "\n";
                                }
                                globalArgumentUses[glob].insert(call);
                            } else if (debug_output) {
                                errs() << "Global " << glob->getName()
                                       << " should not be transferred to ";
                                call->print(errs());
                                errs() << "\n";
                            }
                        }
                    }
                } else if (isa<AllocaInst>(def)) {
                    if (!functionIsAnalysisCandidate(
                                call->getCalledFunction())) {
                        if (debug_output) {
                            errs() << "Function called by ";
                            call->print(errs());
                            errs() << " is not an analysis candidate\n";
                        }
                        continue;
                    }
                    if (!argNeedsAuthentication(arg)) {
                        if (debug_output) {
                            errs() << "Registering argument "
                                   << arg.getOperandNo()
                                   << " (";
                            arg->print(errs());
                            errs() << " ) for call ";
                            call->print(errs());
                            errs() << "\n";
                        }
                        stackPtrsPassedToFuncs[call].insert(arg.get());
                    } else {
                        if (debug_output) {
                            errs() << "Argument ";
                            arg->print(errs());
                            errs() << " for call ";
                            call->print(errs());
                            errs() << " does not need signing\n";
                        }
                    }
                }
            }
        } else if (isInHAKCFunctions(call->getCalledFunction()->getName())) {
            Function &F = getFunction();
            M.HAKCFunctions[&F].insert(call);
        }
    }

    void HAKCFunctionAnalysis::addStackTransfers() {
        for (auto it : stackPtrsPassedToFuncs) {
            CallInst *call = it.first;
            for (unsigned i = 0; i < call->getNumArgOperands(); i++) {
                Value *arg = call->getArgOperand(i);
                if (it.second.find(arg) != it.second.end()) {
                    irBuilder.SetInsertPoint(call);
                    arg = addCliqueTransferCall(arg, currentColor);
                    call->setArgOperand(i, arg);
                }
            }
        }
    }

    /**
         * @brief Retrieves the data needed to transfer data to and from cliques, and
         * sets the function section to the correct PMC ELF section
         */
    void HAKCFunctionAnalysis::getFunctionMTEMetadata() {
        Module &M = *getFunction().getParent();

        Instruction *entry = getFunction().getEntryBlock().getFirstNonPHIOrDbgOrLifetime();
        irBuilder.SetInsertPoint(entry);

        ConstantInt *compartment = getElementCompartment(M.getName(), getFunction().getName());
        ConstantInt *color = getElementColor(M.getName(), getFunction().getName());
        ConstantInt *access_token = getElementAccessToken(M.getName(), getFunction().getName());

        // assert(compartment && "Compartment could not be found!");
        // assert(color && "Color could not be found!");
        // assert(access_token && "Token could not be found!");

        this->claqueId = compartment;
        this->currentColor = color;
        this->currentAccessToken = access_token;

        std::string sectionName = getFunction().getSection().str();

        if (sectionName.empty()) {
            sectionName = ".text" + section_prepend.str();
        } else {
            sectionName += section_prepend;
        }
        sectionName += this->compartmentInfo.getColorFromValue(color);

        if (debug_output) {
            errs() << "Changing section to " << sectionName << "\n";
        }
        getFunction().setSection(sectionName);
    }

    HAKCFunctionAnalysis::HAKCFunctionAnalysis(Function &F, bool debug,
                                               HAKCModuleTransformation &ModTransform)
        : CommonHAKCAnalysis(debug, ModTransform.getCompartmentInfo()),
          dominatorTree(F),
          irBuilder(&F.getEntryBlock()),
          claqueId(nullptr),
          currentColor(nullptr),
          currentAccessToken(nullptr),
          pointersAlreadyAuthenticated(
                  ModTransform.getAuthenticatedPointersIn(&F)),
          M(ModTransform),
          addedDataCheckCount(0),
          addedCodeCheckCount(0),
          addedCliqueTransferCount(0),
          addedClaqueTransferCount(0) {
        for (auto it = inst_begin(F); it != inst_end(F); ++it) {
            Instruction *inst = &*it;
            handleInstruction(inst);
        }
    }

    bool HAKCFunctionAnalysis::modifiedFunction() {
        return !signedPtrsUses.empty() || !indirectCalls.empty() ||
               !globalArgumentUses.empty() || !stackPtrsPassedToFuncs.empty();
    }

    void HAKCFunctionAnalysis::removeSignatures() {
        if (debug_output) {
            errs() << "Pointers needing safe versions:\n";
            for (auto &it : signedPtrsUses) {
                it.first->print(errs());
                //                if (PointerType *pt = dyn_cast<PointerType>(
                //                            it.first->getType()->getPointerElementType())) {
                //                    errs() << ": " << pt->getAddressSpace();
                //                }
                for (auto &i : it.second) {
                    errs() << "\n\t";
                    i->print(errs());
                }
                errs() << "\n+++\n";
            }
            errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
        }

        if (modifiedFunction()) {
            if (debug_output) {
                errs() << "---- createAllAuthenticatedPointers ----\n";
            }
            createAllAuthenticatedPointers();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
                errs() << "----- transformPointerDereferences ------\n";
            }
            transformPointerDereferences();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
                errs() << "-------- addAllIndirectTransfers --------\n";
            }
            addAllIndirectTransfers();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
            }

            if (debug_output) {
                getFunction().print(errs());
            }
        }
    }

    void HAKCFunctionAnalysis::addCompartmentalization() {
        //        if (isOutsideTransferFunc(&getFunction())) {
        //            removeSignatures();
        //            return;
        //        }
        assert(!isOutsideTransferFunc(&getFunction()));

        if (debug_output) {
            errs() << "Pointers needing authentication checks:\n";
            for (auto &it : signedPtrsUses) {
                it.first->print(errs());
                //                if (PointerType *pt = dyn_cast<PointerType>(
                //                            it.first->getType()->getPointerElementType())) {
                //                    errs() << ": " << pt->getAddressSpace();
                //                }
                for (auto &i : it.second) {
                    errs() << "\n\t";
                    i->print(errs());
                }
                errs() << "\n+++\n";
            }
        }

        if (modifiedFunction()) {
            getFunctionMTEMetadata();
            if (debug_output) {
                errs() << "---- createAllAuthenticatedPointers ----\n";
            }
            createAllAuthenticatedPointers();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
                errs() << "----- transformPointerDereferences ------\n";
            }
            transformPointerDereferences();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
                errs() << "-------- addAllIndirectTransfers --------\n";
            }
            addAllIndirectTransfers();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
                errs() << "--------- addAllGlobalTransfers ---------\n";
            }
            addAllGlobalTransfers();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
                errs() << "----------- addStackTransfers -----------\n";
            }
            addStackTransfers();
            if (debug_output) {
                errs() << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
            }

            if (debug_output) {
                getFunction().print(errs());
            }
        }
    }

}// namespace hakc
