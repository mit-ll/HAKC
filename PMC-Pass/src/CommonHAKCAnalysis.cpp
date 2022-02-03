//
// Created by derrick on 8/20/21.
//
#include "HAKCPass.h"

namespace hakc {

    /**
 * @brief Collective analysis functionality
 * @param debug
 */
    CommonHAKCAnalysis::CommonHAKCAnalysis(bool debug, HAKCSystemInformation &compartmentInfo) : debug_output(debug), compartmentInfo(compartmentInfo) {}

    /**
 * @brief Returns true if @param call is an LLVM intrinsic that needs its
 * arguments authenticated
 * @param call
 * @return
 */
    bool CommonHAKCAnalysis::isIntrinsicNeedingAuthentication(CallInst *call) {
        bool result = false;
        if (IntrinsicInst *intrinsic = dyn_cast<IntrinsicInst>(call)) {
            result = (intrinsics_needing_authenticated_args.find(
                              intrinsic->getIntrinsicID()) !=
                      intrinsics_needing_authenticated_args.end());
            if (debug_output) {
                errs() << "Intrinsic (" << intrinsic->getIntrinsicID() << ") ";
                intrinsic->print(errs());
                if (result) {
                    errs() << " is in { ";
                } else {
                    errs() << " is not in { ";
                }
                for (auto id : intrinsics_needing_authenticated_args) {
                    errs() << id << " ";
                }
                errs() << "}\n";
            }
        }
        return result;
    }

    HAKCSystemInformation &CommonHAKCAnalysis::getCompartmentInfo() {
        return compartmentInfo;
    }

    /**
     * @brief Computes the definition chain from an arbitrary value to its source definition
     * @param v
     * @return The chain of definitions starting from v to the source definition
     */
    std::vector<Value *>
    CommonHAKCAnalysis::findDefChain(Value *v, bool followLoad, bool debug) {
        assert(v);
        std::set<Value *> working_list = {v};
        std::vector<Value *> def_chain;
        while (!working_list.empty()) {
            Value *curr = *working_list.begin();
            working_list.erase(curr);
            if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(
                        curr)) {
                working_list.insert(gep->getPointerOperand());
            } else if (BitCastInst *bitcast = dyn_cast<BitCastInst>(curr)) {
                working_list.insert(bitcast->getOperand(0));
            } else if (CallInst *call = dyn_cast<CallInst>(curr)) {
                if (call->getCalledFunction() &&
                    call->getCalledFunction()->getName() ==
                            data_check_name) {
                    working_list.insert(call->getArgOperand(
                            call->getNumArgOperands() - 1));
                    continue;
                }
            } else if (GEPOperator *gep = dyn_cast<GEPOperator>(curr)) {
                working_list.insert(gep->getPointerOperand());
            } else if (BitCastOperator *bitcast = dyn_cast<BitCastOperator>(
                               curr)) {
                working_list.insert(bitcast->getOperand(0));
            } else if (PtrToIntInst *cast = dyn_cast<PtrToIntInst>(curr)) {
                working_list.insert(cast->getPointerOperand());
            } else if (PtrToIntOperator *cast = dyn_cast<PtrToIntOperator>(
                               curr)) {
                working_list.insert(cast->getPointerOperand());
            } else if (followLoad && isa<LoadInst>(curr)) {
                LoadInst *load = dyn_cast<LoadInst>(curr);
                working_list.insert(load->getPointerOperand());
            } else if (IntToPtrInst *bitcast = dyn_cast<IntToPtrInst>(curr)) {
                working_list.insert(bitcast->getOperand(0));
            } else if (SExtInst *sext = dyn_cast<SExtInst>(curr)) {
                working_list.insert(sext->getOperand(0));
            } else if (BinaryOperator *binOp = dyn_cast<BinaryOperator>(curr)) {
                if (getDef(binOp->getOperand(0))->getType()->isPointerTy(), followLoad, debug) {
                    if (debug) {
                        errs() << "Adding arg 0 of ";
                        binOp->print(errs());
                        errs() << "\n";
                    }
                    working_list.insert(binOp->getOperand(0));
                } else if (getDef(
                                   binOp->getOperand(1))
                                   ->getType()
                                   ->isPointerTy(),
                           followLoad, debug) {
                    if (debug) {
                        errs() << "Adding arg 1 of ";
                        binOp->print(errs());
                        errs() << "\n";
                    }
                    working_list.insert(binOp->getOperand(1));
                }
            }
            def_chain.push_back(curr);
        }

        return def_chain;
    }

    /**
 * @brief
 * @param v
 * @return The argument number if @param v is an Argument, or -1 otherwise
 */
    int CommonHAKCAnalysis::getFunctionArgNumber(Value *v) {
        if (Argument *arg = dyn_cast<Argument>(getDef(v, false, debug_output))) {
            return arg->getArgNo();
        }
        return -1;
    }

    /**
     * @brief Returns the source definition of a Value
     * @param V
     * @return
     */
    Value *CommonHAKCAnalysis::getDef(Value *V, bool followLoad, bool debug) {
        std::vector<Value *> def_chain = findDefChain(V, followLoad, debug);
        assert(!def_chain.empty());
        return def_chain.back();
    }

    /**
     * @brief Returns true if the called function is in the list of safe transition calls defined above
     * @param call
     * @return
     */
    bool CommonHAKCAnalysis::callIsSafeTransition(CallInst *call) {
        if (call->getCalledFunction()) {
            return isSafeTransitionFunction(call->getCalledFunction());
        }

        return false;
    }

    /**
 * @brief
 * @param F
 * @return true if #F name is in #hakc_functions or
 * #hakc_transfer_funcs, false otherwise
 * */
    bool CommonHAKCAnalysis::isHAKCFunction(Function *F) {
        return isTransferFunction(F->getName()) || isInHAKCFunctions(F->getName());
    }

    /**
 * @brief
 * @param F
 * @return true if F->getName() is in #safe_transition_functions, false
 * otherwise
 */
    bool CommonHAKCAnalysis::isSafeTransitionFunction(Function *F) {
        return (safe_transition_functions.find(F->getName()) !=
                        safe_transition_functions.end() ||
                kernel_allocation_funcs.find(F->getName()) !=
                        kernel_allocation_funcs.end());
    }


    bool CommonHAKCAnalysis::isOutsideTransferFunc(Function *F) {
        return (F->getName().startswith(outside_transfer_prefix));
    }

    bool CommonHAKCAnalysis::isRegisterRead(Value *v) {
        if (CallInst *call = dyn_cast<CallInst>(v)) {
            return call->isInlineAsm() || (call->getCalledFunction() &&
                                           call->getCalledFunction()->isIntrinsic() &&
                                           call->getCalledFunction()->getIntrinsicID() ==
                                                   Intrinsic::IndependentIntrinsics::read_register);
        }
        return false;
    }

    bool CommonHAKCAnalysis::isPerCPUPointer(Value *v) {
        if (LoadInst *load = dyn_cast<LoadInst>(v)) {
            return isPerCPUPointer(load->getPointerOperand());
        } else if (IntToPtrInst *cast = dyn_cast<IntToPtrInst>(v)) {
            return isPerCPUPointer(cast->getOperand(0));
        } else if (AddOperator *add = dyn_cast<AddOperator>(v)) {
            bool arg0ReadsRegister = isRegisterRead(getDef(add->getOperand(0), false, debug_output));
            bool arg1ReadsRegister = isRegisterRead(getDef(add->getOperand(1), false, debug_output));
            bool arg0ReadsPercpuOffset = false;
            if (LoadInst *load = dyn_cast<LoadInst>(
                        getDef(add->getOperand(0), false, debug_output))) {
                if (GlobalValue *gv = dyn_cast<GlobalValue>(
                            getDef(load->getPointerOperand(), false, debug_output))) {
                    arg0ReadsPercpuOffset = (gv->getName() ==
                                             "__per_cpu_offset");
                }
            }
            bool arg0IsPointer = getDef(
                                         add->getOperand(0), false, debug_output)
                                         ->getType()
                                         ->isPointerTy();
            bool arg1IsPointer = getDef(
                                         add->getOperand(1), false, debug_output)
                                         ->getType()
                                         ->isPointerTy();
            bool arg1ReadsPercpuOffset = false;
            if (LoadInst *load = dyn_cast<LoadInst>(
                        getDef(add->getOperand(1), false, debug_output))) {
                if (GlobalValue *gv = dyn_cast<GlobalValue>(
                            getDef(load->getPointerOperand(), false, debug_output))) {
                    arg1ReadsPercpuOffset = (gv->getName() ==
                                             "__per_cpu_offset");
                }
            }

            if (debug_output) {
                errs() << "Checking if ";
                add->print(errs());
                errs() << " is a per-cpu pointer:\n"
                       << "arg0ReadsRegister: " << arg0ReadsRegister
                       << " arg0ReadsPercpuOffset: " << arg0ReadsPercpuOffset
                       << " arg0IsPointer: " << arg0IsPointer << "\n"
                       << " arg1ReadsRegister: " << arg1ReadsRegister
                       << " arg1ReadsPercpuOffset: " << arg1ReadsPercpuOffset
                       << " arg1IsPointer: " << arg1IsPointer << "\n";
            }
            return (((arg0ReadsRegister || arg0ReadsPercpuOffset) &&
                     !arg1ReadsRegister && !arg1ReadsPercpuOffset &&
                     arg1IsPointer) ||
                    ((arg1ReadsRegister || arg1ReadsPercpuOffset) &&
                     !arg0ReadsRegister && !arg0ReadsPercpuOffset &&
                     arg1IsPointer));
        }

        return false;
    }

    bool CommonHAKCAnalysis::functionIsAnalysisCandidate(Function *F) {
        if (!F) {
            return true;
        }
        if (isSafeTransitionFunction(F)) {
            return false;
        }
        if (isHAKCFunction(F)) {
            return false;
        }
        if (F->getName() == "printk") {
            return false;
        }
        if (isOutsideTransferFunc(F)) {
            return false;
        }
        if (F->isIntrinsic()) {
            return false;
        }
        return true;
    }

    bool CommonHAKCAnalysis::isTransferFunction(StringRef name) {
        for (auto tup : hakc_transfer_funcs) {
            if (std::get<0>(tup).equals(name)) {
                return true;
            }
        }
        return false;
    }

    bool CommonHAKCAnalysis::isValidColor(ConstantInt *symbolColor) {
        return symbolColor && symbolColor->getZExtValue() >= SILVER_CLIQUE &&
               symbolColor->getZExtValue() < NO_CLIQUE;
    }

    bool CommonHAKCAnalysis::isInHAKCFunctions(StringRef name) {
        for (auto tup : hakc_functions) {
            if (std::get<0>(tup).equals(name)) {
                return true;
            }
        }
        return false;
    }

    std::tuple<StringRef, int, int> CommonHAKCAnalysis::getHAKCFunction(StringRef name) {
        for (auto tup : hakc_functions) {
            if (std::get<0>(tup).equals(name) && (std::get<1>(tup) >= 0 || std::get<2>(tup) >= 0)) {
                return tup;
            }
        }

        for (auto tup : hakc_transfer_funcs) {
            if (std::get<0>(tup).equals(name) && (std::get<1>(tup) >= 0 || std::get<2>(tup) >= 0)) {
                return tup;
            }
        }

        return std::tuple<StringRef, int, int>("", -1, -1);
    }

    ConstantInt *CommonHAKCAnalysis::getElementCompartment(StringRef name, StringRef element) {
        return this->compartmentInfo.getElementCompartment(name, element);
    }

    ConstantInt *CommonHAKCAnalysis::getElementColor(StringRef name, StringRef element) {
        return this->compartmentInfo.getElementColor(name, element);
    }

    ConstantInt *CommonHAKCAnalysis::getElementAccessToken(StringRef name, StringRef element) {
        return this->compartmentInfo.getElementAccessToken(name, element);
    }

    /**
    * @brief Returns the size of a type, or the result of sizeof(). This is needed
    * because LLVM Types can be unsized or forward declared, and will throw an exception
    * when getTypeAllocSize is called.
    * @param type The Type that needs a size
    * @return The size of the object
    */
    Value *CommonHAKCAnalysis::createSizeOf(Type *type, IRBuilder<> *irBuilder, Module *M) {
        if (type->isSized()) {
            DataLayout layout(M);
            return irBuilder->getInt64(layout.getTypeAllocSize(type));
        } else if (type->isEmptyTy() || type->isFunctionTy()) {
            /* Opaque (aka forward declared) structs, so assume tag granularity */
            return irBuilder->getInt64(16);
        }
        Value *nullVal = ConstantPointerNull::getNullValue(type);
        Value *idxVal = ConstantInt::get(irBuilder->getInt32Ty(), 1);
        Value *size = irBuilder->CreateGEP(nullVal, idxVal);
        return irBuilder->CreatePtrToInt(size, irBuilder->getInt64Ty());
    }

    /**
    * @brief Saves the color of a pointer prior to an indirect call
    * @param operand The operand of an indirect function call
    * @return A call to get_color_call or nullptr if the argument is not a pointer
    */
    CallInst *CommonHAKCAnalysis::saveColor(Value *operand, IRBuilder<> *irBuilder, Module *M) {
        if (!operand->getType()->isPointerTy() ||
            isa<ConstantPointerNull>(operand)) {
            return nullptr;
        }
        FunctionType *ftype = FunctionType::get(irBuilder->getInt32Ty(),
                                                {irBuilder->getInt8PtrTy()},
                                                false);
        FunctionCallee save_color_call = M->getOrInsertFunction(
                get_color_name, ftype);
        assert(save_color_call && "Could not get save color call");

        return irBuilder->CreateCall(save_color_call,
                                    {irBuilder->CreateBitCast(operand,
                                                             ftype->getParamType(
                                                                     0))});
    }

}// namespace hakc