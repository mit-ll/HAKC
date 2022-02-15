/**
 * @brief HAKC Analysis and Transformation pass
 * @file PMCPass.cpp
 */

#include "PMCPass.h"

using namespace llvm;

namespace {
    /**
     * @brief Core kernel functions that are called directly. Transfers to
     * these functions
     * are not recolored, and the authenticated pointer is passed when invoked.
     */
    const std::set<StringRef> safe_transition_functions = {
            "mod_delayed_work",
            "kasan_check_write",
            "arch_static_branch_jump",
            "arch_static_branch",
            //            "static_branch_TTWU_QUEUE",
            //            "static_branch_WARN_DOUBLE_CLOCK",
            //            "static_branch_HRTICK",
            "kmalloc",
            "bitmap_set",
            "__clear_bit",
            "atomic_set",
            "bitmap_clear",
            "static_key_false",
            "static_key_true",
            "__percpu_counter_init",
            "init_timer_key",
            "inet_peer_base_init",
            "spinlock_check",
            "_raw_spin_lock",
            "_raw_spin_unlock",
            "register_net_sysctl",
            "__nlmsg_put",
            "rhashtable_init",
            //            "nla_put",
            //            "sock_init_data",
            //            "rtnl_notify",
            "neigh_parms_alloc",
            "__preempt_count_add",
            //            "nla_data",
            "proc_create_single_data",
            "write_lock_bh",
            "_raw_write_lock_bh",
            "write_unlock_bh",
            "_raw_write_unlock_bh",
            //            "neigh_sysctl_register",
            "snprintf",
            //            "dev_get_by_index",
            //            "fib_nh_common_init",
            "_raw_spin_lock_bh",
            "_raw_spin_unlock_bh",
            "spin_lock_bh",
            "spin_unlock_bh",
            //            "call_fib_notifiers",
            //            "fib_nexthop_info",
            //            "dev_get_flags",
            "strlen",
            "strchr",
            //            "dev_get_iflink",
            //            "dev_mc_add",
            //            "sock_alloc_send_skb",
            //            "dst_alloc",
            //            "sk_mc_loop",
            //            "__neigh_create",
            //            "fqdir_init",
            //            "neigh_resolve_output",
            //            "skb_set_owner_w",
            //            "dev_queue_xmit",
            //            "__skb_checksum_complete",
            //            "neigh_update",
            //            "kfree_skb",
            //            "call_rcu",
            "proc_dointvec",
            //            "sk_alloc",
            //            "udp_lib_get_port",
            //            "tcp_init_sock",
            //            "udp_cmsg_send",
            //            "dev_mc_del",
            //            "sk_dst_check",
            //            "udp_lib_rehash",
            //            "sk_setup_caps",
            //            "skb_clone",
            //            "sk_filter_trim_cap",
            //            "skb_dst_copy",
            //            "skb_pull_rcsum",
            //            "__udp_enqueue_schedule_skb",
            //            "__skb_recv_udp",
            "_copy_to_iter",
            //            "put_cmsg",
            //            "skb_consume_udp",
            "atomic_notifier_chain_register",
            "instrument_atomic_write",
            //            "hlist_add_head_rcu",
            "spin_lock",
            "spin_unlock",
            "list_add_rcuhlist_empty",
            //            "dev_add_offload",
            "kmemdup",
            "rtnl_register_module",
            "rtnl_af_register",
            "rtnl_af_unregister",
            "__do_once_start",
            "__do_once_done",
            "get_random_bytes",
            "proto_register",
            "proto_unregister",
            //            "__list_add_valid",
            //            "sock_register",
            "register_pernet_subsys",
            "unregister_pernet_subsys",
            "find_next_bit",
            "cpumask_next",
            "proc_create_net_data",
            "mod_delayed_work_on",
            //            "neigh_table_init",
            //            "fib_notifier_ops_register",
            "register_netdevice_notifier",
            "unregister_netdevice_notifier",
            "proc_create_net_single",
            "proc_mkdir",
            "snprintf",
            "kmem_cache_create",
            "alloc_workqueue",
            "__warn_printk",
            //            "dev_hold",
            //            "genl_register_family",
            "system_uses_lse_atomics",
            "__do_once_done",
            "__do_once_start",
            "__memcpy",
            "memcpy",
            "__pi_memcmp",
            "memcmp",
            "__pi_strcmp",
            "strcmp",
            "__kern_my_cpu_offset",
            "__preempt_count_dec_and_test",
            "__percpu_add_case_32",
            "test_bit",
            "cancel_delayed_work",
            //            "inet_frags_init",
            //            "sock_prot_inuse_add",
            //            "dev_add_pack",
            //            "net_generic",
            "neigh_parms_release",
            "preempt_count",
            //            "write_pnet",
            //            "read_pnet",
            "rhltable_init",
            "queued_spin_lock_slowpath",
            "crypto_alloc_shash",
            "memchr_inv",
            "inet_ctl_sock_create",
            "fib_rules_register",
            "kmem_cache_destroy",
            "prandom_u32_state",
            "percpu_counter_add_batch",
            "_mix_pool_bytes",
            "add_device_randomness",
    };

    const StringRef data_check_name = "check_hakc_data_access";
    const StringRef code_check_name = "check_hakc_code_access";
    const StringRef transfer_name = "hakc_transfer_data_to_target";
    const StringRef get_color_name = "get_hakc_address_color";
    const StringRef claque_transfer_name = "hakc_transfer_to_clique";
    const StringRef get_safe_ptr_name = "hakc_safe_ptr";
    const StringRef sign_ptr_with_color_name = "hakc_sign_pointer_with_color";
    const StringRef sign_ptr_name = "hakc_sign_pointer";
    const StringRef per_cpu_transfer_name = "hakc_transfer_percpu_to_clique";

    const StringRef claque_id_name = "__claque_id";
    const StringRef color_name = "__color";
    const StringRef access_token_name = "__acl_tok";
    const StringRef exit_token_name = "__valid_targets";

    const StringRef outside_transfer_prefix = "HAKC_TRANSFER_";

    /**
     * @brief The set of files to run our analysis on
     */
    const std::set<StringRef> source_files_to_instrument = {
            "../net/",
            "../fs/proc/proc_sysctl.c",
            "../lib/list_debug.c",
            "../lib/nlattr.c",
            "../lib/rhashtable.c",
            "../lib/string.c",
            "../lib/kobject_uevent.c",
            "../fs/proc/generic.c",
            "../kernel/",
            "../security/commoncap.c",
            "../drivers/net",
            "../lib/percpu_counter.c",
            "../lib/vsprintf.c",
    };

    /**
     * @brief The set of files to NOT run our analysis on
     */
    const std::set<StringRef> source_files_to_skip = {
            "../lib/idr.c",
            "../lib/xarray.c",
    };

    /**
     * @brief LLVM intrinsics that should use unsigned pointers
     */
    const std::set<Intrinsic::ID> intrinsics_needing_authenticated_args = {
            Intrinsic::IndependentIntrinsics::memcpy,
            Intrinsic::IndependentIntrinsics::memmove,
            Intrinsic::IndependentIntrinsics::memset,
    };

    /**
     * @brief LLVM intrinsics to skip analysis of
     */
    const std::set<Intrinsic::ID> intrinsics_to_skip = {
            Intrinsic::IndependentIntrinsics::dbg_declare,
            Intrinsic::IndependentIntrinsics::dbg_addr,
            Intrinsic::IndependentIntrinsics::dbg_label,
            Intrinsic::IndependentIntrinsics::dbg_value,
            Intrinsic::IndependentIntrinsics::lifetime_start,
            Intrinsic::IndependentIntrinsics::lifetime_end,
            Intrinsic::IndependentIntrinsics::read_register,
    };

    /**
     * @brief ELF sections to skip when trying to find the color
     */
    const std::set<StringRef> sections_to_skip = {
            ".modinfo"};

    /**
     * @brief The names of kernel functions that allocate heap data.  These
     * are used to ensure the developer has added a transfer whenever these
     * are called.
     */
    const std::set<StringRef> kernel_allocation_funcs = {
            "kmalloc",
            "kzalloc",
            "neigh_parms_alloc",
            "nlmsg_new",
            "kmemdup",
            "alloc_percpu",
            "__alloc_percpu",
            "alloc_percpu_gfp",
            "__alloc_percpu_gfp",
            "kmalloc_array",
            "kcalloc",
            "genlmsg_new",
            "sk_alloc",
            "kmem_cache_zalloc",
            "nla_memdup",
            "kzalloc_node",
            "fib_rules_register",
    };

    /**
     * @brief The names of HAKC related operations
     */
    const std::set<StringRef> hakc_functions = {
            data_check_name,
            code_check_name,
            transfer_name,
            get_color_name,
            claque_transfer_name,
            get_safe_ptr_name,
            sign_ptr_with_color_name,
            sign_ptr_name,
    };

    /**
     * @brief The function names used for HAKC transfers
     */
    const std::set<StringRef> hakc_transfer_funcs = {
            transfer_name,
            claque_transfer_name,
            per_cpu_transfer_name,
            "hakc_transfer_sock",
            "hakc_transfer_net",
            "hakc_transfer_socket",
            "hakc_record_common",
            "hakc_transfer_to_destination",
            "hakc_restore_original",
            "hakc_restore_net",
            "hakc_restore_socket",
            "hakc_restore_sock",
    };

    /**
     * @brief The set of functions that should NOT be analyzed for caller
     * authenticated pointer input arguments
     */
    const std::set<StringRef> optimization_deny_list = {
            "inet6_sk_generic"};

    const std::set<StringRef> functions_to_add_transfers = {

    };

    const StringRef section_prepend = ".hakc.";

    /**
     * @brief Finds the functions to instrument, and, for each function,
     * performs an analysis that attempts to determine which pointer input
     * arguments are checked by all callers of said function. Those pointers
     * then do not need to be checked.
     *
     * @param Module
     */
    HAKCModuleTransformation::HAKCModuleTransformation(Module &Module)
            : CommonHAKCAnalysis(false), M(Module),
              compartmentalized(isModuleCompartmentalized(Module)),
              moduleModified(false),
              breakOnMissingTransfer(true),
              debugName("fib6_nh_release"), totalDataChecks(0),
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
                if(debug_output) {
                    errs() << "origInSet:\n";
                    for(auto *v : origInSet) {
                        errs() << "\t";
                        v->print(errs());
                        errs() << "\n";
                    }
                    errs() << "currInSet:\n";
                    for(auto *v : currInSet) {
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
     * @brief Collective analysis functionality
     * @param debug
     */
    CommonHAKCAnalysis::CommonHAKCAnalysis(bool debug) : debug_output(debug) {}

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

    /**
         * @brief Computes the definition chain from an arbitrary value to its source definition
         * @param v
         * @return The chain of definitions starting from v to the source definition
         */
    std::vector<Value *>
    CommonHAKCAnalysis::findDefChain(Value *v, bool followLoad) {
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
                if (getDef(binOp->getOperand(0))->getType()->isPointerTy()) {
                    if (debug_output) {
                        errs() << "Adding arg 0 of ";
                        binOp->print(errs());
                        errs() << "\n";
                    }
                    working_list.insert(binOp->getOperand(0));
                } else if (getDef(
                        binOp->getOperand(1))->getType()->isPointerTy()) {
                    if (debug_output) {
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
        if (Argument *arg = dyn_cast<Argument>(getDef(v))) {
            return arg->getArgNo();
        }
        return -1;
    }

    /**
         * @brief Returns the source definition of a Value
         * @param V
         * @return
         */
    Value *CommonHAKCAnalysis::getDef(Value *V, bool followLoad) {
        std::vector<Value *> def_chain = findDefChain(V, followLoad);
        assert(!def_chain.empty());
        return def_chain.back();
    }

    /**
     * @brief Returns the color value of @param symbolName, or nullptr
     * @param M
     * @param symbolName
     * @return
     */
    GlobalVariable *
    CommonHAKCAnalysis::getSymbolColor(Module &M, StringRef symbolName) {
        std::string colorName = color_name.str();
        colorName += "_";
        colorName += symbolName.str();

        GlobalVariable *symbolColorVar = M.getGlobalVariable(colorName,
                                                             true);
        return symbolColorVar;
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
        return (hakc_functions.find(F->getName()) != hakc_functions.end()) ||
               (hakc_transfer_funcs.find(F->getName()) !=
                hakc_transfer_funcs.end());
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
            bool arg0ReadsRegister = isRegisterRead(getDef(add->getOperand(0)));
            bool arg1ReadsRegister = isRegisterRead(getDef(add->getOperand(1)));
            bool arg0ReadsPercpuOffset = false;
            if (LoadInst *load = dyn_cast<LoadInst>(
                    getDef(add->getOperand(0)))) {
                if (GlobalValue *gv = dyn_cast<GlobalValue>(
                        getDef(load->getPointerOperand()))) {
                    arg0ReadsPercpuOffset = (gv->getName() ==
                                             "__per_cpu_offset");
                }
            }
            bool arg0IsPointer = getDef(
                    add->getOperand(0))->getType()->isPointerTy();
            bool arg1IsPointer = getDef(
                    add->getOperand(1))->getType()->isPointerTy();
            bool arg1ReadsPercpuOffset = false;
            if (LoadInst *load = dyn_cast<LoadInst>(
                    getDef(add->getOperand(1)))) {
                if (GlobalValue *gv = dyn_cast<GlobalValue>(
                        getDef(load->getPointerOperand()))) {
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
        if(F->isIntrinsic()) {
            return false;
        }
        return true;
    }

    /**
        * @brief Moves all unannotated global values to the default PMC data section
        * @param M
        */
    void HAKCModuleTransformation::moveGlobalsToPMCSection() {
        GlobalVariable *color = M.getNamedGlobal(color_name);
        assert(color && "Color is missing");
        const StringRef sectionName = color->getSection();
        for (auto &global : M.globals()) {
            /* The global variable has already been placed */
            if (global.getSection().contains(".hakc.")) {
                continue;
            } else if (global.hasExternalLinkage()) {
                continue;
            } else if (global.hasGlobalUnnamedAddr()) {
                continue;
            } else if (global.getSection() == ".discard.addressable") {
                continue;
            }

            auto *symbolColorVar = getSymbolColor(M, global.getName());
            if (!symbolColorVar &&
                sections_to_skip.find(global.getSection()) ==
                sections_to_skip.end()) {
                std::string finalName = global.getSection().str();
                if (!finalName.empty()) {
                    finalName += ".";
                }
                finalName += sectionName.str();
                if (debug_output) {
                    errs() << "Changing section of global ";
                    global.print(errs());
                    errs() << " to section " << finalName << "\n";
                }

                global.setSection(finalName);
                moduleModified = true;
            }
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
                    } else if (hakc_transfer_funcs.find(
                            call->getCalledFunction()->getName()) !=
                               hakc_transfer_funcs.end()) {
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
                Value *def = getDef(transferCall->getArgOperand(0));
                if (def == allocCall) {
                    transferFound = true;
                    break;
                } else if (LoadInst *load = dyn_cast<LoadInst>(def)) {
                    for (auto *user : load->getPointerOperand()->users()) {
                        if (StoreInst *store = dyn_cast<StoreInst>(user)) {
                            if (getDef(store->getValueOperand()) == allocCall) {
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
        for (const auto &global : M.globals()) {
            if (global.getName().contains("claque_id")) {
                return true;
            }
        }
        return false;
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

        needsAnalysis = (                  /*!isSafeTransitionFunction(F) &&*/
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
            if(debug_output) {
                errs() << M.getName() << " is not compartmentalized\n";
            }
            return authenticatedPointers;
        }

        if (!F->hasInternalLinkage() ||
            optimization_deny_list.find(F->getName()) != optimization_deny_list.end()) {
            if(debug_output) {
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
                        if(debug_output) {
                            errs() << "Pointer ";
                            ptr->print(errs());
                            errs() << " (";
                            getDef(ptr)->print(errs());
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
                                        if (getDef(ptr) == getDef(use.get())) {
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
            if(debug_output) {
                errs() << "authenticatedPointers is empty\n";
            }
        }

        return authenticatedPointers;
    }

    bool HAKCModuleTransformation::pointersMatch(Value *aPtr, Function *aFunc,
                                                 Value *bPtr,
                                                 Function *bFunc, bool print) {
        Value *aDef = getDef(aPtr);
        Value *bDef = getDef(bPtr);

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
                        getDef(call->getArgOperand(aArg->getArgNo())) ==
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
                        getDef(call->getArgOperand(bArg->getArgNo())) ==
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

    void HAKCModuleTransformation::performTransformations() {
        if (isCompartmentalized()) {
            compartmentalizeModule();
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
    }

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

        bool isData = !valueIsReadonlyPtr(getDef(operand));

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

        bool isData = !valueIsReadonlyPtr(getDef(operand));

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

        bool isData = !valueIsReadonlyPtr(getDef(operand));

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
                operand->getType()->getPointerElementType());
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

    /**
         * @brief Returns the size of a type, or the result of sizeof(). This is needed
         * because LLVM Types can be unsized or forward declared, and will throw an exception
         * when getTypeAllocSize is called.
         * @param type The Type that needs a size
         * @return The size of the object
         */
    Value *HAKCFunctionAnalysis::createSizeOf(Type *type) {
        if (type->isSized()) {
            DataLayout layout(getFunction().getParent());
            return irBuilder.getInt64(layout.getTypeAllocSize(type));
        } else if (type->isEmptyTy() || type->isFunctionTy()) {
            /* Opaque (aka forward declared) structs, so assume tag granularity */
            return irBuilder.getInt64(16);
        }
        Value *nullVal = ConstantPointerNull::getNullValue(type);
        Value *idxVal = ConstantInt::get(irBuilder.getInt32Ty(), 1);
        Value *size = irBuilder.CreateGEP(nullVal, idxVal);
        return irBuilder.CreatePtrToInt(size, irBuilder.getInt64Ty());
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

        bool isCode = valueIsReadonlyPtr(getDef(value));

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
                value->getType()->getPointerElementType());
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

    /**
         * @brief Saves the color of a pointer prior to an indirect call
         * @param operand The operand of an indirect function call
         * @return A call to get_color_call or nullptr if the argument is not a pointer
         */
    CallInst *HAKCFunctionAnalysis::saveColor(Value *operand) {
        if (!operand->getType()->isPointerTy() ||
            isa<ConstantPointerNull>(operand)) {
            return nullptr;
        }
        FunctionType *ftype = FunctionType::get(irBuilder.getInt32Ty(),
                                                {irBuilder.getInt8PtrTy()},
                                                false);
        FunctionCallee save_color_call = getFunction().getParent()->getOrInsertFunction(
                get_color_name, ftype);
        assert(save_color_call && "Could not get save color call");

        return irBuilder.CreateCall(save_color_call,
                                    {irBuilder.CreateBitCast(operand,
                                                             ftype->getParamType(
                                                                     0))});
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

        GlobalVariable *exitTokens = F.getParent()->getNamedGlobal(
                exit_token_name);
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

            CallInst *originalColor = saveColor(operand.get());
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
                    Value *def = getDef(operand.get());
                    if (def != it.first) {
                        continue;
                    }

                    auto defChain = findDefChain(operand.get());
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
                    Value *def = getDef(operand.get());
                    if (def != it.first) {
                        continue;
                    }

                    auto defChain = findDefChain(operand.get());

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
                        (it.first == getDef(operand.get()) ||
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
                        return !isa<AllocaInst>(getDef(arg.get()));
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
            Value *def = getDef(val.get(), true);
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
                        Value *def = getDef(arg.get());
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
                    Value *def = getDef(store->getValueOperand());
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
                } else if (LoadInst *load = dyn_cast<LoadInst>(user)) {
                    //                    assert(getDef(load->getPointerOperand()) == it.first && "Unexpected global use");
                    //                    Use &arg = load->getOperandUse(0);
                    //                    addGlobalClonesAndTransfer(it.first, arg, signed_clones, I);
                    //                    if (!signed_clones[it.first]) {
                    //                        errs() << "Could not create transfer for ";
                    //                        it.first->print(errs());
                    //                        errs() << " in function "
                    //                               << getFunction().getName() << "\n";
                    //                    }
                    //                    assert(signed_clones[it.first]);
                } else if (PHINode *phi = dyn_cast<PHINode>(user)) {
                    bool found = false;
                    for (unsigned i = 0; i < phi->getNumIncomingValues(); i++) {
                        if (getDef(phi->getIncomingValue(i)) == it.first) {
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
        Value *def = getDef(v);
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
                Value *def = getDef(val.get());
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
        if(SelectInst *select = dyn_cast<SelectInst>(v)) {
            if(debug_output) {
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
                    getDef(ptr)->print(errs());
                    errs() << " against ";
                    getDef(authPtr)->print(errs());
                    errs() << "\n";
                }
                if (getDef(authPtr) == getDef(ptr)) {
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
        Value *definition = getDef(use.get());
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
        auto *def = getDef(load->getPointerOperand());
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
                        getDef(phi->getIncomingValue(i)))) {
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
        auto *def = getDef(store->getPointerOperand());
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
        Value *def = getDef(v);
        for (auto *ptr : pointersAlreadyAuthenticated) {
            if (getDef(ptr) == def) {
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
                    !isa<GlobalValue>(getDef(compare->getOperand(0)));
            bool arg1NeedsAuth =
                    argNeedsAuthentication(compare->getOperandUse(1)) &&
                    !isa<GlobalValue>(getDef(compare->getOperand(1)));
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
                getDef(globalValueArg.get()))) {
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
                                                call->getCalledFunction()).empty()) ||
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
                Value *def = getDef(arg.get());
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
                        Value *valDef = getDef(val.get());
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
        GlobalVariable *claqueId, *color, *accessToken;
        GlobalVariable *functionColor = getSymbolColor(M,
                                                       getFunction().getName());

        std::string claqueIdName, colorName, aclName;
        claqueIdName = claque_id_name.str();
        colorName = color_name.str();
        aclName = access_token_name.str();

        if (functionColor) {
            StringRef funcName = getFunction().getName();
            std::string addend = "_";
            addend += funcName.str();

            claqueIdName += addend;
            colorName += addend;
            aclName += addend;
        }

        claqueId = M.getNamedGlobal(claqueIdName);
        assert(claqueId && "Claque ID could not be found!");

        color = M.getNamedGlobal(colorName);
        assert(color && "Color could not be found!");

        accessToken = M.getNamedGlobal(aclName);
        assert(accessToken && "Access Token could not be found!");

        Instruction *entry = getFunction().getEntryBlock().getFirstNonPHIOrDbgOrLifetime();
        irBuilder.SetInsertPoint(entry);
        this->claqueId = irBuilder.CreateLoad(claqueId);
        this->currentColor = irBuilder.CreateLoad(color);
        this->currentAccessToken = irBuilder.CreateLoad(accessToken);

        StringRef colorSectionName;
        if (!functionColor) {
            colorSectionName = color->getSection();
        } else {
            colorSectionName = functionColor->getSection();
        }

        auto split = colorSectionName.split(".data" + section_prepend.str());
        std::string sectionName = getFunction().getSection().str();
        if (sectionName.empty()) {
            sectionName = ".text" + section_prepend.str();
        } else {
            sectionName += section_prepend;
        }
        sectionName += split.second.str();
        if (debug_output) {
            errs() << "Changing section to " << sectionName << "\n";
        }
        getFunction().setSection(sectionName);
    }

    HAKCFunctionAnalysis::HAKCFunctionAnalysis(Function &F, bool debug,
                                               HAKCModuleTransformation &ModTransform)
            : CommonHAKCAnalysis(debug),
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

    struct PMCPass : public ModulePass {
        static char ID;

        PMCPass() : ModulePass(ID) {}

        bool runOnModule(Module &M) override {
            HAKCModuleTransformation transformation(M);
            transformation.performTransformations();
            if (transformation.isCompartmentalized()) {
                errs() << "Total Data Checks: "
                       << transformation.totalDataChecks << "\n"
                       << "Total Code Checks: "
                       << transformation.totalCodeChecks << "\n"
                       << "Total Transfers:   " << transformation.totalTransfers
                       << "\n";
            }
            return transformation.isModuleTransformed();
        }
    };
}// namespace

char PMCPass::ID = 0;

static void registerPMCPass(const llvm::PassManagerBuilder &,
                            llvm::legacy::PassManagerBase &PM) {
    PM.add(new PMCPass());
}

static llvm::RegisterStandardPasses
        RegisterMyPass(llvm::PassManagerBuilder::EP_ScalarOptimizerLate,
                       registerPMCPass);

static RegisterPass<PMCPass>
        X("PMCPass", "PAC-MTE Compartment Pass",
          false,// This pass doesn't modify the CFG => true
          false // This pass is not a pure analysis pass => false
);

