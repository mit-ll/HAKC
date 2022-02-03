//
// Created by derrick on 8/20/21.
//

#ifndef PMC_HAKC_DEFS_H
#define PMC_HAKC_DEFS_H

#include "llvm/IR/Intrinsics.h"

#include <set>
#include <vector>

using namespace llvm;

namespace hakc {
    /**
* @brief LLVM intrinsics that should use unsigned pointers
*/
    const std::set<Intrinsic::ID> intrinsics_needing_authenticated_args = {
            Intrinsic::IndependentIntrinsics::memcpy,
            Intrinsic::IndependentIntrinsics::memmove,
            Intrinsic::IndependentIntrinsics::memset,
            };

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
            "nfnetlink_unicast",
            //            "nla_put",
            "memset",
            "llvm.va_start",
            "llvm.va_end",
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

    //    const StringRef exit_token_name = "__valid_targets";

    const StringRef outside_transfer_prefix = "HAKC_TRANSFER_";

    /**
     * @brief The set of files to run our analysis on
     */
    const std::set<StringRef> source_files_to_instrument = {
            "../net/",
            "../fs/proc/proc_sysctl.c",
            "../fs/exec.c",
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
            ".modinfo",
            ".discard.addressable",
            ".gnu.linkonce.this_module"
            };

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
            "nla_strdup",
            "kvmalloc",
            "kvmalloc_array",
            "kvzalloc",
            };

    /**
     * @brief The names of HAKC related operations
     * Tuple: name, id param position, color param position
     */
    const std::set<std::tuple<StringRef, int, int>> hakc_functions = {
            std::tuple<StringRef, int, int>(data_check_name, -1, -1),
            std::tuple<StringRef, int, int>(code_check_name, -1, -1),
            std::tuple<StringRef, int, int>(transfer_name, -1, -1),
            std::tuple<StringRef, int, int>(get_color_name, -1, -1),
            std::tuple<StringRef, int, int>(claque_transfer_name, 2, 3),
            std::tuple<StringRef, int, int>(get_safe_ptr_name, -1, -1),
            std::tuple<StringRef, int, int>(sign_ptr_with_color_name, 1, -1),
            std::tuple<StringRef, int, int>(sign_ptr_name, 1, 2),
            std::tuple<StringRef, int, int>(per_cpu_transfer_name, 2, 3)
            };

    /**
     * @brief The function names used for HAKC transfers
     * Tuple: name, id param position, color param position
     */
     typedef std::tuple<StringRef, int, int> hakc_transfer_def_t;
    const std::set<hakc_transfer_def_t> hakc_transfer_funcs = {
             hakc_transfer_def_t(transfer_name, -1, -1),
             hakc_transfer_def_t(claque_transfer_name, 2, 3),
             hakc_transfer_def_t(per_cpu_transfer_name, 2, 3),
             hakc_transfer_def_t(sign_ptr_with_color_name, 1, -1),
             hakc_transfer_def_t(sign_ptr_name, 1, 2),
             hakc_transfer_def_t("hakc_transfer_skb", 1, 2),
             hakc_transfer_def_t("hakc_transfer_nla", 2, 3),
             hakc_transfer_def_t("hakc_transfer_string", 1, 2),
             hakc_transfer_def_t("hakc_record_common", -1, -1),
             hakc_transfer_def_t("hakc_transfer_to_destination", -1, -1),
             hakc_transfer_def_t("hakc_restore_original", -1, -1),
             hakc_transfer_def_t("hakc_transfer_sock", 0, -1)
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
    const StringRef yaml_file = "hakc-compartments.yml";

    typedef enum {
        SILVER_CLIQUE = 0xF0,
        GREEN_CLIQUE,
        RED_CLIQUE,
        ORANGE_CLIQUE,
        YELLOW_CLIQUE,
        PURPLE_CLIQUE,
        BLUE_CLIQUE,
        GREY_CLIQUE,
        PINK_CLIQUE,
        BROWN_CLIQUE,
        WHITE_CLIQUE,
        BLACK_CLIQUE,
        TEAL_CLIQUE,
        VIOLET_CLIQUE,
        CRIMSON_CLIQUE,
        GOLD_CLIQUE,
        NO_CLIQUE
    } func_color_t;

    // Structs for the yaml template
    struct YamlClique {
        func_color_t        color;
        uint64_t            access_token;
    };

    struct YamlCompartment {
        uint64_t                 id;
        uint64_t                 entry_token;
        std::vector<uint64_t>    targets;
        std::vector<YamlClique>  cliques;
    };

    struct YamlSymbol {
        uint64_t        compartment;
        func_color_t    color;
        std::string     name;
    };
    
    struct YamlFile {
        uint64_t                        guid;
        std::string                     name;
        std::vector<YamlSymbol>         symbols;
    };

    struct YamlInformation {
        std::vector<YamlCompartment>  compartments;
        std::vector<YamlFile>  files;
    };
    
    typedef std::vector<YamlInformation> YamlIn;
}

#endif//PMC_HAKC_DEFS_H
