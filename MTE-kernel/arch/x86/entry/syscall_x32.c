// SPDX-License-Identifier: GPL-2.0
/* System call table for x32 ABI. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/moduleparam.h>
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "syscall."
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

/*
 * Reuse the 64-bit entry points for the x32 versions that occupy different
 * slots in the syscall table.
 */
#define __x32_sys_readv		__x64_sys_readv
#define __x32_sys_writev	__x64_sys_writev
#define __x32_sys_getsockopt	__x64_sys_getsockopt
#define __x32_sys_setsockopt	__x64_sys_setsockopt
#define __x32_sys_vmsplice	__x64_sys_vmsplice
#define __x32_sys_process_vm_readv	__x64_sys_process_vm_readv
#define __x32_sys_process_vm_writev	__x64_sys_process_vm_writev

#define __SYSCALL_64(nr, sym)

#define __SYSCALL_X32(nr, sym) extern long __x32_##sym(const struct pt_regs *);
#define __SYSCALL_COMMON(nr, sym) extern long __x64_##sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#undef __SYSCALL_X32
#undef __SYSCALL_COMMON

#define __SYSCALL_X32(nr, sym) [nr] = __x32_##sym,
#define __SYSCALL_COMMON(nr, sym) [nr] = __x64_##sym,

asmlinkage const sys_call_ptr_t x32_sys_call_table[__NR_x32_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_x32_syscall_max] = &__x64_sys_ni_syscall,
#include <asm/syscalls_64.h>
};

/* Maybe enable x32 syscalls */

#if defined(CONFIG_X86_X32_DISABLED)
DEFINE_STATIC_KEY_FALSE(x32_enabled_skey);
#else
DEFINE_STATIC_KEY_TRUE(x32_enabled_skey);
#endif

static int __init x32_param_set(const char *val, const struct kernel_param *p)
{
	bool enabled;
	int ret;

	ret = kstrtobool(val, &enabled);
	if (ret)
		return ret;
	if (IS_ENABLED(CONFIG_X86_X32_DISABLED)) {
		if (enabled) {
			static_key_enable(&x32_enabled_skey.key);
			pr_info("Enabled x32 syscalls\n");
		}
	} else {
		if (!enabled) {
			static_key_disable(&x32_enabled_skey.key);
			pr_info("Disabled x32 syscalls\n");
		}
	}
	return 0;
}

static int x32_param_get(char *buffer, const struct kernel_param *p)
{
	return sprintf(buffer, "%c\n",
		       static_key_enabled(&x32_enabled_skey) ? 'Y' : 'N');
}

static const struct kernel_param_ops x32_param_ops = {
	.set = x32_param_set,
	.get = x32_param_get,
};

arch_param_cb(x32, &x32_param_ops, NULL, 0444);
