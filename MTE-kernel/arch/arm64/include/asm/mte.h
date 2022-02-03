/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 ARM Ltd.
 */
#ifndef __ASM_MTE_H
#define __ASM_MTE_H

#include <asm/mte-def.h>

#ifndef __ASSEMBLY__

#include <linux/page-flags.h>
#include <linux/types.h>

#include <asm/pgtable-types.h>

extern u64 gcr_kernel_excl;

void mte_clear_page_tags(void *addr);
unsigned long mte_copy_tags_from_user(void *to, const void __user *from,
				      unsigned long n);
unsigned long mte_copy_tags_to_user(void __user *to, void *from,
				    unsigned long n);
int mte_save_tags(struct page *page);
void mte_save_page_tags(const void *page_addr, void *tag_storage);
bool mte_restore_tags(swp_entry_t entry, struct page *page);
void mte_restore_page_tags(void *page_addr, const void *tag_storage);
void mte_invalidate_tags(int type, pgoff_t offset);
void mte_invalidate_tags_area(int type);
void *mte_allocate_tag_storage(void);
void mte_free_tag_storage(char *storage);

#ifdef CONFIG_ARM64_MTE

/* track which pages have valid allocation tags */
#define PG_mte_tagged	PG_arch_2

void mte_sync_tags(pte_t *ptep, pte_t pte);
void mte_copy_page_tags(void *kto, const void *kfrom);
void flush_mte_state(void);
void mte_thread_switch(struct task_struct *next);
void mte_suspend_exit(void);
long set_mte_ctrl(struct task_struct *task, unsigned long arg);
long get_mte_ctrl(struct task_struct *task);
int mte_ptrace_copy_tags(struct task_struct *child, long request,
			 unsigned long addr, unsigned long data);

#define MTE_DISABLED (__is_defined(CONFIG_PAC_MTE_EVAL_CODEGEN) && \
			!IS_ENABLED(CONFIG_PAC_MTE_EVAL_ENABLE_MTE))

static inline void mte_assign_mem_tag_range(void *addr, size_t size)
{
#if MTE_DISABLED
	return;
#else
	u64 _addr = (u64)addr;
	u64 _end = _addr + size;

	/*
	 * This function must be invoked from an MTE enabled context.
	 *
	 * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
	 * size must be non-zero and MTE_GRANULE_SIZE aligned.
	 */
	do {
		/*
		 * 'asm volatile' is required to prevent the compiler to move
		 * the statement outside of the loop.
		 */
		#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_CODEGEN)
		#if !IS_ENABLED(CONFIG_PAC_MTE_MTE_MEMORY_BARRIER)
		asm volatile(__MTE_PREAMBLE
			     "ldr x16, =tag_clobber_memory\n\t"
			     "mov x17, %0\n\t"
			     "lsr x17, x17, #49\n\t"
			     "str %0, [x16]\n\t"
			     :
			     : "r" (_addr)
			     : "memory");
		#else
		asm volatile(__MTE_PREAMBLE
			     "ldr x16, [%0]\n\t"
			     "mov x17, %0\n\t"
			     "lsr x17, x17, #49\n\t"
			     "dmb ishld\n\t"
			     "str x16, [%0]\n\t"
			     :
			     : "r" (_addr)
			     : "memory");
		#endif
		#else
		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
			     :
			     : "r" (_addr)
			     : "memory");
		#endif

		_addr += MTE_GRANULE_SIZE;
	} while (_addr < _end);
#endif
}

#define mte_get_ptr_tag(ptr)	((u8)(((u64)(ptr)) >> MTE_TAG_SHIFT))
u8 mte_get_mem_tag(void *addr);
u8 mte_get_random_tag(void);
void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);

void mte_init_tags(u64 max_tag);

#else /* CONFIG_ARM64_MTE */

/* unused if !CONFIG_ARM64_MTE, silence the compiler */
#define PG_mte_tagged	0

static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
{
}
static inline void mte_copy_page_tags(void *kto, const void *kfrom)
{
}
static inline void flush_mte_state(void)
{
}
static inline void mte_thread_switch(struct task_struct *next)
{
}
static inline void mte_suspend_exit(void)
{
}
static inline long set_mte_ctrl(struct task_struct *task, unsigned long arg)
{
	return 0;
}
static inline long get_mte_ctrl(struct task_struct *task)
{
	return 0;
}
static inline int mte_ptrace_copy_tags(struct task_struct *child,
				       long request, unsigned long addr,
				       unsigned long data)
{
	return -EIO;
}

static inline void mte_assign_mem_tag_range(void *addr, size_t size)
{
}

#define mte_get_ptr_tag(ptr)	0xFF
static inline u8 mte_get_mem_tag(void *addr)
{
	return 0xFF;
}
static inline u8 mte_get_random_tag(void)
{
	return 0xFF;
}
static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
{
	return addr;
}

static inline void mte_init_tags(u64 max_tag)
{
}

#endif /* CONFIG_ARM64_MTE */

#endif /* __ASSEMBLY__ */
#endif /* __ASM_MTE_H  */
