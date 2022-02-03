/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 ARM Ltd.
 */
#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/mte.h>
#include <asm/page.h>
#include <asm/sysreg.h>

	.arch	armv8.5-a+memtag


/*
 * performance evaluation analogs for MTE instructions
 */
#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_CODEGEN)
	// TODO: If this is modified, make the same change in mte.c
	.macro _LDG, arg1, arg2
#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_ENABLE_MTE)
	ldr x16, [\arg2]
	mov x17, #0xF0 // TODO: use x16 if necessary
	lsl x17, x17, #49
	orr \arg1, x17, x17
#endif
	.endm

	.macro _STG3, arg1, arg2, arg3
#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_ENABLE_MTE)
	ldr x16, [\arg2] // TODO: Check if load and store take the same time
			 // and only do that
	mov x17, \arg1 // TODO: check if lsr 0 is fine and don't use x17
	lsr x17, x17, #49
	str x16, [\arg2]
	add \arg2, \arg2, \arg3
#endif
	.endm

	.macro _STG2, arg1, arg2
	_STG3 \arg1, \arg2, #0
	.endm

	.macro _LDGM, arg1, arg2
#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_ENABLE_MTE)
	/* Repeat a ldg 6 times, which was determined from a running system */
	_LDG \arg1, \arg2
	_LDG \arg1, \arg2
	_LDG \arg1, \arg2
	_LDG \arg1, \arg2
	_LDG \arg1, \arg2
	_LDG \arg1, \arg2
	/* Move fake tags into target register */
	mov \arg1, #0xF0F0F0F0F0F0F0F0
#endif
	.endm

	.macro _STGM, arg1, arg2
#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_ENABLE_MTE)
	/* Repeat a stg 6 times, which was determined from a running system */
	_STG2 \arg1, \arg2
	_STG2 \arg1, \arg2
	_STG2 \arg1, \arg2
	_STG2 \arg1, \arg2
	_STG2 \arg1, \arg2
	_STG2 \arg1, \arg2
#endif
	.endm
#else
	.macro _LDG, arg1, arg2
	ldg \arg1, [\arg2]
	.endm

	.macro _STG2, arg1, arg2
	stg \arg1, [\arg2]
	.endm

	.macro _STG3, arg1, arg2, arg3
	stg \arg1, [\arg2], \arg3
	.endm

	.macro _LDGM, arg1, arg2
	ldgm \arg1, [\arg2]
	.endm

	.macro _STGM, arg1, arg2
	stgm \arg1, [\arg2]
	.endm
#endif

/*
 * multitag_transfer_size - set \reg to the block size that is accessed by the
 * LDGM/STGM instructions.
 */
	.macro	multitag_transfer_size, reg, tmp
#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_CODEGEN)
	/* NB: Values taken from running system */
	mov \reg, #0x100
	mov \tmp, #0x4
	add \reg, \reg, #0x1
	sub \reg, \reg, #0x1
#else
	mrs_s	\reg, SYS_GMID_EL1
	ubfx	\reg, \reg, #SYS_GMID_EL1_BS_SHIFT, #SYS_GMID_EL1_BS_SIZE
	mov	\tmp, #4
	lsl	\reg, \tmp, \reg
#endif
	.endm

/*
 * Clear the tags in a page
 *   x0 - address of the page to be cleared
 */
SYM_FUNC_START(mte_clear_page_tags)
	multitag_transfer_size x1, x2
1:	_STGM	xzr, x0
	add	x0, x0, x1
	tst	x0, #(PAGE_SIZE - 1)
	b.ne	1b
	ret
SYM_FUNC_END(mte_clear_page_tags)

/*
 * Copy the tags from the source page to the destination one
 *   x0 - address of the destination page
 *   x1 - address of the source page
 */
SYM_FUNC_START(mte_copy_page_tags)
	mov	x2, x0
	mov	x3, x1
	multitag_transfer_size x5, x6
1:	_LDGM	x4, x3
	_STGM	x4, x2
	add	x2, x2, x5
	add	x3, x3, x5
	tst	x2, #(PAGE_SIZE - 1)
	b.ne	1b
	ret
SYM_FUNC_END(mte_copy_page_tags)

/*
 * Read tags from a user buffer (one tag per byte) and set the corresponding
 * tags at the given kernel address. Used by PTRACE_POKEMTETAGS.
 *   x0 - kernel address (to)
 *   x1 - user buffer (from)
 *   x2 - number of tags/bytes (n)
 * Returns:
 *   x0 - number of tags read/set
 */
SYM_FUNC_START(mte_copy_tags_from_user)
	mov	x3, x1
	cbz	x2, 2f
1:
	uao_user_alternative 2f, ldrb, ldtrb, w4, x1, 0
	lsl	x4, x4, #MTE_TAG_SHIFT
	_STG3	x4, x0, #MTE_GRANULE_SIZE
	add	x1, x1, #1
	subs	x2, x2, #1
	b.ne	1b

	// exception handling and function return
2:	sub	x0, x1, x3		// update the number of tags set
	ret
SYM_FUNC_END(mte_copy_tags_from_user)

/*
 * Get the tags from a kernel address range and write the tag values to the
 * given user buffer (one tag per byte). Used by PTRACE_PEEKMTETAGS.
 *   x0 - user buffer (to)
 *   x1 - kernel address (from)
 *   x2 - number of tags/bytes (n)
 * Returns:
 *   x0 - number of tags read/set
 */
SYM_FUNC_START(mte_copy_tags_to_user)
	mov	x3, x0
	cbz	x2, 2f
1:
	_LDG	x4, x1
	ubfx	x4, x4, #MTE_TAG_SHIFT, #MTE_TAG_SIZE
	uao_user_alternative 2f, strb, sttrb, w4, x0, 0
	add	x0, x0, #1
	add	x1, x1, #MTE_GRANULE_SIZE
	subs	x2, x2, #1
	b.ne	1b

	// exception handling and function return
2:	sub	x0, x0, x3		// update the number of tags copied
	ret
SYM_FUNC_END(mte_copy_tags_to_user)

/*
 * Save the tags in a page
 *   x0 - page address
 *   x1 - tag storage
 */
SYM_FUNC_START(mte_save_page_tags)
	multitag_transfer_size x7, x5
1:
	mov	x2, #0
2:
	_LDGM	x5, x0
	orr	x2, x2, x5
	add	x0, x0, x7
	tst	x0, #0xFF		// 16 tag values fit in a register,
	b.ne	2b			// which is 16*16=256 bytes

	str	x2, [x1], #8

	tst	x0, #(PAGE_SIZE - 1)
	b.ne	1b

	ret
SYM_FUNC_END(mte_save_page_tags)

/*
 * Restore the tags in a page
 *   x0 - page address
 *   x1 - tag storage
 */
SYM_FUNC_START(mte_restore_page_tags)
	multitag_transfer_size x7, x5
1:
	ldr	x2, [x1], #8
2:
	_STGM	x2, x0
	add	x0, x0, x7
	tst	x0, #0xFF
	b.ne	2b

	tst	x0, #(PAGE_SIZE - 1)
	b.ne	1b

	ret
SYM_FUNC_END(mte_restore_page_tags)

///*
// * Assign allocation tags for a region of memory based on the pointer tag
// *   x0 - source pointer
// *   x1 - size (The caller has to check that it is greater then zero)
// *
// * Note: size must be non-zero and MTE_GRANULE_SIZE aligned
// */
//SYM_FUNC_START(mte_assign_mem_tag_range)
//	/* if (src == NULL) return; */
//	cbz	x0, 2f
//1:	_STG2	x0, x0
//	add	x0, x0, #MTE_GRANULE_SIZE
//	sub	x1, x1, #MTE_GRANULE_SIZE
//	cbnz	x1, 1b
//2:	ret
//SYM_FUNC_END(mte_assign_mem_tag_range)
