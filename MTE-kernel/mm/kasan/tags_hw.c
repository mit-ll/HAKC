// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains core hardware tag-based KASAN code.
 *
 * Copyright (c) 2020 Google, Inc.
 * Author: Andrey Konovalov <andreyknvl@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>

#include "kasan.h"

void kasan_init_tags(void)
{
	mte_init_tags(KASAN_TAG_MAX);
}

void *kasan_reset_tag(const void *addr)
{
	return reset_tag(addr);
}

void kasan_poison_memory(const void *address, size_t size, u8 value)
{
	mte_set_mem_tag_range(reset_tag(address),
		round_up(size, KASAN_GRANULE_SIZE), value);
}

void kasan_unpoison_memory(const void *address, size_t size)
{
	mte_set_mem_tag_range(reset_tag(address),
		round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
}

u8 random_tag(void)
{
	return mte_get_random_tag();
}

bool check_invalid_free(void *addr)
{
	u8 ptr_tag = get_tag(addr);
	u8 mem_tag = mte_get_mem_tag(addr);

	if (mem_tag == KASAN_TAG_INVALID)
		return true;
	if (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag)
		return true;
	return false;
}

void kasan_set_free_info(struct kmem_cache *cache,
				void *object, u8 tag)
{
	struct kasan_alloc_meta *alloc_meta;

	alloc_meta = get_alloc_info(cache, object);
	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
}

struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
				void *object, u8 tag)
{
	struct kasan_alloc_meta *alloc_meta;

	alloc_meta = get_alloc_info(cache, object);
	return &alloc_meta->free_track[0];
}
