#ifndef LINUX_HAKC_H
#define LINUX_HAKC_H

#include <linux/types.h>
#include <linux/bits.h>
#include <asm/memory.h>

noinline void hakc_debug_breakpoint(void);

typedef u32 claque_id_t;
typedef u64 pac_salt_t;
typedef u64 clique_access_tok_t;

#define hakc_noinline

#if IS_ENABLED(CONFIG_PAC_MTE_COMPART)

#undef hakc_noinline
#define hakc_noinline noinline

#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_CODEGEN) && \
	!IS_ENABLED(PAC_MTE_MTE_MEMORY_BARRIER)
extern int tag_clobber_memory[4];
#endif

#define HAKC_COLOR_BIT_COUNT 4
#define CLAQUE_ID_BIT_COUNT 8
#define CLAQUE_ID_START (20)

#define LOWER_CLAQUE_BIT_MASK 0x10000000
#define UPPER_CLAQUE_BIT_MASK 0xFF00000000000000

#define CLAQUE_START_2 56
#define CLAQUE_BIT_MASK_2 UPPER_CLAQUE_BIT_MASK

/* Smallest consecutive bytes that can be colored */
#define COLOR_GRANULARITY (1 << HAKC_COLOR_BIT_COUNT)

/* Round up to the nearest COLOR_GRANULARITY */
#define HAKC_ROUND_UP(x) (((((x)-1) | (COLOR_GRANULARITY - 1)) + 1))

#define HAKC_MODULES_VADDR                                               \
	((unsigned long)KERNEL_START ^ LOWER_CLAQUE_BIT_MASK)

#define HAKC_ADDRESS_BITS VA_BITS

#define HAKC_KADDR(ADDR) (void *)(0xFFFF000000000000 | (u64)(ADDR))

#define _TAKE_SECOND(_ignore, x, ...) x

#if IS_ENABLED(CONFIG_PAC_MTE_EVAL_CODEGEN)
#define EMBED_CLAQUE_ID(CLAQUE, ADDR) 	ADDR
#else
#define EMBED_CLAQUE_ID(CLAQUE, ADDR)	\
	(((u64)ADDR & ~CLAQUE_BIT_MASK_2) | (((u64)CLAQUE) << CLAQUE_START_2))
#endif

#define HAKC_HERE ((const void *)_THIS_IP_)


#define HAKC_CLAQUE_MASK                                                        \
	(((1ul << (CLAQUE_ID_START + CLAQUE_ID_BIT_COUNT)) - 1) ^              \
	 ((1ul << CLAQUE_ID_START) - 1))



#define KERN_CLAQUE_BIT_MASK (0xFFFFFFFFFFF00000)

#define HAKC_CONTEXT_ADDR(ADDR) ((u64)(ADDR)&KERN_CLAQUE_BIT_MASK)
#define HAKC_CLAQUE_ADDR(ADDR) ((u64)(ADDR) & ~KERN_CLAQUE_BIT_MASK)

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
	START_CLIQUE = SILVER_CLIQUE,
	END_CLIQUE = START_CLIQUE + COLOR_GRANULARITY,
	INVALID_CLIQUE = END_CLIQUE
} clique_color_t;

#define HAKC_COLOR_COUNT (END_CLIQUE - START_CLIQUE)

typedef struct claque_entry_token {
	claque_id_t claque_id;
	clique_access_tok_t entry_token;
} claque_entry_tok_t;

void hakc_init_tags(void);

#define VALID_CLAQUE(claque_id)                                                \
	((claque_id) > 0 && (claque_id) < ((1ul << CLAQUE_ID_BIT_COUNT) - 1))
#define VALID_COLOR(color) ((color) >= START_CLIQUE && (color) < END_CLIQUE)

#define HAKC_MASK_COLOR(COLOR) (1 << (COLOR - START_CLIQUE))

#define HAKC_CONTEXT(CLAQUE_ID, COLOR_MASK, TYPE)                               \
	(((TYPE)(CLAQUE_ID) << COLOR_GRANULARITY) | (COLOR_MASK))

#define PAC_MODIFIER(CLAQUE_ID, COLOR_MASK)                                    \
	HAKC_CONTEXT(CLAQUE_ID, COLOR_MASK, pac_salt_t)

#define HAKC_ENTRY_TOKEN(CLAQUE, ENTRY_COLORS)                                  \
	{                                                                      \
		.claque_id = CLAQUE, .entry_token = ENTRY_COLORS               \
	}
#define HAKC_EXIT(TARGET, ...)                                                  \
	static __attribute__((used))                                           \
		const claque_entry_tok_t __valid_targets[] = { TARGET,         \
							       ##__VA_ARGS__ }

const char *get_hakc_color_name(clique_color_t color);

clique_color_t get_hakc_address_color(const void *addr);
claque_id_t get_hakc_address_claque(const void *addr);

void hakc_color_address(const void *addr_to_color, clique_color_t color,
		       size_t size);

clique_color_t get_hakc_color_by_name(const char *color_name);

void *check_hakc_data_access(const void *address,
			    const clique_access_tok_t access_tok);
void *check_hakc_code_access(const void *address,
			    const clique_access_tok_t access_tok,
			    const claque_entry_tok_t *valid_targets,
			    size_t n_targets);

void *hakc_transfer_data_to_target(const void *target, void *data_to_transfer,
				  size_t transfer_size, bool is_code);

void *hakc_transfer_to_clique(void *data_to_transfer, size_t size,
			     claque_id_t claque_id, clique_color_t color,
			     bool is_code);

void *hakc_sign_pointer(void *addr, claque_id_t claque_id,
	clique_color_t color, bool is_code);

void *hakc_transfer_percpu_to_clique(void *original, size_t size,
				    claque_id_t claque_id,
				    clique_color_t color);

void *hakc_sign_pointer_with_color(void *addr, claque_id_t claque_id,
				  bool is_code);

static inline claque_id_t upper_bit_claque(unsigned long address)
{
	return ((address & CLAQUE_BIT_MASK_2) >> CLAQUE_START_2);
}

static inline claque_id_t lower_bit_claque(unsigned long address)
{
	return ((address & (LOWER_CLAQUE_BIT_MASK | HAKC_CLAQUE_MASK)) >>
		(CLAQUE_ID_START));
}

static inline bool claque_in_high_bits(unsigned long address)
{
	return ((address & UPPER_CLAQUE_BIT_MASK) != UPPER_CLAQUE_BIT_MASK) &&
	       VALID_CLAQUE(upper_bit_claque(address));
}

static inline void *hakc_safe_ptr2(unsigned long addr)
{
	unsigned long tmp = addr;
	if (!(tmp & BIT(VA_BITS - 1))) {
		return (void*)(tmp & 0x0000FFFFFFFFFFFF);
	} else {
		return (void*)HAKC_KADDR(tmp);
	}
}

static inline void *hakc_safe_ptr(unsigned long addr)
{
	if (!addr) {
		return (void *)addr;
	}
	return (void *)((unsigned long)HAKC_KADDR(addr) | CLAQUE_BIT_MASK_2);
//	return hakc_safe_ptr2(addr);
}

void *hakc_transfer_string(void *, claque_id_t, clique_color_t);
struct sk_buff *hakc_transfer_skb(struct sk_buff *, claque_id_t, clique_color_t);
const struct nlattr * const *hakc_transfer_nla(const struct nlattr * const [], size_t, claque_id_t, clique_color_t);

#define HAKC_GET_SAFE_PTR(ptr) ((typeof(ptr))hakc_safe_ptr((unsigned long)(ptr)))

#define MODULE_CLAQUE(mod) (mod)->claque_id

#define _HAKC_DATA_COLOR_ATTR(COLOR)                                            \
	__attribute__((used, section(".data.hakc." #COLOR)))

#define HAKC_MODULE_CLIQUE(CLAQUE_ID, COLOR, ...)                               \
	static _HAKC_DATA_COLOR_ATTR(COLOR) const claque_id_t __claque_id =     \
		CLAQUE_ID;                                                     \
	static _HAKC_DATA_COLOR_ATTR(COLOR) const clique_color_t __color =      \
		COLOR;                                                         \
	static _HAKC_DATA_COLOR_ATTR(COLOR)                                     \
		const clique_access_tok_t __acl_tok =                          \
			HAKC_CONTEXT(CLAQUE_ID,                                 \
				    HAKC_MASK_COLOR(COLOR) |                        \
					    _TAKE_SECOND(0, ##__VA_ARGS__, 0), \
				    const clique_access_tok_t);

#define HAKC_MODULE_CLAQUE(CLAQUE_ID, COLOR, ...)                               \
	HAKC_MODULE_CLIQUE(CLAQUE_ID, COLOR, ##__VA_ARGS__)                     \
	MODULE_INFO(claque_id, #CLAQUE_ID);                                    \
	MODULE_INFO(color, #COLOR);

#define HAKC_SYMBOL_CLAQUE(SYM, CLAQUE_ID, COLOR, ...)                          \
	static _HAKC_DATA_COLOR_ATTR(COLOR)                                     \
		const claque_id_t __claque_id_##SYM = CLAQUE_ID;               \
	static _HAKC_DATA_COLOR_ATTR(COLOR)                                     \
		const clique_color_t __color_##SYM = COLOR;                    \
	static _HAKC_DATA_COLOR_ATTR(COLOR)                                     \
		const clique_access_tok_t __acl_tok_##SYM =                    \
			HAKC_CONTEXT(CLAQUE_ID,                                 \
				    HAKC_MASK_COLOR(COLOR) |                        \
					    _TAKE_SECOND(0, ##__VA_ARGS__, 0), \
				    const clique_access_tok_t)

#define HAKC_OUTSIDE_TRANSFER_FUNC(func) HAKC_TRANSFER_##func

#define DEFINE_HAKC_OUTSIDE_TRANSFER_FUNC(func, rettype, args...)  \
	rettype HAKC_OUTSIDE_TRANSFER_FUNC(func)(args)

#else

#define HAKC_GET_SAFE_PTR(ptr) ptr

#define HAKC_SYMBOL_CLAQUE(SYM, CLAQUE_ID, COLOR, ...)

#define DEFINE_HAKC_OUTSIDE_TRANSFER_FUNC(func, rettype, args...) func
#define HAKC_OUTSIDE_TRANSFER_FUNC(func) func
#define __claque_id	0
#define __color		0
#define hakc_sign_pointer_with_color(addr, claque_id, is_code)	addr


#endif /* IS_ENABLED(CONFIG_PAC_MTE_COMPART) */

#endif /* LINUX_HAKC_H */
