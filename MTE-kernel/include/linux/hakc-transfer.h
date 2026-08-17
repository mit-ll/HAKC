//
// Created by derrick on 12/3/20.
//

#ifndef MTE_KERNEL_HAKC_TRANSFER_H
#define MTE_KERNEL_HAKC_TRANSFER_H

#include <net/net_namespace.h>
#include <linux/skbuff.h>

#include "hakc.h"

struct hakc_transfer_common {
    claque_id_t original_id;
    clique_color_t original_color;
    void *original;
    void* transferred;
    size_t size;
};

#define HAKC_TRANSFER_CONCAT(a, b) a##b

#define TRANSFER_STRUCT_TYPE(NAME)                                             \
	HAKC_TRANSFER_CONCAT(struct hakc_transfer_, NAME)
#define TRANSFER_FUNC_NAME(NAME) HAKC_TRANSFER_CONCAT(hakc_transfer_,NAME)
#define RESTORE_FUNC_NAME(NAME) HAKC_TRANSFER_CONCAT(hakc_restore_,NAME)
#define HAKC_COMMON_NAME(NAME) HAKC_TRANSFER_CONCAT(hakc_data_, NAME)

#define HAKC_STRUCT_TRANSFER(NAME) \
TRANSFER_STRUCT_TYPE(NAME) { struct hakc_transfer_common HAKC_COMMON_NAME(NAME); }; \
void TRANSFER_FUNC_NAME(NAME)(struct NAME *orig, const void* dest, size_t sz, \
TRANSFER_STRUCT_TYPE(NAME) *transfer); \
void RESTORE_FUNC_NAME(NAME)(TRANSFER_STRUCT_TYPE(NAME)*);

#define HAKC_CUSTOM_STRUCT_TRANSFER(NAME) \
    TRANSFER_STRUCT_TYPE(NAME); \
    void TRANSFER_FUNC_NAME(NAME)(struct NAME *orig, const void* dest, \
            size_t sz, TRANSFER_STRUCT_TYPE(NAME) *transfer); \
    void RESTORE_FUNC_NAME(NAME)(TRANSFER_STRUCT_TYPE(NAME)*); \
    TRANSFER_STRUCT_TYPE(NAME)

#define HAKC_TRANSFERRED(NAME, OBJ) (OBJ).HAKC_COMMON_NAME(NAME).transferred
#define HAKC_ORIGINAL(NAME, OBJ) (OBJ).HAKC_COMMON_NAME(NAME).original

HAKC_CUSTOM_STRUCT_TRANSFER(net) {
    struct hakc_transfer_common HAKC_COMMON_NAME(net);
    struct hakc_transfer_common HAKC_COMMON_NAME(proc_net);
};
HAKC_STRUCT_TRANSFER(socket);
HAKC_STRUCT_TRANSFER(sock);

//HAKC_CUSTOM_STRUCT_TRANSFER(sk_buff) {
//	struct hakc_transfer_common HAKC_COMMON_NAME(skb);
//	struct hakc_transfer_common HAKC_COMMON_NAME(head);
//	struct hakc_transfer_common HAKC_COMMON_NAME(sk);
//	unsigned long data;
//};

#endif //MTE_KERNEL_HAKC_TRANSFER_H
