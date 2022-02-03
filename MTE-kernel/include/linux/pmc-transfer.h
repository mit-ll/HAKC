//
// Created by derrick on 12/3/20.
//

#ifndef MTE_KERNEL_PMC_TRANSFER_H
#define MTE_KERNEL_PMC_TRANSFER_H

#include <net/net_namespace.h>

#include "mte-compart.h"

struct pmc_transfer_common {
    claque_id_t original_id;
    clique_color_t original_color;
    void *original;
    void* transferred;
    size_t size;
};

#define MTE_TRANSFER_CONCAT(a, b) a##b

#define TRANSFER_STRUCT_TYPE(NAME) MTE_TRANSFER_CONCAT(struct pmc_transfer_, \
NAME)
#define TRANSFER_FUNC_NAME(NAME) MTE_TRANSFER_CONCAT(transfer_,NAME)
#define RESTORE_FUNC_NAME(NAME) MTE_TRANSFER_CONCAT(restore_,NAME)
#define PMC_COMMON_NAME(NAME) MTE_TRANSFER_CONCAT(data_, NAME)

#define PMC_STRUCT_TRANSFER(NAME) \
TRANSFER_STRUCT_TYPE(NAME) { struct pmc_transfer_common PMC_COMMON_NAME(NAME); }; \
void TRANSFER_FUNC_NAME(NAME)(struct NAME *orig, const void* dest, size_t sz, \
TRANSFER_STRUCT_TYPE(NAME) *transfer); \
void RESTORE_FUNC_NAME(NAME)(TRANSFER_STRUCT_TYPE(NAME)*);

#define PMC_CUSTOM_STRUCT_TRANSFER(NAME) \
    TRANSFER_STRUCT_TYPE(NAME); \
    void TRANSFER_FUNC_NAME(NAME)(struct NAME *orig, const void* dest, \
            size_t sz, TRANSFER_STRUCT_TYPE(NAME) *transfer); \
    void RESTORE_FUNC_NAME(NAME)(TRANSFER_STRUCT_TYPE(NAME)*); \
    TRANSFER_STRUCT_TYPE(NAME)

#define PMC_TRANSFERRED(NAME, OBJ) (OBJ).PMC_COMMON_NAME(NAME).transferred
#define PMC_ORIGINAL(NAME, OBJ) (OBJ).PMC_COMMON_NAME(NAME).original

PMC_CUSTOM_STRUCT_TRANSFER(net) {
    struct pmc_transfer_common PMC_COMMON_NAME(net);
    struct pmc_transfer_common PMC_COMMON_NAME(proc_net);
};
PMC_STRUCT_TRANSFER(socket);
PMC_STRUCT_TRANSFER(sock);


#endif //MTE_KERNEL_PMC_TRANSFER_H
