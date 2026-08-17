// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	IPV6 GSO/GRO offload support
 *	Linux INET6 implementation
 *
 *      IPV6 Extension Header GSO/GRO support
 */
#include <net/protocol.h>
#include "ip6_offload.h"

#include <linux/hakc.h>
#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_IPV6)
HAKC_MODULE_CLAQUE(2, RED_CLIQUE, HAKC_MASK_COLOR(SILVER_CLIQUE) | HAKC_MASK_COLOR(GREEN_CLIQUE));
#endif

static const struct net_offload rthdr_offload = {
	.flags		=	INET6_PROTO_GSO_EXTHDR,
};

static const struct net_offload dstopt_offload = {
	.flags		=	INET6_PROTO_GSO_EXTHDR,
};

int __init ipv6_exthdrs_offload_init(void)
{
	int ret;

	ret = inet6_add_offload(&rthdr_offload, IPPROTO_ROUTING);
	if (ret)
		goto out;

	ret = inet6_add_offload(&dstopt_offload, IPPROTO_DSTOPTS);
	if (ret)
		goto out_rt;

out:
	return ret;

out_rt:
	inet6_del_offload(&rthdr_offload, IPPROTO_ROUTING);
	goto out;
}
