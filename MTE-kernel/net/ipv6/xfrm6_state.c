// SPDX-License-Identifier: GPL-2.0
/*
 * xfrm6_state.c: based on xfrm4_state.c
 *
 * Authors:
 *	Mitsuru KANDA @USAGI
 *	Kazunori MIYAZAWA @USAGI
 *	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
 *		IPv6 support
 *	YOSHIFUJI Hideaki @USAGI
 *		Split up af-specific portion
 *
 */

#include <net/xfrm.h>

#include <linux/hakc.h>
#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_IPV6)
HAKC_MODULE_CLAQUE(2, RED_CLIQUE, HAKC_MASK_COLOR(SILVER_CLIQUE) | HAKC_MASK_COLOR(GREEN_CLIQUE));
#endif

static struct xfrm_state_afinfo xfrm6_state_afinfo = {
	.family			= AF_INET6,
	.proto			= IPPROTO_IPV6,
	.output			= xfrm6_output,
	.transport_finish	= xfrm6_transport_finish,
	.local_error		= xfrm6_local_error,
};

int __init xfrm6_state_init(void)
{
	return xfrm_state_register_afinfo(&xfrm6_state_afinfo);
}

void xfrm6_state_fini(void)
{
	xfrm_state_unregister_afinfo(&xfrm6_state_afinfo);
}
