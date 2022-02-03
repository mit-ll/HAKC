// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  UDPLITEv6   An implementation of the UDP-Lite protocol over IPv6.
 *              See also net/ipv4/udplite.c
 *
 *  Authors:    Gerrit Renker       <gerrit@erg.abdn.ac.uk>
 *
 *  Changes:
 *  Fixes:
 */
#include <linux/export.h>
#include <linux/proc_fs.h>
#include "udp_impl.h"

#include <linux/hakc.h>
#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_IPV6)
HAKC_MODULE_CLAQUE(2, RED_CLIQUE, HAKC_MASK_COLOR(SILVER_CLIQUE) | HAKC_MASK_COLOR(GREEN_CLIQUE));
#endif

static int udplitev6_rcv(struct sk_buff *skb)
{
	return __udp6_lib_rcv(skb, &udplite_table, IPPROTO_UDPLITE);
}

static int udplitev6_err(struct sk_buff *skb,
			  struct inet6_skb_parm *opt,
			  u8 type, u8 code, int offset, __be32 info)
{
	return __udp6_lib_err(skb, opt, type, code, offset, info,
			      &udplite_table);
}

static const struct inet6_protocol udplitev6_protocol = {
	.handler	=	udplitev6_rcv,
	.err_handler	=	udplitev6_err,
	.flags		=	INET6_PROTO_NOPOLICY|INET6_PROTO_FINAL,
};

struct proto udplitev6_prot = {
	.name		   = "UDPLITEv6",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip6_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.init		   = udplite_sk_init,
	.destroy	   = udpv6_destroy_sock,
	.setsockopt	   = udpv6_setsockopt,
	.getsockopt	   = udpv6_getsockopt,
	.sendmsg	   = udpv6_sendmsg,
	.recvmsg	   = udpv6_recvmsg,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.rehash		   = udp_v6_rehash,
	.get_port	   = udp_v6_get_port,
	.memory_allocated  = &udp_memory_allocated,
	.sysctl_mem	   = sysctl_udp_mem,
	.obj_size	   = sizeof(struct udp6_sock),
	.h.udp_table	   = &udplite_table,
};

static struct inet_protosw udplite6_protosw = {
	.type		= SOCK_DGRAM,
	.protocol	= IPPROTO_UDPLITE,
	.prot		= &udplitev6_prot,
	.ops		= &inet6_dgram_ops,
	.flags		= INET_PROTOSW_PERMANENT,
};

int __init udplitev6_init(void)
{
	int ret;

	ret = inet6_add_protocol(&udplitev6_protocol, IPPROTO_UDPLITE);
	if (ret)
		goto out;

	ret = inet6_register_protosw(&udplite6_protosw);
	if (ret)
		goto out_udplitev6_protocol;
out:
	return ret;

out_udplitev6_protocol:
	inet6_del_protocol(&udplitev6_protocol, IPPROTO_UDPLITE);
	goto out;
}

void udplitev6_exit(void)
{
	inet6_unregister_protosw(&udplite6_protosw);
	inet6_del_protocol(&udplitev6_protocol, IPPROTO_UDPLITE);
}

#ifdef CONFIG_PROC_FS
static struct udp_seq_afinfo udplite6_seq_afinfo = {
	.family		= AF_INET6,
	.udp_table	= &udplite_table,
};

static int __net_init noinline udplite6_proc_init_net(struct net *net)
{
	if (!proc_create_net_data("udplite6", 0444, net->proc_net,
			&udp6_seq_ops, sizeof(struct udp_iter_state),
			&udplite6_seq_afinfo))
		return -ENOMEM;
	return 0;
}

#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_IPV6)
DEFINE_HAKC_OUTSIDE_TRANSFER_FUNC(udplite6_proc_init_net, int, struct net* net) {
	int result;

	struct proc_dir_entry *orig_proc_net = net->proc_net;
	/* NB: The sizes were determined at run time */
	net->proc_net = hakc_transfer_to_clique(net->proc_net, 172,
						__claque_id, __color, false);
	net = hakc_transfer_to_clique(net, sizeof(*net), __claque_id,
				      __color, false);
	result = udplite6_proc_init_net(net);
	HAKC_GET_SAFE_PTR(net)->proc_net = orig_proc_net;

	return result;
}
#endif

static void __net_exit udplite6_proc_exit_net(struct net *net)
{
	remove_proc_entry("udplite6", net->proc_net);
}

static struct pernet_operations udplite6_net_ops = {
	.init = udplite6_proc_init_net,
#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_IPV6)
	.init = HAKC_OUTSIDE_TRANSFER_FUNC(udplite6_proc_init_net),
#else
	.init = udplite6_proc_init_net,
#endif
	.exit = udplite6_proc_exit_net,
};

int __init udplite6_proc_init(void)
{
	return register_pernet_subsys(&udplite6_net_ops);
}

void udplite6_proc_exit(void)
{
	unregister_pernet_subsys(&udplite6_net_ops);
}
#endif
