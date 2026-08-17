#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_tables.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_arp.h>
#include <net/netfilter/nf_tables_ipv4.h>
#include <net/netfilter/nf_tables_ipv6.h>

#include <linux/hakc.h>
#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_NF_TABLES)
#include <linux/hakc-transfer.h>
HAKC_MODULE_CLAQUE(3, BLUE_CLIQUE, HAKC_MASK_COLOR(SILVER_CLIQUE));
#endif

#ifdef CONFIG_NF_TABLES_IPV4
static unsigned int nft_do_chain_ipv4(void *priv,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct nft_pktinfo pkt;

	nft_set_pktinfo(&pkt, skb, state);
	nft_set_pktinfo_ipv4(&pkt, skb);

	return nft_do_chain(&pkt, priv);
}

static const struct nft_chain_type nft_chain_filter_ipv4 = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_IPV4,
	.hook_mask	= (1 << NF_INET_LOCAL_IN) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING),
	.hooks		= {
		[NF_INET_LOCAL_IN]	= nft_do_chain_ipv4,
		[NF_INET_LOCAL_OUT]	= nft_do_chain_ipv4,
		[NF_INET_FORWARD]	= nft_do_chain_ipv4,
		[NF_INET_PRE_ROUTING]	= nft_do_chain_ipv4,
		[NF_INET_POST_ROUTING]	= nft_do_chain_ipv4,
	},
};

static void nft_chain_filter_ipv4_init(void)
{
	nft_register_chain_type(&nft_chain_filter_ipv4);
}
static void nft_chain_filter_ipv4_fini(void)
{
	nft_unregister_chain_type(&nft_chain_filter_ipv4);
}

#else
static inline void nft_chain_filter_ipv4_init(void) {}
static inline void nft_chain_filter_ipv4_fini(void) {}
#endif /* CONFIG_NF_TABLES_IPV4 */

#ifdef CONFIG_NF_TABLES_ARP
static unsigned int nft_do_chain_arp(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	struct nft_pktinfo pkt;

	nft_set_pktinfo(&pkt, skb, state);
	nft_set_pktinfo_unspec(&pkt, skb);

	return nft_do_chain(&pkt, priv);
}

static const struct nft_chain_type nft_chain_filter_arp = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_ARP,
	.owner		= THIS_MODULE,
	.hook_mask	= (1 << NF_ARP_IN) |
			  (1 << NF_ARP_OUT),
	.hooks		= {
		[NF_ARP_IN]		= nft_do_chain_arp,
		[NF_ARP_OUT]		= nft_do_chain_arp,
	},
};

static void nft_chain_filter_arp_init(void)
{
	nft_register_chain_type(&nft_chain_filter_arp);
}

static void nft_chain_filter_arp_fini(void)
{
	nft_unregister_chain_type(&nft_chain_filter_arp);
}
#else
static inline void nft_chain_filter_arp_init(void) {}
static inline void nft_chain_filter_arp_fini(void) {}
#endif /* CONFIG_NF_TABLES_ARP */

#ifdef CONFIG_NF_TABLES_IPV6
static hakc_noinline unsigned int nft_do_chain_ipv6(void *priv,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct nft_pktinfo pkt;
	nft_set_pktinfo(&pkt, skb, state);
	nft_set_pktinfo_ipv6(&pkt, skb);

	return nft_do_chain(&pkt, priv);
}

#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_NF_TABLES)
static unsigned int HAKC_TRANSFER_nft_do_chain_ipv6(void *priv,
              struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
  clique_color_t orig_skb_color = get_hakc_address_color(skb);
  claque_id_t orig_skb_id = get_hakc_address_claque(skb);   
  clique_color_t orig_state_color = get_hakc_address_color(state);
  claque_id_t orig_state_id = get_hakc_address_claque(state);
  clique_color_t orig_state_sk_color, orig_state_net_color;
  claque_id_t orig_state_sk_id, orig_state_net_id;    
  unsigned int retval;

  skb = hakc_transfer_skb(skb, __claque_id, __color);
  if (state->sk != NULL) {
    orig_state_sk_color = get_hakc_address_color(state->sk);
    orig_state_sk_id = get_hakc_address_claque(state->sk);
    ((struct nf_hook_state*)state)->sk = hakc_transfer_to_clique(state->sk, sizeof(*state->sk), __claque_id, __color, false);
  }
  if (state->net != NULL) {
    orig_state_net_color = get_hakc_address_color(state->net);
    orig_state_net_id = get_hakc_address_claque(state->net);
    ((struct nf_hook_state*)state)->net = hakc_transfer_to_clique(state->net, sizeof(*state->net), __claque_id, __color, false);
  }
  state = hakc_transfer_to_clique((void*)state, sizeof(*state), __claque_id, __color, false);
  retval = nft_do_chain_ipv6(priv, skb, state);
  skb = HAKC_GET_SAFE_PTR(skb);
  skb->head = HAKC_GET_SAFE_PTR(skb->head);
  hakc_transfer_skb(skb, orig_skb_id, orig_skb_color);
  state = HAKC_GET_SAFE_PTR(state);
  if (state->sk != NULL) {
    ((struct nf_hook_state*)state)->sk = hakc_transfer_to_clique(state->sk, sizeof(*state->sk), orig_state_sk_id, orig_state_sk_color, false);
  }
  if (state->net != NULL) {
    ((struct nf_hook_state*)state)->net = hakc_transfer_to_clique(state->net, sizeof(*state->net), orig_state_net_id, orig_state_net_color, false);
  }
  state = hakc_transfer_to_clique((void*)state, sizeof(*state), orig_state_id, orig_state_color, false);
  return retval;
}
#endif

#if IS_ENABLED(CONFIG_PAC_MTE_COMPART)
static struct nft_chain_type nft_chain_filter_ipv6 = {
#else
static const struct nft_chain_type nft_chain_filter_ipv6 = {
#endif
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_IPV6,
	.hook_mask	= (1 << NF_INET_LOCAL_IN) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING),
	.hooks		= {
#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_NF_TABLES)
		[NF_INET_LOCAL_IN]	= HAKC_TRANSFER_nft_do_chain_ipv6,
		[NF_INET_LOCAL_OUT]	= HAKC_TRANSFER_nft_do_chain_ipv6,
		[NF_INET_FORWARD]	= HAKC_TRANSFER_nft_do_chain_ipv6,
		[NF_INET_PRE_ROUTING]	= HAKC_TRANSFER_nft_do_chain_ipv6,
		[NF_INET_POST_ROUTING]	= HAKC_TRANSFER_nft_do_chain_ipv6,
#else
		[NF_INET_LOCAL_IN]	= nft_do_chain_ipv6,
		[NF_INET_LOCAL_OUT]	= nft_do_chain_ipv6,
		[NF_INET_FORWARD]	= nft_do_chain_ipv6,
		[NF_INET_PRE_ROUTING]	= nft_do_chain_ipv6,
		[NF_INET_POST_ROUTING]	= nft_do_chain_ipv6,
#endif
	},
};

static void nft_chain_filter_ipv6_init(void)
{
	nft_register_chain_type(&nft_chain_filter_ipv6);
}

static void nft_chain_filter_ipv6_fini(void)
{
	nft_unregister_chain_type(&nft_chain_filter_ipv6);
}
#else
static inline void nft_chain_filter_ipv6_init(void) {}
static inline void nft_chain_filter_ipv6_fini(void) {}
#endif /* CONFIG_NF_TABLES_IPV6 */

#ifdef CONFIG_NF_TABLES_INET
static unsigned int nft_do_chain_inet(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct nft_pktinfo pkt;

	nft_set_pktinfo(&pkt, skb, state);

	switch (state->pf) {
	case NFPROTO_IPV4:
		nft_set_pktinfo_ipv4(&pkt, skb);
		break;
	case NFPROTO_IPV6:
		nft_set_pktinfo_ipv6(&pkt, skb);
		break;
	default:
		break;
	}

	return nft_do_chain(&pkt, priv);
}

static unsigned int nft_do_chain_inet_ingress(void *priv, struct sk_buff *skb,
					      const struct nf_hook_state *state)
{
	struct nf_hook_state ingress_state = *state;
	struct nft_pktinfo pkt;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		/* Original hook is NFPROTO_NETDEV and NF_NETDEV_INGRESS. */
		ingress_state.pf = NFPROTO_IPV4;
		ingress_state.hook = NF_INET_INGRESS;
		nft_set_pktinfo(&pkt, skb, &ingress_state);

		if (nft_set_pktinfo_ipv4_ingress(&pkt, skb) < 0)
			return NF_DROP;
		break;
	case htons(ETH_P_IPV6):
		ingress_state.pf = NFPROTO_IPV6;
		ingress_state.hook = NF_INET_INGRESS;
		nft_set_pktinfo(&pkt, skb, &ingress_state);

		if (nft_set_pktinfo_ipv6_ingress(&pkt, skb) < 0)
			return NF_DROP;
		break;
	default:
		return NF_ACCEPT;
	}

	return nft_do_chain(&pkt, priv);
}

static const struct nft_chain_type nft_chain_filter_inet = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_INET,
	.hook_mask	= (1 << NF_INET_INGRESS) |
			  (1 << NF_INET_LOCAL_IN) |
			  (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_PRE_ROUTING) |
			  (1 << NF_INET_POST_ROUTING),
	.hooks		= {
		[NF_INET_INGRESS]	= nft_do_chain_inet_ingress,
		[NF_INET_LOCAL_IN]	= nft_do_chain_inet,
		[NF_INET_LOCAL_OUT]	= nft_do_chain_inet,
		[NF_INET_FORWARD]	= nft_do_chain_inet,
		[NF_INET_PRE_ROUTING]	= nft_do_chain_inet,
		[NF_INET_POST_ROUTING]	= nft_do_chain_inet,
        },
};

static void nft_chain_filter_inet_init(void)
{
	nft_register_chain_type(&nft_chain_filter_inet);
}

static void nft_chain_filter_inet_fini(void)
{
	nft_unregister_chain_type(&nft_chain_filter_inet);
}
#else
static inline void nft_chain_filter_inet_init(void) {}
static inline void nft_chain_filter_inet_fini(void) {}
#endif /* CONFIG_NF_TABLES_IPV6 */

#if IS_ENABLED(CONFIG_NF_TABLES_BRIDGE)
static unsigned int
nft_do_chain_bridge(void *priv,
		    struct sk_buff *skb,
		    const struct nf_hook_state *state)
{
	struct nft_pktinfo pkt;

	nft_set_pktinfo(&pkt, skb, state);

	switch (eth_hdr(skb)->h_proto) {
	case htons(ETH_P_IP):
		nft_set_pktinfo_ipv4_validate(&pkt, skb);
		break;
	case htons(ETH_P_IPV6):
		nft_set_pktinfo_ipv6_validate(&pkt, skb);
		break;
	default:
		nft_set_pktinfo_unspec(&pkt, skb);
		break;
	}

	return nft_do_chain(&pkt, priv);
}

static const struct nft_chain_type nft_chain_filter_bridge = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_BRIDGE,
	.hook_mask	= (1 << NF_BR_PRE_ROUTING) |
			  (1 << NF_BR_LOCAL_IN) |
			  (1 << NF_BR_FORWARD) |
			  (1 << NF_BR_LOCAL_OUT) |
			  (1 << NF_BR_POST_ROUTING),
	.hooks		= {
		[NF_BR_PRE_ROUTING]	= nft_do_chain_bridge,
		[NF_BR_LOCAL_IN]	= nft_do_chain_bridge,
		[NF_BR_FORWARD]		= nft_do_chain_bridge,
		[NF_BR_LOCAL_OUT]	= nft_do_chain_bridge,
		[NF_BR_POST_ROUTING]	= nft_do_chain_bridge,
	},
};

static void nft_chain_filter_bridge_init(void)
{
	nft_register_chain_type(&nft_chain_filter_bridge);
}

static void nft_chain_filter_bridge_fini(void)
{
	nft_unregister_chain_type(&nft_chain_filter_bridge);
}
#else
static inline void nft_chain_filter_bridge_init(void) {}
static inline void nft_chain_filter_bridge_fini(void) {}
#endif /* CONFIG_NF_TABLES_BRIDGE */

#ifdef CONFIG_NF_TABLES_NETDEV
static unsigned int nft_do_chain_netdev(void *priv, struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct nft_pktinfo pkt;

	nft_set_pktinfo(&pkt, skb, state);

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		nft_set_pktinfo_ipv4_validate(&pkt, skb);
		break;
	case htons(ETH_P_IPV6):
		nft_set_pktinfo_ipv6_validate(&pkt, skb);
		break;
	default:
		nft_set_pktinfo_unspec(&pkt, skb);
		break;
	}

	return nft_do_chain(&pkt, priv);
}

static const struct nft_chain_type nft_chain_filter_netdev = {
	.name		= "filter",
	.type		= NFT_CHAIN_T_DEFAULT,
	.family		= NFPROTO_NETDEV,
	.hook_mask	= (1 << NF_NETDEV_INGRESS),
	.hooks		= {
		[NF_NETDEV_INGRESS]	= nft_do_chain_netdev,
	},
};

static void nft_netdev_event(unsigned long event, struct net_device *dev,
			     struct nft_ctx *ctx)
{
	struct nft_base_chain *basechain = nft_base_chain(ctx->chain);
	struct nft_hook *hook, *found = NULL;
	int n = 0;

	if (event != NETDEV_UNREGISTER)
		return;

	list_for_each_entry(hook, &basechain->hook_list, list) {
		if (hook->ops.dev == dev)
			found = hook;

		n++;
	}
	if (!found)
		return;

	if (n > 1) {
		nf_unregister_net_hook(ctx->net, &found->ops);
		list_del_rcu(&found->list);
		kfree_rcu(found, rcu);
		return;
	}

	/* UNREGISTER events are also happening on netns exit.
	 *
	 * Although nf_tables core releases all tables/chains, only this event
	 * handler provides guarantee that hook->ops.dev is still accessible,
	 * so we cannot skip exiting net namespaces.
	 */
	__nft_release_basechain(ctx);
}

static hakc_noinline int nf_tables_netdev_event(struct notifier_block *this,
				  unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct nft_table *table;
	struct nft_chain *chain, *nr;
	struct nft_ctx ctx = {
		.net	= dev_net(dev),
	};

	if (event != NETDEV_UNREGISTER &&
	    event != NETDEV_CHANGENAME)
		return NOTIFY_DONE;

	mutex_lock(&ctx.net->nft.commit_mutex);
	list_for_each_entry(table, &ctx.net->nft.tables, list) {
		if (table->family != NFPROTO_NETDEV)
			continue;

		ctx.family = table->family;
		ctx.table = table;
		list_for_each_entry_safe(chain, nr, &table->chains, list) {
			if (!nft_is_base_chain(chain))
				continue;

			ctx.chain = chain;
			nft_netdev_event(event, dev, &ctx);
		}
	}
	mutex_unlock(&ctx.net->nft.commit_mutex);

	return NOTIFY_DONE;
}

#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_NF_TABLES)
DEFINE_HAKC_OUTSIDE_TRANSFER_FUNC(nf_tables_netdev_event, int, struct notifier_block *this,
				  unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
  struct net *net = dev_net(dev);
  struct netdev_notifier_info *info = ptr;
  dev_net_set(dev, hakc_transfer_to_clique(net, sizeof(*net), __claque_id, __color, false));
  info->dev = hakc_transfer_to_clique(dev, sizeof(*dev), __claque_id, __color, false);
  info = hakc_transfer_to_clique(info, sizeof(*info), __claque_id, __color, false);
  return nf_tables_netdev_event(this, event, info);
}
#endif

static struct notifier_block nf_tables_netdev_notifier = {
#if IS_ENABLED(CONFIG_PAC_MTE_COMPART_NF_TABLES)
	.notifier_call	= HAKC_OUTSIDE_TRANSFER_FUNC(nf_tables_netdev_event),
#else
	.notifier_call	= nf_tables_netdev_event,
#endif
};

static int nft_chain_filter_netdev_init(void)
{
	int err;

	nft_register_chain_type(&nft_chain_filter_netdev);

	err = register_netdevice_notifier(&nf_tables_netdev_notifier);
	if (err)
		goto err_register_netdevice_notifier;

	return 0;

err_register_netdevice_notifier:
	nft_unregister_chain_type(&nft_chain_filter_netdev);

	return err;
}

static void nft_chain_filter_netdev_fini(void)
{
	nft_unregister_chain_type(&nft_chain_filter_netdev);
	unregister_netdevice_notifier(&nf_tables_netdev_notifier);
}
#else
static inline int nft_chain_filter_netdev_init(void) { return 0; }
static inline void nft_chain_filter_netdev_fini(void) {}
#endif /* CONFIG_NF_TABLES_NETDEV */

int __init nft_chain_filter_init(void)
{
	int err;

	err = nft_chain_filter_netdev_init();
	if (err < 0)
		return err;

	nft_chain_filter_ipv4_init();
	nft_chain_filter_ipv6_init();
	nft_chain_filter_arp_init();
	nft_chain_filter_inet_init();
	nft_chain_filter_bridge_init();

	return 0;
}

void nft_chain_filter_fini(void)
{
	nft_chain_filter_bridge_fini();
	nft_chain_filter_inet_fini();
	nft_chain_filter_arp_fini();
	nft_chain_filter_ipv6_fini();
	nft_chain_filter_ipv4_fini();
	nft_chain_filter_netdev_fini();
}
