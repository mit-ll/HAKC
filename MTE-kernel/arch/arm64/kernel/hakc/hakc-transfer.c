//
// Created by derrick on 12/3/20.
//

#include <linux/hakc-transfer.h>
#include <linux/netdevice.h>

static void hakc_record_common(void *ptr, struct hakc_transfer_common *result)
{
	result->original_id = get_hakc_address_claque(ptr);
	result->original_color = get_hakc_address_color(ptr);
	result->original = (void *)ptr;
}

static void hakc_transfer_to_destination(const void *dest, void *ptr,
					size_t size,
					struct hakc_transfer_common *result)
{
	hakc_record_common(ptr, result);
	result->transferred = hakc_transfer_data_to_target(
		dest, result->original, size, false);
	result->size = size;
}

static void hakc_restore_original(struct hakc_transfer_common *original)
{
	//	if(VALID_CLAQUE(original->original_id)) {
	if (HAKC_GET_SAFE_PTR(original->transferred) !=
	    HAKC_GET_SAFE_PTR(original->original)) {
		hakc_transfer_to_clique(original->transferred, original->size,
				       original->original_id,
				       original->original_color, false);
	}
	//	}
}

#define DEFINE_TRANSFER(NAME)                                                  \
	void TRANSFER_FUNC_NAME(NAME)(struct NAME * orig, const void *dest,    \
				      size_t sz,                               \
				      TRANSFER_STRUCT_TYPE(NAME) * transfer)   \
	{                                                                      \
		hakc_transfer_to_destination(                                   \
			dest, orig, sz, &transfer->HAKC_COMMON_NAME(NAME));    \
	}                                                                      \
	EXPORT_SYMBOL(TRANSFER_FUNC_NAME(NAME));                               \
	void RESTORE_FUNC_NAME(NAME)(TRANSFER_STRUCT_TYPE(NAME) * transfer)    \
	{                                                                      \
		hakc_restore_original(&transfer->HAKC_COMMON_NAME(NAME));       \
	}                                                                      \
	EXPORT_SYMBOL(RESTORE_FUNC_NAME(NAME));

DEFINE_TRANSFER(socket);
DEFINE_TRANSFER(sock);

void TRANSFER_FUNC_NAME(net)(struct net *orig, const void *dest, size_t sz,
			     TRANSFER_STRUCT_TYPE(net) * transfer)
{
	/* NB: The sizes were determined at run time */
	hakc_transfer_to_destination(dest, HAKC_GET_SAFE_PTR(orig)->proc_net, 172,
				    &transfer->HAKC_COMMON_NAME(proc_net));
	HAKC_GET_SAFE_PTR(orig)->proc_net =
		HAKC_TRANSFERRED(proc_net, *transfer);
	hakc_transfer_to_destination(dest, orig, 3136,
				    &transfer->HAKC_COMMON_NAME(net));
}
EXPORT_SYMBOL(TRANSFER_FUNC_NAME(net));

void RESTORE_FUNC_NAME(net)(TRANSFER_STRUCT_TYPE(net) * transfer)
{
	hakc_restore_original(&transfer->HAKC_COMMON_NAME(net));
	hakc_restore_original(&transfer->HAKC_COMMON_NAME(proc_net));
	if (HAKC_ORIGINAL(proc_net, *transfer)) {
		HAKC_GET_SAFE_PTR((struct net *)HAKC_ORIGINAL(net, *transfer))
			->proc_net = HAKC_ORIGINAL(proc_net, *transfer);
	}
}
EXPORT_SYMBOL(RESTORE_FUNC_NAME(net));

//void TRANSFER_FUNC_NAME(sk_buff)(struct sk_buff* skb, const void *dest, size_t sz,
//				 TRANSFER_STRUCT_TYPE(sk_buff) * transfer) {
//	size_t head_offset = skb->data - skb->head;
//
//	skb->sk = hakc_transfer_to_clique(
//		skb->sk, sizeof(*skb->sk), __claque_id, __color, false);
//
//	skb->head = hakc_transfer_to_clique(
//		skb->head,
//		skb->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff)),
//		__claque_id, __color, false);
//	skb->data = skb->head + head_offset;
//	skb = hakc_transfer_to_clique(
//		skb,
//		SKB_DATA_ALIGN(sizeof(struct sk_buff)) +
//		SKB_DATA_ALIGN(
//			sizeof(struct skb_shared_info)),
//		__claque_id, __color,
//		false);
//}
//EXPORT_SYMBOL(TRANSFER_FUNC_NAME(sk_buff));
//
//void RESTORE_FUNC_NAME(sk_buff)(TRANSFER_STRUCT_TYPE(sk_buff) * transfer)
//{
//
//}
//EXPORT_SYMBOL(RESTORE_FUNC_NAME(sk_buff));