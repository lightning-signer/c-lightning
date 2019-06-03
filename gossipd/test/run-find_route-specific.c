/* We can't seem to route the following:
 *
 * Expect route 03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf -> 0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae -> 02ea622d5c8d6143f15ed3ce1d501dd0d3d09d3b1c83a44d0034949f8a9ab60f06
 *
 * getchannels:
 * {'channels': [{'active': True, 'short_id': '6990x2x1/1', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 1, 'destination': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'source': '02ea622d5c8d6143f15ed3ce1d501dd0d3d09d3b1c83a44d0034949f8a9ab60f06', 'last_update': 1504064344}, {'active': True, 'short_id': '6989x2x1/0', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 0, 'destination': '03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf', 'source': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'last_update': 1504064344}, {'active': True, 'short_id': '6990x2x1/0', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 0, 'destination': '02ea622d5c8d6143f15ed3ce1d501dd0d3d09d3b1c83a44d0034949f8a9ab60f06', 'source': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'last_update': 1504064344}, {'active': True, 'short_id': '6989x2x1/1', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 1, 'destination': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'source': '03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf', 'last_update': 1504064344}]}
 */
#include <common/status.h>

#include <stdio.h>
#define status_fmt(level, fmt, ...)					\
	do { printf((fmt) ,##__VA_ARGS__); printf("\n"); } while(0)

#include "../routing.c"
#include "../gossip_store.c"
#include "../broadcast.c"

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire_channel_announcement */
bool fromwire_channel_announcement(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, secp256k1_ecdsa_signature *node_signature_1 UNNEEDED, secp256k1_ecdsa_signature *node_signature_2 UNNEEDED, secp256k1_ecdsa_signature *bitcoin_signature_1 UNNEEDED, secp256k1_ecdsa_signature *bitcoin_signature_2 UNNEEDED, u8 **features UNNEEDED, struct bitcoin_blkid *chain_hash UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED, struct node_id *node_id_1 UNNEEDED, struct node_id *node_id_2 UNNEEDED, struct pubkey *bitcoin_key_1 UNNEEDED, struct pubkey *bitcoin_key_2 UNNEEDED)
{ fprintf(stderr, "fromwire_channel_announcement called!\n"); abort(); }
/* Generated stub for fromwire_channel_update */
bool fromwire_channel_update(const void *p UNNEEDED, secp256k1_ecdsa_signature *signature UNNEEDED, struct bitcoin_blkid *chain_hash UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED, u32 *timestamp UNNEEDED, u8 *message_flags UNNEEDED, u8 *channel_flags UNNEEDED, u16 *cltv_expiry_delta UNNEEDED, struct amount_msat *htlc_minimum_msat UNNEEDED, u32 *fee_base_msat UNNEEDED, u32 *fee_proportional_millionths UNNEEDED)
{ fprintf(stderr, "fromwire_channel_update called!\n"); abort(); }
/* Generated stub for fromwire_channel_update_option_channel_htlc_max */
bool fromwire_channel_update_option_channel_htlc_max(const void *p UNNEEDED, secp256k1_ecdsa_signature *signature UNNEEDED, struct bitcoin_blkid *chain_hash UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED, u32 *timestamp UNNEEDED, u8 *message_flags UNNEEDED, u8 *channel_flags UNNEEDED, u16 *cltv_expiry_delta UNNEEDED, struct amount_msat *htlc_minimum_msat UNNEEDED, u32 *fee_base_msat UNNEEDED, u32 *fee_proportional_millionths UNNEEDED, struct amount_msat *htlc_maximum_msat UNNEEDED)
{ fprintf(stderr, "fromwire_channel_update_option_channel_htlc_max called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_local_add_channel */
bool fromwire_gossipd_local_add_channel(const void *p UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED, struct node_id *remote_node_id UNNEEDED, struct amount_sat *satoshis UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_local_add_channel called!\n"); abort(); }
/* Generated stub for fromwire_gossip_store_channel_amount */
bool fromwire_gossip_store_channel_amount(const void *p UNNEEDED, struct amount_sat *satoshis UNNEEDED)
{ fprintf(stderr, "fromwire_gossip_store_channel_amount called!\n"); abort(); }
/* Generated stub for fromwire_gossip_store_private_update */
bool fromwire_gossip_store_private_update(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, u8 **update UNNEEDED)
{ fprintf(stderr, "fromwire_gossip_store_private_update called!\n"); abort(); }
/* Generated stub for fromwire_node_announcement */
bool fromwire_node_announcement(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, secp256k1_ecdsa_signature *signature UNNEEDED, u8 **features UNNEEDED, u32 *timestamp UNNEEDED, struct node_id *node_id UNNEEDED, u8 rgb_color[3] UNNEEDED, u8 alias[32] UNNEEDED, u8 **addresses UNNEEDED)
{ fprintf(stderr, "fromwire_node_announcement called!\n"); abort(); }
/* Generated stub for fromwire_peektype */
int fromwire_peektype(const u8 *cursor UNNEEDED)
{ fprintf(stderr, "fromwire_peektype called!\n"); abort(); }
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
/* Generated stub for fromwire_wireaddr */
bool fromwire_wireaddr(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct wireaddr *addr UNNEEDED)
{ fprintf(stderr, "fromwire_wireaddr called!\n"); abort(); }
/* Generated stub for gossip_store_read */
u8 *gossip_store_read(const tal_t *ctx UNNEEDED, int gossip_store_fd UNNEEDED, u64 offset UNNEEDED)
{ fprintf(stderr, "gossip_store_read called!\n"); abort(); }
/* Generated stub for onion_type_name */
const char *onion_type_name(int e UNNEEDED)
{ fprintf(stderr, "onion_type_name called!\n"); abort(); }
/* Generated stub for sanitize_error */
char *sanitize_error(const tal_t *ctx UNNEEDED, const u8 *errmsg UNNEEDED,
		     struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "sanitize_error called!\n"); abort(); }
/* Generated stub for status_failed */
void status_failed(enum status_failreason code UNNEEDED,
		   const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "status_failed called!\n"); abort(); }
/* Generated stub for towire_errorfmt */
u8 *towire_errorfmt(const tal_t *ctx UNNEEDED,
		    const struct channel_id *channel UNNEEDED,
		    const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "towire_errorfmt called!\n"); abort(); }
/* Generated stub for towire_gossipd_local_add_channel */
u8 *towire_gossipd_local_add_channel(const tal_t *ctx UNNEEDED, const struct short_channel_id *short_channel_id UNNEEDED, const struct node_id *remote_node_id UNNEEDED, struct amount_sat satoshis UNNEEDED)
{ fprintf(stderr, "towire_gossipd_local_add_channel called!\n"); abort(); }
/* Generated stub for towire_gossip_store_channel_amount */
u8 *towire_gossip_store_channel_amount(const tal_t *ctx UNNEEDED, struct amount_sat satoshis UNNEEDED)
{ fprintf(stderr, "towire_gossip_store_channel_amount called!\n"); abort(); }
/* Generated stub for towire_gossip_store_private_update */
u8 *towire_gossip_store_private_update(const tal_t *ctx UNNEEDED, const u8 *update UNNEEDED)
{ fprintf(stderr, "towire_gossip_store_private_update called!\n"); abort(); }
/* Generated stub for update_peers_broadcast_index */
void update_peers_broadcast_index(struct list_head *peers UNNEEDED, u32 offset UNNEEDED)
{ fprintf(stderr, "update_peers_broadcast_index called!\n"); abort(); }
/* Generated stub for wire_type_name */
const char *wire_type_name(int e UNNEEDED)
{ fprintf(stderr, "wire_type_name called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

#if DEVELOPER
/* Generated stub for memleak_remove_htable */
void memleak_remove_htable(struct htable *memtable UNNEEDED, const struct htable *ht UNNEEDED)
{ fprintf(stderr, "memleak_remove_htable called!\n"); abort(); }
/* Generated stub for memleak_remove_intmap_ */
void memleak_remove_intmap_(struct htable *memtable UNNEEDED, const struct intmap *m UNNEEDED)
{ fprintf(stderr, "memleak_remove_intmap_ called!\n"); abort(); }
#endif

const void *trc;

static struct half_chan *
get_or_make_connection(struct routing_state *rstate,
		       const struct node_id *from_id,
		       const struct node_id *to_id,
		       const char *shortid,
		       struct amount_sat satoshis)
{
	struct short_channel_id scid;
	struct chan *chan;
	const int idx = node_id_idx(from_id, to_id);

	if (!short_channel_id_from_str(shortid, strlen(shortid), &scid,
				       false))
		abort();
	chan = get_channel(rstate, &scid);
	if (!chan)
		chan = new_chan(rstate, &scid, from_id, to_id, satoshis);

	/* Make sure it's seen as initialized (index non-zero). */
	chan->half[idx].bcast.index = 1;
	chan->half[idx].htlc_minimum = AMOUNT_MSAT(0);
	if (!amount_sat_to_msat(&chan->half[idx].htlc_maximum, satoshis))
		abort();

	return &chan->half[idx];
}

static bool channel_is_between(const struct chan *chan,
			       const struct node_id *a, const struct node_id *b)
{
	if (node_id_eq(&chan->nodes[0]->id, a)
	    && node_id_eq(&chan->nodes[1]->id, b))
		return true;

	if (node_id_eq(&chan->nodes[0]->id, b)
	    && node_id_eq(&chan->nodes[1]->id, a))
		return true;

	return false;
}

int main(void)
{
	setup_locale();

	struct half_chan *nc;
	struct routing_state *rstate;
	struct node_id a, b, c, d;
	struct amount_msat fee;
	struct chan **route;
	const double riskfactor = 1.0 / BLOCKS_PER_YEAR / 10000;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	setup_tmpctx();

	node_id_from_hexstr("03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf",
			   strlen("03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf"),
			   &a);
	node_id_from_hexstr("0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae",
			   strlen("0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae"),
			   &b);
	node_id_from_hexstr("02ea622d5c8d6143f15ed3ce1d501dd0d3d09d3b1c83a44d0034949f8a9ab60f06",
			   strlen("02ea622d5c8d6143f15ed3ce1d501dd0d3d09d3b1c83a44d0034949f8a9ab60f06"),
			   &c);
	node_id_from_hexstr("02cca6c5c966fcf61d121e3a70e03a1cd9eeeea024b26ea666ce974d43b242e636",
			   strlen("02cca6c5c966fcf61d121e3a70e03a1cd9eeeea024b26ea666ce974d43b242e636"),
			   &d);

	rstate = new_routing_state(tmpctx, NULL, &a, 0, NULL, NULL);

	/* [{'active': True, 'short_id': '6990:2:1/1', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 1, 'destination': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'source': '02ea622d5c8d6143f15ed3ce1d501dd0d3d09d3b1c83a44d0034949f8a9ab60f06', 'last_update': 1504064344}, */

	nc = get_or_make_connection(rstate, &c, &b, "6990x2x1", AMOUNT_SAT(1000));
	nc->base_fee = 0;
	nc->proportional_fee = 10;
	nc->delay = 5;
	nc->channel_flags = 1;
	nc->message_flags = 0;
	nc->bcast.timestamp = 1504064344;

	/* {'active': True, 'short_id': '6989:2:1/0', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 0, 'destination': '03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf', 'source': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'last_update': 1504064344}, */
	nc = get_or_make_connection(rstate, &b, &a, "6989x2x1", AMOUNT_SAT(1000));
	nc->base_fee = 0;
	nc->proportional_fee = 10;
	nc->delay = 5;
	nc->channel_flags = 0;
	nc->message_flags = 0;
	nc->bcast.timestamp = 1504064344;

	/* {'active': True, 'short_id': '6990:2:1/0', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 0, 'destination': '02ea622d5c8d6143f15ed3ce1d501dd0d3d09d3b1c83a44d0034949f8a9ab60f06', 'source': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'last_update': 1504064344}, */
	nc = get_or_make_connection(rstate, &b, &c, "6990x2x1", AMOUNT_SAT(1000));
	nc->base_fee = 0;
	nc->proportional_fee = 10;
	nc->delay = 5;
	nc->channel_flags = 0;
	nc->message_flags = 0;
	nc->bcast.timestamp = 1504064344;
	nc->htlc_minimum = AMOUNT_MSAT(100);

	/* {'active': True, 'short_id': '6989:2:1/1', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 0, 'channel_flags': 1, 'destination': '0230ad0e74ea03976b28fda587bb75bdd357a1938af4424156a18265167f5e40ae', 'source': '03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf', 'last_update': 1504064344}]} */
	nc = get_or_make_connection(rstate, &a, &b, "6989x2x1", AMOUNT_SAT(1000));
	nc->base_fee = 0;
	nc->proportional_fee = 10;
	nc->delay = 5;
	nc->channel_flags = 1;
	nc->message_flags = 0;
	nc->bcast.timestamp = 1504064344;

	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(100000), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(route);
	assert(tal_count(route) == 2);
	assert(channel_is_between(route[0], &a, &b));
	assert(channel_is_between(route[1], &b, &c));


	/* We should not be able to find a route that exceeds our own capacity */
	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(1000001), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(!route);

	/* Now test with a query that exceeds the channel capacity after adding
	 * some fees */
	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(999999), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(!route);

	/* This should fail to return a route because it is smaller than these
	 * htlc_minimum_msat on the last channel. */
	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(1), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(!route);

	/* {'active': True, 'short_id': '6990:2:1/0', 'fee_per_kw': 10, 'delay': 5, 'message_flags': 1, 'htlc_maximum_msat': 500000, 'htlc_minimum_msat': 100, 'channel_flags': 0, 'destination': '02cca6c5c966fcf61d121e3a70e03a1cd9eeeea024b26ea666ce974d43b242e636', 'source': '03c173897878996287a8100469f954dd820fcd8941daed91c327f168f3329be0bf', 'last_update': 1504064344}, */
	nc = get_or_make_connection(rstate, &a, &d, "6991x2x1", AMOUNT_SAT(1000));
	nc->base_fee = 0;
	nc->proportional_fee = 0;
	nc->delay = 5;
	nc->channel_flags = 0;
	nc->message_flags = 1;
	nc->bcast.timestamp = 1504064344;
	nc->htlc_minimum = AMOUNT_MSAT(100);
	nc->htlc_maximum = AMOUNT_MSAT(500000); /* half capacity */

	/* This should route correctly at the max_msat level */
	route = find_route(tmpctx, rstate, &a, &d, AMOUNT_MSAT(500000), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(route);

	/* This should fail to return a route because it's larger than the
	 * htlc_maximum_msat on the last channel. */
	route = find_route(tmpctx, rstate, &a, &d, AMOUNT_MSAT(500001), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(!route);

	tal_free(tmpctx);
	secp256k1_context_destroy(secp256k1_ctx);
	return 0;
}
