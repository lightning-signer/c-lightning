#include "../routing.c"
#include "../gossip_store.c"
#include "../broadcast.c"
#include <stdio.h>

void status_fmt(enum log_level level UNUSED, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
}

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

static void node_id_from_privkey(const struct privkey *p, struct node_id *id)
{
	struct pubkey k;
	pubkey_from_privkey(p, &k);
	node_id_from_pubkey(id, &k);
}

/* Updates existing route if required. */
static void add_connection(struct routing_state *rstate,
					      const struct node_id *from,
					      const struct node_id *to,
					      u32 base_fee, s32 proportional_fee,
					      u32 delay)
{
	struct short_channel_id scid;
	struct half_chan *c;
	struct chan *chan;
	struct amount_sat satoshis = AMOUNT_SAT(100000);

	/* Make a unique scid. */
	memcpy(&scid, from, sizeof(scid) / 2);
	memcpy((char *)&scid + sizeof(scid) / 2, to, sizeof(scid) / 2);

	chan = get_channel(rstate, &scid);
	if (!chan)
		chan = new_chan(rstate, &scid, from, to, satoshis);

	c = &chan->half[node_id_idx(from, to)];
	/* Make sure it's seen as initialized (index non-zero). */
	c->bcast.index = 1;
	c->base_fee = base_fee;
	c->proportional_fee = proportional_fee;
	c->delay = delay;
	c->channel_flags = node_id_idx(from, to);
	c->htlc_minimum = AMOUNT_MSAT(0);
	c->htlc_maximum = AMOUNT_MSAT(100000 * 1000);
}

/* Returns chan connecting from and to: *idx set to refer
 * to connection with src=from, dst=to */
static struct chan *find_channel(struct routing_state *rstate UNUSED,
					    const struct node *from,
					    const struct node *to,
					    int *idx)
{
	struct chan_map_iter i;
	struct chan *c;

	*idx = node_id_idx(&from->id, &to->id);

	for (c = first_chan(to, &i); c; c = next_chan(to, &i)) {
		if (c->nodes[*idx] == from)
			return c;
	}
	return NULL;
}

static struct half_chan *get_connection(struct routing_state *rstate,
					       const struct node_id *from_id,
					       const struct node_id *to_id)
{
	int idx;
	struct node *from, *to;
	struct chan *c;

	from = get_node(rstate, from_id);
	to = get_node(rstate, to_id);
	if (!from || ! to)
		return NULL;

	c = find_channel(rstate, from, to, &idx);
	if (!c)
		return NULL;
	return &c->half[idx];
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

	struct routing_state *rstate;
	struct node_id a, b, c, d;
	struct privkey tmp;
	struct amount_msat fee;
	struct chan **route;
	const double riskfactor = 1.0 / BLOCKS_PER_YEAR / 10000;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	setup_tmpctx();

	memset(&tmp, 'a', sizeof(tmp));
	node_id_from_privkey(&tmp, &a);
	rstate = new_routing_state(tmpctx, NULL, &a, 0, NULL, NULL);

	new_node(rstate, &a);

	memset(&tmp, 'b', sizeof(tmp));
	node_id_from_privkey(&tmp, &b);
	new_node(rstate, &b);

	/* A<->B */
	add_connection(rstate, &a, &b, 1, 1, 1);

	route = find_route(tmpctx, rstate, &a, &b, AMOUNT_MSAT(1000), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(route);
	assert(tal_count(route) == 1);
	assert(amount_msat_eq(fee, AMOUNT_MSAT(0)));

	/* A<->B<->C */
	memset(&tmp, 'c', sizeof(tmp));
	node_id_from_privkey(&tmp, &c);
	new_node(rstate, &c);

	status_trace("A = %s", type_to_string(tmpctx, struct node_id, &a));
	status_trace("B = %s", type_to_string(tmpctx, struct node_id, &b));
	status_trace("C = %s", type_to_string(tmpctx, struct node_id, &c));
	add_connection(rstate, &b, &c, 1, 1, 1);

	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(1000), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(route);
	assert(tal_count(route) == 2);
	assert(amount_msat_eq(fee, AMOUNT_MSAT(1)));

	/* A<->D<->C: Lower base, higher percentage. */
	memset(&tmp, 'd', sizeof(tmp));
	node_id_from_privkey(&tmp, &d);
	new_node(rstate, &d);
	status_trace("D = %s", type_to_string(tmpctx, struct node_id, &d));

	add_connection(rstate, &a, &d, 0, 2, 1);
	add_connection(rstate, &d, &c, 0, 2, 1);

	/* Will go via D for small amounts. */
	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(1000), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(route);
	assert(tal_count(route) == 2);
	assert(channel_is_between(route[0], &a, &d));
	assert(channel_is_between(route[1], &d, &c));
	assert(amount_msat_eq(fee, AMOUNT_MSAT(0)));

	/* Will go via B for large amounts. */
	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(3000000), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(route);
	assert(tal_count(route) == 2);
	assert(channel_is_between(route[0], &a, &b));
	assert(channel_is_between(route[1], &b, &c));
	assert(amount_msat_eq(fee, AMOUNT_MSAT(1 + 3)));

	/* Make B->C inactive, force it back via D */
	get_connection(rstate, &b, &c)->channel_flags |= ROUTING_FLAGS_DISABLED;
	route = find_route(tmpctx, rstate, &a, &c, AMOUNT_MSAT(3000000), riskfactor, 0.0, NULL,
			   ROUTING_MAX_HOPS, &fee);
	assert(route);
	assert(tal_count(route) == 2);
	assert(channel_is_between(route[0], &a, &d));
	assert(channel_is_between(route[1], &d, &c));
	assert(amount_msat_eq(fee, AMOUNT_MSAT(0 + 6)));

	tal_free(tmpctx);
	secp256k1_context_destroy(secp256k1_ctx);
	return 0;
}
