#include "config.h"
#include "plugins/channel_hint.h"
#define TESTING
#include "../../common/dijkstra.c"
#include "../libplugin-pay.c"
#include <bitcoin/chainparams.h>
#include <ccan/crc32c/crc32c.h>
#include <common/gossip_store.h>
#include <common/setup.h>
#include <common/utils.h>
#include <gossipd/gossip_store_wiregen.h>
#include <stdio.h>
#include <unistd.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for aux_command */
struct command *aux_command(const struct command *cmd)

{ fprintf(stderr, "aux_command called!\n"); abort(); }
/* Generated stub for blinded_onion_hops */
u8 **blinded_onion_hops(const tal_t *ctx UNNEEDED,
			struct amount_msat final_amount UNNEEDED,
			u32 final_cltv UNNEEDED,
			struct amount_msat total_amount UNNEEDED,
			const struct blinded_path *path UNNEEDED)
{ fprintf(stderr, "blinded_onion_hops called!\n"); abort(); }
/* Generated stub for command_finished */
struct command_result *command_finished(struct command *cmd UNNEEDED, struct json_stream *response)

{ fprintf(stderr, "command_finished called!\n"); abort(); }
/* Generated stub for command_still_pending */
struct command_result *command_still_pending(struct command *cmd)

{ fprintf(stderr, "command_still_pending called!\n"); abort(); }
/* Generated stub for daemon_poll */
int daemon_poll(struct pollfd *fds UNNEEDED, nfds_t nfds UNNEEDED, int timeout UNNEEDED)
{ fprintf(stderr, "daemon_poll called!\n"); abort(); }
/* Generated stub for feature_offered */
bool feature_offered(const u8 *features UNNEEDED, size_t f UNNEEDED)
{ fprintf(stderr, "feature_offered called!\n"); abort(); }
/* Generated stub for fromwire_bigsize */
bigsize_t fromwire_bigsize(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bigsize called!\n"); abort(); }
/* Generated stub for fromwire_channel_id */
bool fromwire_channel_id(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
			 struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "fromwire_channel_id called!\n"); abort(); }
/* Generated stub for gossmod_add_localchan */
void gossmod_add_localchan(struct gossmap_localmods *mods UNNEEDED,
			   const struct node_id *self UNNEEDED,
			   const struct node_id *peer UNNEEDED,
			   const struct short_channel_id_dir *scidd UNNEEDED,
			   struct amount_msat capacity_msat UNNEEDED,
			   struct amount_msat htlcmin UNNEEDED,
			   struct amount_msat htlcmax UNNEEDED,
			   struct amount_msat spendable UNNEEDED,
			   struct amount_msat total_htlcmax UNNEEDED,
			   struct amount_msat fee_base UNNEEDED,
			   u32 fee_proportional UNNEEDED,
			   u16 cltv_delta UNNEEDED,
			   bool enabled UNNEEDED,
			   const char *buf UNUSED UNNEEDED,
			   const jsmntok_t *chantok UNUSED UNNEEDED,
			   void *cbarg UNUSED UNNEEDED)
{ fprintf(stderr, "gossmod_add_localchan called!\n"); abort(); }
/* Generated stub for gossmods_from_listpeerchannels_ */
struct gossmap_localmods *gossmods_from_listpeerchannels_(const tal_t *ctx UNNEEDED,
							  const struct node_id *self UNNEEDED,
							  const char *buf UNNEEDED,
							  const jsmntok_t *toks UNNEEDED,
							  bool zero_rates UNNEEDED,
							  void (*cb)(struct gossmap_localmods *mods UNNEEDED,
								     const struct node_id *self_ UNNEEDED,
								     const struct node_id *peer UNNEEDED,
								     const struct short_channel_id_dir *scidd UNNEEDED,
								     struct amount_msat capacity_msat UNNEEDED,
								     struct amount_msat htlcmin UNNEEDED,
								     struct amount_msat htlcmax UNNEEDED,
								     struct amount_msat spendable UNNEEDED,
								     struct amount_msat total_htlcmax UNNEEDED,
								     struct amount_msat fee_base UNNEEDED,
								     u32 fee_proportional UNNEEDED,
								     u16 cltv_delta UNNEEDED,
								     bool enabled UNNEEDED,
								     const char *buf_ UNNEEDED,
								     const jsmntok_t *chantok UNNEEDED,
								     void *cbarg_) UNNEEDED,
							  void *cbarg UNNEEDED)
{ fprintf(stderr, "gossmods_from_listpeerchannels_ called!\n"); abort(); }
/* Generated stub for json_add_amount_msat */
void json_add_amount_msat(struct json_stream *result UNNEEDED,
			  const char *msatfieldname UNNEEDED,
			  struct amount_msat msat)

{ fprintf(stderr, "json_add_amount_msat called!\n"); abort(); }
/* Generated stub for json_add_bool */
void json_add_bool(struct json_stream *result UNNEEDED, const char *fieldname UNNEEDED,
		   bool value UNNEEDED)
{ fprintf(stderr, "json_add_bool called!\n"); abort(); }
/* Generated stub for json_add_hex_talarr */
void json_add_hex_talarr(struct json_stream *result UNNEEDED,
			 const char *fieldname UNNEEDED,
			 const tal_t *data UNNEEDED)
{ fprintf(stderr, "json_add_hex_talarr called!\n"); abort(); }
/* Generated stub for json_add_invstring */
void json_add_invstring(struct json_stream *result UNNEEDED, const char *invstring UNNEEDED)
{ fprintf(stderr, "json_add_invstring called!\n"); abort(); }
/* Generated stub for json_add_node_id */
void json_add_node_id(struct json_stream *response UNNEEDED,
				const char *fieldname UNNEEDED,
				const struct node_id *id UNNEEDED)
{ fprintf(stderr, "json_add_node_id called!\n"); abort(); }
/* Generated stub for json_add_num */
void json_add_num(struct json_stream *result UNNEEDED, const char *fieldname UNNEEDED,
		  unsigned int value UNNEEDED)
{ fprintf(stderr, "json_add_num called!\n"); abort(); }
/* Generated stub for json_add_preimage */
void json_add_preimage(struct json_stream *result UNNEEDED, const char *fieldname UNNEEDED,
		     const struct preimage *preimage UNNEEDED)
{ fprintf(stderr, "json_add_preimage called!\n"); abort(); }
/* Generated stub for json_add_secret */
void json_add_secret(struct json_stream *response UNNEEDED,
		     const char *fieldname UNNEEDED,
		     const struct secret *secret UNNEEDED)
{ fprintf(stderr, "json_add_secret called!\n"); abort(); }
/* Generated stub for json_add_sha256 */
void json_add_sha256(struct json_stream *result UNNEEDED, const char *fieldname UNNEEDED,
		     const struct sha256 *hash UNNEEDED)
{ fprintf(stderr, "json_add_sha256 called!\n"); abort(); }
/* Generated stub for json_add_short_channel_id */
void json_add_short_channel_id(struct json_stream *response UNNEEDED,
			       const char *fieldname UNNEEDED,
			       struct short_channel_id id UNNEEDED)
{ fprintf(stderr, "json_add_short_channel_id called!\n"); abort(); }
/* Generated stub for json_add_short_channel_id_dir */
void json_add_short_channel_id_dir(struct json_stream *response UNNEEDED,
				   const char *fieldname UNNEEDED,
				   struct short_channel_id_dir idd UNNEEDED)
{ fprintf(stderr, "json_add_short_channel_id_dir called!\n"); abort(); }
/* Generated stub for json_add_string */
void json_add_string(struct json_stream *js UNNEEDED,
		     const char *fieldname UNNEEDED,
		     const char *str TAKES UNNEEDED)
{ fprintf(stderr, "json_add_string called!\n"); abort(); }
/* Generated stub for json_add_timeabs */
void json_add_timeabs(struct json_stream *result UNNEEDED, const char *fieldname UNNEEDED,
		      struct timeabs t UNNEEDED)
{ fprintf(stderr, "json_add_timeabs called!\n"); abort(); }
/* Generated stub for json_add_u32 */
void json_add_u32(struct json_stream *result UNNEEDED, const char *fieldname UNNEEDED,
		  uint32_t value UNNEEDED)
{ fprintf(stderr, "json_add_u32 called!\n"); abort(); }
/* Generated stub for json_add_u64 */
void json_add_u64(struct json_stream *result UNNEEDED, const char *fieldname UNNEEDED,
		  uint64_t value UNNEEDED)
{ fprintf(stderr, "json_add_u64 called!\n"); abort(); }
/* Generated stub for json_array_end */
void json_array_end(struct json_stream *js UNNEEDED)
{ fprintf(stderr, "json_array_end called!\n"); abort(); }
/* Generated stub for json_array_start */
void json_array_start(struct json_stream *js UNNEEDED, const char *fieldname UNNEEDED)
{ fprintf(stderr, "json_array_start called!\n"); abort(); }
/* Generated stub for json_get_member */
const jsmntok_t *json_get_member(const char *buffer UNNEEDED, const jsmntok_t tok[] UNNEEDED,
				 const char *label UNNEEDED)
{ fprintf(stderr, "json_get_member called!\n"); abort(); }
/* Generated stub for json_next */
const jsmntok_t *json_next(const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_next called!\n"); abort(); }
/* Generated stub for json_object_end */
void json_object_end(struct json_stream *js UNNEEDED)
{ fprintf(stderr, "json_object_end called!\n"); abort(); }
/* Generated stub for json_object_start */
void json_object_start(struct json_stream *ks UNNEEDED, const char *fieldname UNNEEDED)
{ fprintf(stderr, "json_object_start called!\n"); abort(); }
/* Generated stub for json_scan */
const char *json_scan(const tal_t *ctx UNNEEDED,
		      const char *buffer UNNEEDED,
		      const jsmntok_t *tok UNNEEDED,
		      const char *guide UNNEEDED,
		      ...)
{ fprintf(stderr, "json_scan called!\n"); abort(); }
/* Generated stub for json_strdup */
char *json_strdup(const tal_t *ctx UNNEEDED, const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_strdup called!\n"); abort(); }
/* Generated stub for json_to_bool */
bool json_to_bool(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, bool *b UNNEEDED)
{ fprintf(stderr, "json_to_bool called!\n"); abort(); }
/* Generated stub for json_to_createonion_response */
struct createonion_response *json_to_createonion_response(const tal_t *ctx UNNEEDED,
							  const char *buffer UNNEEDED,
							  const jsmntok_t *toks UNNEEDED)
{ fprintf(stderr, "json_to_createonion_response called!\n"); abort(); }
/* Generated stub for json_to_int */
bool json_to_int(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, int *num UNNEEDED)
{ fprintf(stderr, "json_to_int called!\n"); abort(); }
/* Generated stub for json_to_listpeers_channels */
struct listpeers_channel **json_to_listpeers_channels(const tal_t *ctx UNNEEDED,
						      const char *buffer UNNEEDED,
						      const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_to_listpeers_channels called!\n"); abort(); }
/* Generated stub for json_to_msat */
bool json_to_msat(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		  struct amount_msat *msat UNNEEDED)
{ fprintf(stderr, "json_to_msat called!\n"); abort(); }
/* Generated stub for json_to_node_id */
bool json_to_node_id(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			       struct node_id *id UNNEEDED)
{ fprintf(stderr, "json_to_node_id called!\n"); abort(); }
/* Generated stub for json_to_number */
bool json_to_number(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		    unsigned int *num UNNEEDED)
{ fprintf(stderr, "json_to_number called!\n"); abort(); }
/* Generated stub for json_to_preimage */
bool json_to_preimage(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, struct preimage *preimage UNNEEDED)
{ fprintf(stderr, "json_to_preimage called!\n"); abort(); }
/* Generated stub for json_to_sat */
bool json_to_sat(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		 struct amount_sat *sat UNNEEDED)
{ fprintf(stderr, "json_to_sat called!\n"); abort(); }
/* Generated stub for json_to_short_channel_id */
bool json_to_short_channel_id(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			      struct short_channel_id *scid UNNEEDED)
{ fprintf(stderr, "json_to_short_channel_id called!\n"); abort(); }
/* Generated stub for json_to_short_channel_id_dir */
bool json_to_short_channel_id_dir(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
				  struct short_channel_id_dir *scidd UNNEEDED)
{ fprintf(stderr, "json_to_short_channel_id_dir called!\n"); abort(); }
/* Generated stub for json_to_u16 */
bool json_to_u16(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
                 uint16_t *num UNNEEDED)
{ fprintf(stderr, "json_to_u16 called!\n"); abort(); }
/* Generated stub for json_to_u32 */
bool json_to_u32(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, u32 *num UNNEEDED)
{ fprintf(stderr, "json_to_u32 called!\n"); abort(); }
/* Generated stub for json_to_u64 */
bool json_to_u64(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, u64 *num UNNEEDED)
{ fprintf(stderr, "json_to_u64 called!\n"); abort(); }
/* Generated stub for json_tok_bin_from_hex */
u8 *json_tok_bin_from_hex(const tal_t *ctx UNNEEDED, const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_tok_bin_from_hex called!\n"); abort(); }
/* Generated stub for json_tok_full */
const char *json_tok_full(const char *buffer UNNEEDED, const jsmntok_t *t UNNEEDED)
{ fprintf(stderr, "json_tok_full called!\n"); abort(); }
/* Generated stub for json_tok_full_len */
int json_tok_full_len(const jsmntok_t *t UNNEEDED)
{ fprintf(stderr, "json_tok_full_len called!\n"); abort(); }
/* Generated stub for json_tok_streq */
bool json_tok_streq(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED, const char *str UNNEEDED)
{ fprintf(stderr, "json_tok_streq called!\n"); abort(); }
/* Generated stub for jsonrpc_request_start_ */
struct out_req *jsonrpc_request_start_(struct command *cmd UNNEEDED,
				       const char *method UNNEEDED,
				       const char *id_prefix UNNEEDED,
				       const char *filter UNNEEDED,
				       struct command_result *(*cb)(struct command *command UNNEEDED,
								    const char *methodname UNNEEDED,
								    const char *buf UNNEEDED,
								    const jsmntok_t *result UNNEEDED,
								    void *arg) UNNEEDED,
				       struct command_result *(*errcb)(struct command *command UNNEEDED,
								       const char *methodname UNNEEDED,
								       const char *buf UNNEEDED,
								       const jsmntok_t *result UNNEEDED,
								       void *arg) UNNEEDED,
				       void *arg)

{ fprintf(stderr, "jsonrpc_request_start_ called!\n"); abort(); }
/* Generated stub for jsonrpc_stream_fail */
struct json_stream *jsonrpc_stream_fail(struct command *cmd UNNEEDED,
					int code UNNEEDED,
					const char *err)

{ fprintf(stderr, "jsonrpc_stream_fail called!\n"); abort(); }
/* Generated stub for jsonrpc_stream_success */
struct json_stream *jsonrpc_stream_success(struct command *cmd)

{ fprintf(stderr, "jsonrpc_stream_success called!\n"); abort(); }
/* Generated stub for memleak_add_helper_ */
void memleak_add_helper_(const tal_t *p UNNEEDED, void (*cb)(struct htable *memtable UNNEEDED,
						    const tal_t *)){ }
/* Generated stub for memleak_scan_htable */
void memleak_scan_htable(struct htable *memtable UNNEEDED, const struct htable *ht UNNEEDED)
{ fprintf(stderr, "memleak_scan_htable called!\n"); abort(); }
/* Generated stub for notleak_ */
void *notleak_(void *ptr UNNEEDED, bool plus_children UNNEEDED)
{ fprintf(stderr, "notleak_ called!\n"); abort(); }
/* Generated stub for plugin_err */
void   plugin_err(struct plugin *p UNNEEDED, const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "plugin_err called!\n"); abort(); }
/* Generated stub for plugin_gossmap_logcb */
void plugin_gossmap_logcb(struct plugin *plugin UNNEEDED,
			  enum log_level level UNNEEDED,
			  const char *fmt UNNEEDED,
			  ...)
{ fprintf(stderr, "plugin_gossmap_logcb called!\n"); abort(); }
/* Generated stub for plugin_log */
void plugin_log(struct plugin *p UNNEEDED, enum log_level l UNNEEDED, const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "plugin_log called!\n"); abort(); }
/* Generated stub for plugin_notification_end */
void plugin_notification_end(struct plugin *plugin UNNEEDED,
			     struct json_stream *stream TAKES UNNEEDED)
{ fprintf(stderr, "plugin_notification_end called!\n"); abort(); }
/* Generated stub for plugin_notification_start */
struct json_stream *plugin_notification_start(struct plugin *plugins UNNEEDED,
					      const char *method UNNEEDED)
{ fprintf(stderr, "plugin_notification_start called!\n"); abort(); }
/* Generated stub for plugin_notify_message */
void plugin_notify_message(struct command *cmd UNNEEDED,
			   enum log_level level UNNEEDED,
			   const char *fmt UNNEEDED, ...)

{ fprintf(stderr, "plugin_notify_message called!\n"); abort(); }
/* Generated stub for random_select */
bool random_select(double weight UNNEEDED, double *tot_weight UNNEEDED)
{ fprintf(stderr, "random_select called!\n"); abort(); }
/* Generated stub for send_outreq */
struct command_result *send_outreq(const struct out_req *req UNNEEDED)
{ fprintf(stderr, "send_outreq called!\n"); abort(); }
/* Generated stub for towire_bigsize */
void towire_bigsize(u8 **pptr UNNEEDED, const bigsize_t val UNNEEDED)
{ fprintf(stderr, "towire_bigsize called!\n"); abort(); }
/* Generated stub for towire_channel_id */
void towire_channel_id(u8 **pptr UNNEEDED, const struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "towire_channel_id called!\n"); abort(); }
/* Generated stub for trace_span_end */
void trace_span_end(const void *key UNNEEDED)
{ fprintf(stderr, "trace_span_end called!\n"); abort(); }
/* Generated stub for trace_span_start */
void trace_span_start(const char *name UNNEEDED, const void *key UNNEEDED)
{ fprintf(stderr, "trace_span_start called!\n"); abort(); }
/* Generated stub for trace_span_tag */
void trace_span_tag(const void *key UNNEEDED, const char *name UNNEEDED, const char *value UNNEEDED)
{ fprintf(stderr, "trace_span_tag called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

static void write_to_store(int store_fd, const u8 *msg)
{
	struct gossip_hdr hdr;

	hdr.flags = cpu_to_be16(0);
	hdr.len = cpu_to_be16(tal_count(msg));
	hdr.timestamp = 0;
	hdr.crc = cpu_to_be32(crc32c(be32_to_cpu(hdr.timestamp), msg, tal_count(msg)));
	assert(write(store_fd, &hdr, sizeof(hdr)) == sizeof(hdr));
	assert(write(store_fd, msg, tal_count(msg)) == tal_count(msg));
}

static void update_connection(int store_fd,
			      const struct node_id *from,
			      const struct node_id *to,
			      struct short_channel_id scid,
			      struct amount_msat min,
			      struct amount_msat max,
			      u32 base_fee, s32 proportional_fee,
			      u32 delay,
			      bool disable)
{
	secp256k1_ecdsa_signature dummy_sig;
	u8 flags = node_id_idx(from, to);
	u8 *msg;

	if (disable)
		flags |= ROUTING_FLAGS_DISABLED;

	/* So valgrind doesn't complain */
	memset(&dummy_sig, 0, sizeof(dummy_sig));

	msg = towire_channel_update(tmpctx,
				    &dummy_sig,
				    &chainparams->genesis_blockhash,
				    scid, 0,
				    ROUTING_OPT_HTLC_MAX_MSAT,
				    flags,
				    delay,
				    min,
				    base_fee,
				    proportional_fee,
				    max);

	write_to_store(store_fd, msg);
}

static void node_id(char n, struct node_id *id)
{
	struct privkey p;
	struct pubkey k;
	memset(&p, n, sizeof(p));
	pubkey_from_privkey(&p, &k);
	node_id_from_pubkey(id, &k);
}

static struct short_channel_id_dir add_connection(int store_fd, char from, char to,
						  u32 base_fee,
						  s32 proportional_fee,
						  u32 delay,
						  struct amount_sat capacity)
{
	secp256k1_ecdsa_signature dummy_sig;
	struct secret not_a_secret;
	struct pubkey dummy_key;
	u8 *msg;
	struct node_id from_id, to_id;
	const struct node_id *ids[2];
	static struct short_channel_id_dir scidd;

	/* So valgrind doesn't complain */
	memset(&dummy_sig, 0, sizeof(dummy_sig));
	memset(&not_a_secret, 1, sizeof(not_a_secret));
	pubkey_from_secret(&not_a_secret, &dummy_key);

	node_id(from, &from_id);
	node_id(to, &to_id);

	if (node_id_cmp(&from_id, &to_id) > 0) {
		scidd.dir = 1;
		ids[0] = &to_id;
		ids[1] = &from_id;
	} else {
		scidd.dir = 0;
		ids[0] = &from_id;
		ids[1] = &to_id;
	}
	scidd.scid.u64++;
	msg = towire_channel_announcement(tmpctx, &dummy_sig, &dummy_sig,
					  &dummy_sig, &dummy_sig,
					  /* features */ NULL,
					  &chainparams->genesis_blockhash,
					  scidd.scid,
					  ids[0], ids[1],
					  &dummy_key, &dummy_key);
	write_to_store(store_fd, msg);
	msg = towire_gossip_store_channel_amount(tmpctx, capacity);
	write_to_store(store_fd, msg);

	update_connection(store_fd, &from_id, &to_id, scidd.scid,
			  AMOUNT_MSAT(0),
			  amount_msat(capacity.satoshis * 1000),
			  base_fee, proportional_fee,
			  delay, false);
	return scidd;
}

/* A -> B -> C -> D -> E
 *
 * Each node has two channels with the next, one has worse characteristics.
 */
int main(int argc, char *argv[])
{
	struct payment *p;
	struct payment_modifier **mods;
	struct channel_hint_set *hints;

	common_setup(argv[0]);
	chainparams = chainparams_for_network("regtest");
	hints = channel_hint_set_new(tmpctx);

	mods = tal_arrz(tmpctx, struct payment_modifier *, 1);
	p = payment_new(mods, tal(tmpctx, struct command), NULL, hints, mods);

	/* We want to permute order of channels between each node, to
	 * avoid "it works because it chooses the first one!" */
	for (size_t i = 0; i < 2; i++) {
		const char gossip_version = 10;
		struct gossmap *gossmap;
		char *gossipfilename;
		int store_fd;
		struct short_channel_id_dir scids[2], path[4];
		struct route_hop *r;
		struct node_id src, dst;
		const struct dijkstra *dij;
		const char *errmsg;
		u32 risk_factor = 10;

		store_fd = tmpdir_mkstemp(tmpctx, "run-route-calc.XXXXXX",
					  &gossipfilename);
		assert(write(store_fd, &gossip_version, sizeof(gossip_version))
		       == sizeof(gossip_version));

		/* Cheap base vs expensive base */
		scids[0] = add_connection(store_fd, 'A', 'B',
					  1000 * !i,
					  100,
					  1,
					  AMOUNT_SAT(100000000));
		scids[1] = add_connection(store_fd, 'A', 'B',
					  1000 * !!i,
					  100,
					  1,
					  AMOUNT_SAT(100000000));
		path[0] = scids[!i];

		/* Cheap proportion vs expensive proportion */
		scids[0] = add_connection(store_fd, 'B', 'C',
					  1000,
					  100 * !i,
					  1,
					  AMOUNT_SAT(100000000));
		scids[1] = add_connection(store_fd, 'B', 'C',
					  1000,
					  100 * !!i,
					  1,
					  AMOUNT_SAT(100000000));
		path[1] = scids[!i];

		/* Low delay vs high delay */
		scids[0] = add_connection(store_fd, 'C', 'D',
					  1000,
					  100,
					  10 * !i,
					  AMOUNT_SAT(100000000));
		scids[1] = add_connection(store_fd, 'C', 'D',
					  1000,
					  100,
					  10 * !!i,
					  AMOUNT_SAT(100000000));
		path[2] = scids[!i];

		/* High capacity vs low capacity */
		scids[0] = add_connection(store_fd, 'D', 'E',
					  1000,
					  100,
					  1,
					  amount_sat(100 + 100000000 * !!i));
		scids[1] = add_connection(store_fd, 'D', 'E',
					  1000,
					  100,
					  1,
					  amount_sat(100 + 100000000 * !i));
		path[3] = scids[!i];

		gossmap = gossmap_load(tmpctx, gossipfilename, NULL, NULL);
		global_gossmap = gossmap;

		node_id('A', &src);
		node_id('E', &dst);

		/* First check high level code gives correct answer */
		r = route(tmpctx, gossmap,
			  gossmap_find_node(gossmap, &src),
			  gossmap_find_node(gossmap, &dst),
			  /* 80 sats: should bias us against 100 sat channel */
			  AMOUNT_MSAT(80000),
			  /* Final delay */
			  22,
			  risk_factor,
			  /* Max hops */
			  ARRAY_SIZE(path) + 1,
			  p,
			  &errmsg);

		assert(r);
		assert(errmsg == NULL);
		assert(tal_count(r) == ARRAY_SIZE(path));

		for (size_t j = 0; j < ARRAY_SIZE(path); j++) {
			assert(short_channel_id_eq(r[j].scid, path[j].scid));
			assert(r[j].direction == path[j].dir);
		}

		/* Now check Dijkstra directly */
		dij = dijkstra(tmpctx, gossmap, gossmap_find_node(gossmap, &dst),
			       AMOUNT_MSAT(80000),
			       risk_factor,
			       payment_route_can_carry, route_score, p);

		/* It's a line, distances should decrement */
		assert(dijkstra_distance(dij, 0) == 4);
		assert(dijkstra_distance(dij, 1) == 3);
		assert(dijkstra_distance(dij, 2) == 2);
		assert(dijkstra_distance(dij, 3) == 1);
		assert(dijkstra_distance(dij, 4) == 0);

		/* Cost should climb as we go. */
		struct amount_msat amount = AMOUNT_MSAT(80000);
		assert(amount_msat_eq(dij[4].amount, amount));
		assert(amount_msat_add_fee(&amount, 1000, 100));
		assert(amount_msat_eq(dij[3].amount, amount));
		assert(amount_msat_add_fee(&amount, 1000, 100));
		assert(amount_msat_eq(dij[2].amount, amount));
		assert(amount_msat_add_fee(&amount, 1000, 0));
		assert(amount_msat_eq(dij[1].amount, amount));
		assert(amount_msat_add_fee(&amount, 0, 100));
		assert(amount_msat_eq(dij[0].amount, amount));

		/* Similarly, score should climb as we go */
		u64 score = 0;
		struct amount_msat fee;
		assert(dij[4].score == score);
		assert(amount_msat_fee(&fee, dij[3].amount, 1000, 100));
		score += route_score(fee,
				     risk_price(dij[3].amount, risk_factor, 1),
				     dij[3].amount,
				     path[3].dir,
				     gossmap_find_chan(gossmap, &path[3].scid));
		assert(dij[3].score == score);
		assert(amount_msat_fee(&fee, dij[2].amount, 1000, 100));
		score += route_score(fee,
				     risk_price(dij[2].amount, risk_factor, 1),
				     dij[2].amount,
				     path[2].dir,
				     gossmap_find_chan(gossmap, &path[2].scid));
		assert(dij[2].score == score);
		assert(amount_msat_fee(&fee, dij[1].amount, 1000, 0));
		score += route_score(fee,
				     risk_price(dij[1].amount, risk_factor, 0),
				     dij[1].amount,
				     path[1].dir,
				     gossmap_find_chan(gossmap, &path[1].scid));
		assert(dij[1].score == score);
		assert(amount_msat_fee(&fee, dij[0].amount, 0, 100));
		score += route_score(fee,
				     risk_price(dij[0].amount, risk_factor, 1),
				     dij[0].amount,
				     path[0].dir,
				     gossmap_find_chan(gossmap, &path[0].scid));
		assert(dij[0].score == score);
	}

	common_shutdown();
	return 0;
}
