#include "config.h"
#include "../bigsize.c"
#include "../json_parse.c"
#include "../json_parse_simple.c"
#include "../onion_decode.c"
#include "../sphinx.c"
#include "../hmac.c"
#include "../type_to_string.c"
#include "../../wire/towire.c"
#include "../../wire/fromwire.c"
#include "../../wire/onion_wiregen.c"
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <common/channel_id.h>
#include <common/json_stream.h>
#include <common/setup.h>
#include <common/wireaddr.h>
#include <stdio.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for amount_asset_is_main */
bool amount_asset_is_main(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_is_main called!\n"); abort(); }
/* Generated stub for amount_asset_to_sat */
struct amount_sat amount_asset_to_sat(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_to_sat called!\n"); abort(); }
/* Generated stub for amount_msat */
struct amount_msat amount_msat(u64 millisatoshis UNNEEDED)
{ fprintf(stderr, "amount_msat called!\n"); abort(); }
/* Generated stub for amount_msat_less */
bool amount_msat_less(struct amount_msat a UNNEEDED, struct amount_msat b UNNEEDED)
{ fprintf(stderr, "amount_msat_less called!\n"); abort(); }
/* Generated stub for amount_sat */
struct amount_sat amount_sat(u64 satoshis UNNEEDED)
{ fprintf(stderr, "amount_sat called!\n"); abort(); }
/* Generated stub for amount_sat_add */
 bool amount_sat_add(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_add called!\n"); abort(); }
/* Generated stub for amount_sat_div */
struct amount_sat amount_sat_div(struct amount_sat sat UNNEEDED, u64 div UNNEEDED)
{ fprintf(stderr, "amount_sat_div called!\n"); abort(); }
/* Generated stub for amount_sat_eq */
bool amount_sat_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_eq called!\n"); abort(); }
/* Generated stub for amount_sat_greater_eq */
bool amount_sat_greater_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_greater_eq called!\n"); abort(); }
/* Generated stub for amount_sat_mul */
bool amount_sat_mul(struct amount_sat *res UNNEEDED, struct amount_sat sat UNNEEDED, u64 mul UNNEEDED)
{ fprintf(stderr, "amount_sat_mul called!\n"); abort(); }
/* Generated stub for amount_sat_sub */
 bool amount_sat_sub(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_sub called!\n"); abort(); }
/* Generated stub for amount_sat_to_asset */
struct amount_asset amount_sat_to_asset(struct amount_sat *sat UNNEEDED, const u8 *asset UNNEEDED)
{ fprintf(stderr, "amount_sat_to_asset called!\n"); abort(); }
/* Generated stub for amount_tx_fee */
struct amount_sat amount_tx_fee(u32 fee_per_kw UNNEEDED, size_t weight UNNEEDED)
{ fprintf(stderr, "amount_tx_fee called!\n"); abort(); }
/* Generated stub for decrypt_encrypted_data */
struct tlv_encrypted_data_tlv *decrypt_encrypted_data(const tal_t *ctx UNNEEDED,
						      const struct pubkey *blinding UNNEEDED,
						      const struct secret *ss UNNEEDED,
						      const u8 *enctlv)

{ fprintf(stderr, "decrypt_encrypted_data called!\n"); abort(); }
/* Generated stub for ecdh */
void ecdh(const struct pubkey *point UNNEEDED, struct secret *ss UNNEEDED)
{ fprintf(stderr, "ecdh called!\n"); abort(); }
/* Generated stub for fromwire_amount_msat */
struct amount_msat fromwire_amount_msat(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_amount_msat called!\n"); abort(); }
/* Generated stub for fromwire_tlv */
bool fromwire_tlv(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
		  const struct tlv_record_type *types UNNEEDED, size_t num_types UNNEEDED,
		  void *record UNNEEDED, struct tlv_field **fields UNNEEDED,
		  const u64 *extra_types UNNEEDED, size_t *err_off UNNEEDED, u64 *err_type UNNEEDED)
{ fprintf(stderr, "fromwire_tlv called!\n"); abort(); }
/* Generated stub for mvt_tag_str */
const char *mvt_tag_str(enum mvt_tag tag UNNEEDED)
{ fprintf(stderr, "mvt_tag_str called!\n"); abort(); }
/* Generated stub for new_onionreply */
struct onionreply *new_onionreply(const tal_t *ctx UNNEEDED, const u8 *contents TAKES UNNEEDED)
{ fprintf(stderr, "new_onionreply called!\n"); abort(); }
/* Generated stub for node_id_from_hexstr */
bool node_id_from_hexstr(const char *str UNNEEDED, size_t slen UNNEEDED, struct node_id *id UNNEEDED)
{ fprintf(stderr, "node_id_from_hexstr called!\n"); abort(); }
/* Generated stub for parse_amount_msat */
bool parse_amount_msat(struct amount_msat *msat UNNEEDED, const char *s UNNEEDED, size_t slen UNNEEDED)
{ fprintf(stderr, "parse_amount_msat called!\n"); abort(); }
/* Generated stub for parse_amount_sat */
bool parse_amount_sat(struct amount_sat *sat UNNEEDED, const char *s UNNEEDED, size_t slen UNNEEDED)
{ fprintf(stderr, "parse_amount_sat called!\n"); abort(); }
/* Generated stub for pubkey_from_node_id */
bool pubkey_from_node_id(struct pubkey *key UNNEEDED, const struct node_id *id UNNEEDED)
{ fprintf(stderr, "pubkey_from_node_id called!\n"); abort(); }
/* Generated stub for tlv_field_offset */
size_t tlv_field_offset(const u8 *tlvstream UNNEEDED, size_t tlvlen UNNEEDED, u64 fieldtype UNNEEDED)
{ fprintf(stderr, "tlv_field_offset called!\n"); abort(); }
/* Generated stub for towire_amount_msat */
void towire_amount_msat(u8 **pptr UNNEEDED, const struct amount_msat msat UNNEEDED)
{ fprintf(stderr, "towire_amount_msat called!\n"); abort(); }
/* Generated stub for towire_tlv */
void towire_tlv(u8 **pptr UNNEEDED,
		const struct tlv_record_type *types UNNEEDED, size_t num_types UNNEEDED,
		const void *record UNNEEDED)
{ fprintf(stderr, "towire_tlv called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

/* Updated each time, as we pretend to be Alice, Bob, Carol */
static struct secret mykey;

static void test_ecdh(const struct pubkey *point, struct secret *ss)
{
	if (secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
			   mykey.data, NULL, NULL) != 1)
		abort();
}

int main(int argc, char *argv[])
{
	char *json;
	size_t i;
	jsmn_parser parser;
	jsmntok_t toks[5000];
	const jsmntok_t *t, *generate_tok;
	struct sphinx_path *sp;
	struct secret session_key;
	struct onionpacket *op;
	u8 *assoc_data, *expected, *actual;
	struct secret *unused_path_secrets;
	u8 *payloads[5];

	common_setup(argv[0]);

	if (argv[1])
		json = grab_file(tmpctx, argv[1]);
	else {
		char *dir = getenv("BOLTDIR");
		json = grab_file(tmpctx,
				 path_join(tmpctx,
					   dir ? dir : "../bolts",
					   "bolt04/onion-test.json"));
		if (!json) {
			printf("test file not found, skipping\n");
			goto out;
		}
	}

	jsmn_init(&parser);
	if (jsmn_parse(&parser, json, strlen(json), toks, ARRAY_SIZE(toks)) < 0)
		abort();

	generate_tok = json_get_member(json, toks, "generate");
	json_to_secret(json, json_get_member(json, generate_tok, "session_key"), &session_key);
	assoc_data = json_tok_bin_from_hex(tmpctx, json, json_get_member(json, generate_tok, "associated_data"));
	sp = sphinx_path_new_with_key(tmpctx, assoc_data, &session_key);
	json_for_each_arr(i, t, json_get_member(json, generate_tok, "hops")) {
		struct pubkey k;
		const u8 *cursor;
		size_t max, len;

		json_to_pubkey(json, json_get_member(json, t, "pubkey"), &k);
		payloads[i] = json_tok_bin_from_hex(NULL, json, json_get_member(json, t, "payload"));
		/* First byte(s) are length: check and remove them for our API. */
		cursor = payloads[i];
		max = tal_bytelen(payloads[i]);
		len = fromwire_bigsize(&cursor, &max);
		assert(len == max);
		sphinx_add_hop(sp, &k, take(tal_dup_arr(NULL, u8, cursor, max, 0)));
	}
	assert(i == ARRAY_SIZE(payloads));

	op = create_onionpacket(tmpctx, sp, ROUTING_INFO_SIZE, &unused_path_secrets);

	expected = json_tok_bin_from_hex(tmpctx, json, json_get_member(json, toks, "onion"));
	actual = serialize_onionpacket(tmpctx, op);
	assert(memeq(expected, tal_bytelen(expected), actual, tal_bytelen(actual)));

	/* Now decode! */
	op = parse_onionpacket(tmpctx, actual, tal_bytelen(actual), NULL);
	json_for_each_arr(i, t, json_get_member(json, toks, "decode")) {
		struct route_step *rs;
		struct secret ss;

		json_to_secret(json, t, &mykey);
		test_ecdh(&op->ephemeralkey, &ss);
		rs = process_onionpacket(tmpctx, op, &ss, assoc_data, tal_bytelen(assoc_data), true);
		assert(memeq(rs->raw_payload, tal_bytelen(rs->raw_payload),
			     payloads[i], tal_bytelen(payloads[i])));
		if (rs->nextcase == ONION_FORWARD)
			op = rs->next;
		else
			op = NULL;
	}
	assert(!op);

	for (size_t j=0; j<ARRAY_SIZE(payloads); j++) {
		tal_free(payloads[j]);
	}

out:
	common_shutdown();
}
