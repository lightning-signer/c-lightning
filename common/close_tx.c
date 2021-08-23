#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "permute_tx.h"
#include <assert.h>
#include <common/utils.h>

static void add_keypath_item_to_last_output(struct bitcoin_tx *tx,
					    u32 index,
					    const struct ext_key *ext) {
	// Skip if there is no wallet keypath for this output.
	if (index == UINT32_MAX)
		return;

	size_t outndx = tx->psbt->num_outputs - 1;
	struct wally_map *map_in = &tx->psbt->outputs[outndx].keypaths;

	u8 fingerprint[BIP32_KEY_FINGERPRINT_LEN];
	if (bip32_key_get_fingerprint(
		    (struct ext_key *) ext, fingerprint, sizeof(fingerprint)) != WALLY_OK) {
		abort();
	}

	u32 path[1];
	path[0] = index;

	tal_wally_start();
	if (wally_map_add_keypath_item(map_in,
				       ext->pub_key, sizeof(ext->pub_key),
				       fingerprint, sizeof(fingerprint),
				       path, 1) != WALLY_OK) {
		abort();
	}
	tal_wally_end(tx->psbt);
}

struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   u32 local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit)
{
	struct bitcoin_tx *tx;
	size_t num_outputs = 0;
	struct amount_sat total_out;
	u8 *script;

	assert(amount_sat_add(&total_out, to_us, to_them));
	assert(amount_sat_less_eq(total_out, funding_sats));

	/* BOLT #3:
	 *
	 * ## Closing Transaction
	 *
	 * Note that there are two possible variants for each node.
	 *
	 * * version: 2
	 * * locktime: 0
	 * * txin count: 1
	 */
	/* Now create close tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, chainparams, 1, 2, 0);

	/* Our input spends the anchor tx output. */
	bitcoin_tx_add_input(tx, funding,
			     BITCOIN_TX_DEFAULT_SEQUENCE, NULL,
			     funding_sats, NULL, funding_wscript);

	if (amount_sat_greater_eq(to_us, dust_limit)) {
		script = tal_dup_talarr(tx, u8, our_script);
		/* One output is to us. */
		bitcoin_tx_add_output(tx, script, NULL, to_us);
		add_keypath_item_to_last_output(tx, local_wallet_index, local_wallet_ext_key);
		num_outputs++;
	}

	if (amount_sat_greater_eq(to_them, dust_limit)) {
		script = tal_dup_talarr(tx, u8, their_script);
		/* Other output is to them. */
		bitcoin_tx_add_output(tx, script, NULL, to_them);
		num_outputs++;
	}

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		return tal_free(tx);

	permute_outputs(tx, NULL, NULL);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}
