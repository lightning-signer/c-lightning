#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <common/derive_basepoints.h>
#include <common/utxo.h>
#include <common/node_id.h>
#include <ccan/crypto/sha256/sha256.h>

extern struct node_id self_node_id;

void py_init_hsm(struct bip32_key_version *bip32_key_version,
		 struct chainparams const *chainparams,
		 struct secret *hsm_encryption_key,
		 struct privkey *privkey,
		 struct secret *seed,
		 struct secrets *secrets,
		 struct sha256 *shaseed,
		 struct secret *hsm_secret);

bool py_handle_ecdh(struct pubkey *point, struct secret *o_ss);

void py_handle_cannouncement_sig(u8 *ca, size_t calen,
				 struct node_id *node_id,
				 u64 dbid);

void py_handle_get_channel_basepoints(struct node_id *peer_id, u64 dbid);

void py_handle_sign_remote_commitment_tx(
	struct bitcoin_tx *tx,
	struct pubkey *remote_funding_pubkey,
	struct amount_sat *funding,
	struct node_id *peer_id,
	u64 dbid,
	struct witscript const **output_witscripts,
	struct pubkey *remote_per_commit,
	bool option_static_remotekey,
	u8 ****o_sigs);

void py_handle_sign_remote_htlc_tx(
	struct bitcoin_tx *tx,
	u8 *wscript,
	struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid);

void py_handle_get_per_commitment_point(struct node_id *peer_id,
					u64 dbid,
					u64 n);

void py_handle_sign_mutual_close_tx(
	struct bitcoin_tx *tx,
	struct pubkey *remote_funding_pubkey,
	struct amount_sat *funding,
	struct node_id *peer_id,
	u64 dbid);

void py_handle_pass_client_hsmfd(struct node_id *peer_id,
				 u64 dbid,
				 u64 capabilities);

void py_handle_sign_withdrawal_tx(
	struct node_id *peer_id, u64 dbid,
	struct amount_sat *satoshi_out,
	struct amount_sat *change_out,
	u32 change_keyindex,
	struct bitcoin_tx_output **outputs,
	struct utxo **utxos,
	struct bitcoin_tx *tx,
	u8 ****o_sigs);

void setup_python_functions(void);
