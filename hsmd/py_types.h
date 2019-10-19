#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <common/derive_basepoints.h>
#include <common/node_id.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/utxo.h>

PyObject *py_none(void);
PyObject *py_bip32_key_version(struct bip32_key_version const *vp);
PyObject *py_sha256(struct sha256 const *sp);
PyObject *py_sha256_double(struct sha256_double const *sp);
PyObject *py_witscript(struct witscript const *pp);
PyObject *py_witscripts(struct witscript const **witscripts);
PyObject *py_bitcoin_blkid(struct bitcoin_blkid const *bp);
PyObject *py_bitcoin_txid(struct bitcoin_txid const *bp);
PyObject *py_amount_sat(struct amount_sat const *ap);
PyObject *py_amount_msat(struct amount_msat const *ap);
PyObject *py_chainparams(struct chainparams const *cp);
PyObject *py_node_id(struct node_id *pp);
PyObject *py_secp256k1_pubkey(secp256k1_pubkey *kp);
PyObject *py_secret(struct secret *sp);
PyObject *py_privkey(struct privkey *kp);
PyObject *py_pubkey(struct pubkey *kp);
PyObject *py_secrets(struct secrets *sp);
PyObject *py_unilateral_close_info(struct unilateral_close_info *ip);
PyObject *py_bitcoin_tx_output(struct bitcoin_tx_output *output);
PyObject *py_bitcoin_tx_outputs(struct bitcoin_tx_output **outputs);
PyObject *py_utxo(struct utxo *utxo);
PyObject *py_utxos(struct utxo **utxos);
PyObject *py_amounts_sat(struct amount_sat **input_amounts);
PyObject *py_wally_tx_witness_items(struct wally_tx_witness_item *items,
				    size_t num_items);
PyObject *py_wally_tx_witness_stack(struct wally_tx_witness_stack *pp);
PyObject *py_wally_tx_input(struct wally_tx_input const *pp);
PyObject *py_wally_tx_inputs(struct wally_tx_input *inputs, size_t num_inputs);
PyObject *py_wally_tx_output(struct wally_tx_output const *pp);
PyObject *py_wally_tx_outputs(struct wally_tx_output *outputs,
			      size_t num_outputs);
PyObject *py_wally_tx(struct wally_tx const *pp);
PyObject *py_bitcoin_tx(struct bitcoin_tx const *pp);

void py_return_sigs(char const * func, PyObject *pretval, u8 ****o_sigs);
