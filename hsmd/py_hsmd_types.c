#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <hsmd/py_hsmd_types.h>

PyObject *py_none(void)
{
	Py_RETURN_NONE;
}

PyObject *py_bip32_key_version(struct bip32_key_version const *vp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "bip32_pubkey_version",
			     PyLong_FromLong(vp->bip32_pubkey_version));
	PyDict_SetItemString(pdict, "bip32_privkey_version",
			     PyLong_FromLong(vp->bip32_privkey_version));
	return pdict;
}

PyObject *py_sha256(struct sha256 const *sp)
{
	return PyBytes_FromStringAndSize((char const *) sp->u.u8, 32);
}

PyObject *py_sha256_double(struct sha256_double const *sp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "sha", py_sha256(&(sp->sha)));
	return pdict;
}

PyObject *py_witscript(struct witscript const *pp)
{
	return pp->ptr ?
		PyBytes_FromStringAndSize(
			(char const *) pp->ptr, tal_count(pp->ptr)) :
		py_none();
}

PyObject *py_witscripts(struct witscript const **witscripts)
{
	size_t len = tal_count(witscripts);
	PyObject *plist = PyList_New(len);
	for (size_t ii = 0; ii < len; ++ii)
		PyList_SetItem(plist, ii, py_witscript(witscripts[ii]));
	return plist;
}

PyObject *py_bitcoin_blkid(struct bitcoin_blkid const *bp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "shad", py_sha256_double(&(bp->shad)));
	return pdict;
}

PyObject *py_bitcoin_txid(struct bitcoin_txid const *bp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "shad", py_sha256_double(&(bp->shad)));
	return pdict;
}

PyObject *py_amount_sat(struct amount_sat const *ap)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "satoshis",
			     PyLong_FromUnsignedLongLong(ap->satoshis));
	return pdict;
}

PyObject *py_amount_msat(struct amount_msat const *ap)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "millisatoshis",
			     PyLong_FromUnsignedLongLong(ap->millisatoshis));
	return pdict;
}

PyObject *py_chainparams(struct chainparams const *cp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "network_name",
			     PyUnicode_FromString(cp->network_name));
	PyDict_SetItemString(pdict, "bip173_name",
			     PyUnicode_FromString(cp->bip173_name));
	PyDict_SetItemString(pdict, "bip70_name",
			     PyUnicode_FromString(cp->bip70_name));
	PyDict_SetItemString(pdict, "genesis_blockhash",
			     py_bitcoin_blkid(&(cp->genesis_blockhash)));
	PyDict_SetItemString(pdict, "rpc_port",
			     PyLong_FromLong(cp->rpc_port));
	PyDict_SetItemString(pdict, "cli",
			     PyUnicode_FromString(cp->cli));
	PyDict_SetItemString(pdict, "cli_args",
			     PyUnicode_FromString(cp->cli_args));
	PyDict_SetItemString(pdict, "cli_min_supported_version",
			     PyLong_FromUnsignedLongLong(
				     cp->cli_min_supported_version));
	PyDict_SetItemString(pdict, "dust_limit",
			     py_amount_sat(&(cp->dust_limit)));
	PyDict_SetItemString(pdict, "max_funding",
			     py_amount_sat(&(cp->max_funding)));
	PyDict_SetItemString(pdict, "max_payment",
			     py_amount_msat(&(cp->max_payment)));
	PyDict_SetItemString(pdict, "when_lightning_became_cool",
			     PyLong_FromUnsignedLong(
				     cp->when_lightning_became_cool));
	PyDict_SetItemString(pdict, "p2pkh_version",
			     PyLong_FromUnsignedLong(cp->p2pkh_version));
	PyDict_SetItemString(pdict, "p2sh_version",
			     PyLong_FromUnsignedLong(cp->p2sh_version));
	PyDict_SetItemString(pdict, "testnet",
			     PyBool_FromLong(cp->testnet));
	PyDict_SetItemString(pdict, "bip32_key_version",
			     py_bip32_key_version(&(cp->bip32_key_version)));
	PyDict_SetItemString(pdict, "is_elements",
			     PyBool_FromLong(cp->is_elements));
	PyDict_SetItemString(pdict, "fee_asset_tag",
			     cp->fee_asset_tag ?
			     PyBytes_FromStringAndSize
			     ((char const *) cp->fee_asset_tag, 33) :
			     py_none());
	return pdict;
}

PyObject *py_node_id(struct node_id *pp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "k",
			     PyBytes_FromStringAndSize(
				     (char const *) pp->k, PUBKEY_CMPR_LEN));
	return pdict;
}

PyObject *py_secp256k1_pubkey(secp256k1_pubkey *kp)
{
	return PyBytes_FromStringAndSize((char const *) kp->data, 64);
}

PyObject *py_secret(struct secret *sp)
{
	return PyBytes_FromStringAndSize((char const *) sp->data, 32);
}

PyObject *py_privkey(struct privkey *kp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "secret", py_secret(&(kp->secret)));
	return pdict;
}

PyObject *py_pubkey(struct pubkey *kp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "pubkey",
			     py_secp256k1_pubkey(&(kp->pubkey)));
	return pdict;
}

PyObject *py_secrets(struct secrets *sp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "funding_privkey",
			     py_privkey(&(sp->funding_privkey)));
	PyDict_SetItemString(pdict, "revocation_basepoint_secret",
			     py_secret(&(sp->revocation_basepoint_secret)));
	PyDict_SetItemString(pdict, "payment_basepoint_secret",
			     py_secret(&(sp->payment_basepoint_secret)));
	PyDict_SetItemString(pdict, "htlc_basepoint_secret",
			     py_secret(&(sp->htlc_basepoint_secret)));
	PyDict_SetItemString(pdict, "delayed_payment_basepoint_secret",
			     py_secret(
				     &(sp->delayed_payment_basepoint_secret)));
	return pdict;
}

PyObject *py_unilateral_close_info(struct unilateral_close_info *ip)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "channel_id",
			     PyLong_FromUnsignedLongLong(ip->channel_id));
	PyDict_SetItemString(pdict, "node_id", py_node_id(&(ip->peer_id)));
	PyDict_SetItemString(pdict, "commitment_point",
			     ip->commitment_point ?
			     py_pubkey(ip->commitment_point) :
			     py_none());
	return pdict;
}

PyObject *py_bitcoin_tx_output(struct bitcoin_tx_output *output)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "amount", py_amount_sat(&(output->amount)));
	PyDict_SetItemString(pdict, "script",
			     PyBytes_FromStringAndSize(
				     (char const *) output->script,
				     tal_count(output->script)));
	return pdict;
}

PyObject *py_bitcoin_tx_outputs(struct bitcoin_tx_output **outputs)
{
	size_t len = tal_count(outputs);
	PyObject *plist = PyList_New(len);
	for (size_t ii = 0; ii < len; ++ii)
		PyList_SetItem(plist, ii, py_bitcoin_tx_output(outputs[ii]));
	return plist;
}

PyObject *py_utxo(struct utxo *utxo)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "txid", py_bitcoin_txid(&(utxo->txid)));
	PyDict_SetItemString(pdict, "outnum",
			     PyLong_FromUnsignedLong(utxo->outnum));
	PyDict_SetItemString(pdict, "amount", py_amount_sat(&(utxo->amount)));
	PyDict_SetItemString(pdict, "keyindex",
			     PyLong_FromUnsignedLong(utxo->keyindex));
	PyDict_SetItemString(pdict, "is_p2sh",
			     PyBool_FromLong(utxo->is_p2sh ? 1 : 0));
	PyDict_SetItemString(pdict, "close_info",
			     utxo->close_info ?
			     py_unilateral_close_info(utxo->close_info) :
			     py_none());
	/* status, blockheight, spendheight and scriptPubkey are not
	   set in this context */
	return pdict;
}

PyObject *py_utxos(struct utxo **utxos)
{
	size_t len = tal_count(utxos);
	PyObject *plist = PyList_New(len);
	for (size_t ii = 0; ii < len; ++ii)
		PyList_SetItem(plist, ii, py_utxo(utxos[ii]));
	return plist;
}

PyObject *py_amounts_sat(struct amount_sat **input_amounts)
{
	size_t len = tal_count(input_amounts);
	PyObject *plist = PyList_New(len);
	for (size_t ii = 0; ii < len; ++ii)
		PyList_SetItem(plist, ii, input_amounts[ii] ?
			       py_amount_sat(input_amounts[ii]) : py_none());
	return plist;
}

PyObject *py_wally_tx_witness_items(struct wally_tx_witness_item *items,
                                           size_t num_items)
{
	PyObject *plist = PyList_New(num_items);
	for (size_t ii = 0; ii < num_items; ++ii)
		PyList_SetItem(plist, ii,
			       PyBytes_FromStringAndSize(
				       (char const *) items[ii].witness,
				       items[ii].witness_len));
	return plist;
}

PyObject *py_wally_tx_witness_stack(struct wally_tx_witness_stack *pp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "items",
			     py_wally_tx_witness_items(
				     pp->items, pp->num_items));
	PyDict_SetItemString(pdict, "items_allocation_len",
			     PyLong_FromSize_t(pp->items_allocation_len));
	return pdict;
}

PyObject *py_wally_tx_input(struct wally_tx_input const *pp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "txhash",
			     PyBytes_FromStringAndSize(
				     (char const *) pp->txhash,
				     WALLY_TXHASH_LEN));
	PyDict_SetItemString(pdict, "index",
			     PyLong_FromUnsignedLong(pp->index));
	PyDict_SetItemString(pdict, "sequence",
			     PyLong_FromUnsignedLong(pp->sequence));
	PyDict_SetItemString(pdict, "script",
			     PyBytes_FromStringAndSize(
				     (char const *) pp->script,
				     pp->script_len));
	PyDict_SetItemString(pdict, "witness",
			     pp->witness
			     ? py_wally_tx_witness_stack(pp->witness)
			     : py_none());
	PyDict_SetItemString(pdict, "features",
			     PyLong_FromUnsignedLong(pp->features));
	return pdict;
}

PyObject *py_wally_tx_inputs(struct wally_tx_input *inputs,
                                    size_t num_inputs)
{
	PyObject *plist = PyList_New(num_inputs);
	for (size_t ii = 0; ii < num_inputs; ++ii)
		PyList_SetItem(plist, ii, py_wally_tx_input(&(inputs[ii])));
	return plist;
}

PyObject *py_wally_tx_output(struct wally_tx_output const *pp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "satoshi",
			     PyLong_FromUnsignedLongLong(pp->satoshi));
	PyDict_SetItemString(pdict, "script",
			     PyBytes_FromStringAndSize(
				     (char const *) pp->script,
				     pp->script_len));
	PyDict_SetItemString(pdict, "features",
			     PyLong_FromUnsignedLong(pp->features));
	return pdict;
}

PyObject *py_wally_tx_outputs(struct wally_tx_output *outputs,
                                     size_t num_outputs)
{
	PyObject *plist = PyList_New(num_outputs);
	for (size_t ii = 0; ii < num_outputs; ++ii)
		PyList_SetItem(plist, ii, py_wally_tx_output(&(outputs[ii])));
	return plist;
}

PyObject *py_wally_tx(struct wally_tx const *pp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "version",
			     PyLong_FromUnsignedLong(pp->version));
	PyDict_SetItemString(pdict, "locktime",
			     PyLong_FromUnsignedLong(pp->locktime));
	PyDict_SetItemString(pdict, "inputs",
			     py_wally_tx_inputs(pp->inputs, pp->num_inputs));
	PyDict_SetItemString(pdict, "inputs_allocation_len",
			     PyLong_FromSize_t(pp->inputs_allocation_len));
	PyDict_SetItemString(pdict, "outputs",
			     py_wally_tx_outputs(pp->outputs, pp->num_outputs));
	PyDict_SetItemString(pdict, "outputs_allocation_len",
			     PyLong_FromSize_t(pp->outputs_allocation_len));
	return pdict;
}

PyObject *py_bitcoin_tx(struct bitcoin_tx const *pp)
{
	PyObject *pdict = PyDict_New();
	PyDict_SetItemString(pdict, "input_amounts",
			     py_amounts_sat(pp->input_amounts));
	PyDict_SetItemString(pdict, "wally_tx", py_wally_tx(pp->wtx));
	PyDict_SetItemString(pdict, "chainparams",
			     py_chainparams(pp->chainparams));
	return pdict;
}

void py_return_sigs(char const * func, PyObject *pretval, u8 ****o_sigs)
{
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	if (!PySequence_Check(pretval)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s:%d %s bad return type",
			      __FILE__, __LINE__, __FUNCTION__);
		Py_DECREF(pretval);	// not reached
	}
	u8 ***sigs;
	Py_ssize_t nsigs = PySequence_Length(pretval);
	sigs = tal_arrz(tmpctx, u8**, nsigs);
	for (size_t ii = 0; ii < nsigs; ++ii) {
		PyObject *sig = PySequence_GetItem(pretval, ii);
		if (!PySequence_Check(sig)) {
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s:%d %s bad sig type",
				      __FILE__, __LINE__, __FUNCTION__);
			Py_DECREF(sig);		// not reached
			Py_DECREF(pretval);	// not reached
		}
		Py_ssize_t nelem = PySequence_Length(sig);
		sigs[ii] = tal_arrz(sigs, u8*, nelem);
		for (size_t jj = 0; jj < nelem; ++jj) {
			PyObject *elem = PySequence_GetItem(sig, jj);
			if (!PyBytes_Check(elem)) {
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "%s:%d %s bad elem type",
					      __FILE__, __LINE__, __FUNCTION__);
				Py_DECREF(elem);	// not reached
				Py_DECREF(sig);		// not reached
				Py_DECREF(pretval);	// not reached
			}
			size_t elen = PyBytes_Size(elem);
			sigs[ii][jj] = tal_arr(sigs[ii], u8, elen);
			memcpy(sigs[ii][jj], PyBytes_AsString(elem), elen);
			Py_DECREF(elem);
		}
		Py_DECREF(sig);
	}
	Py_DECREF(pretval);
	*o_sigs = sigs;
}
