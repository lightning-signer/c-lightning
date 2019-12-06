#include <hsmd/py_hsmd.h>
#include <hsmd/py_types.h>

struct node_id self_node_id;

/*~ Python function objects. */
static struct {
	PyObject *setup;
	PyObject *init_hsm;
	PyObject *handle_pass_client_hsmfd;
	PyObject *handle_ecdh;
	PyObject *handle_get_channel_basepoints;
	PyObject *handle_get_per_commitment_point;
	PyObject *handle_cannouncement_sig;
	PyObject *handle_sign_withdrawal_tx;
	PyObject *handle_sign_remote_commitment_tx;
	PyObject *handle_sign_remote_htlc_tx;
	PyObject *handle_sign_mutual_close_tx;
} pyfunc;

void py_init_hsm(struct bip32_key_version *bip32_key_version,
		 struct chainparams const *chainparams,
		 struct secret *hsm_encryption_key,
		 struct privkey *privkey,
		 struct secret *seed,
		 struct secrets *secrets,
		 struct sha256 *shaseed,
		 struct secret *hsm_secret)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(8);
	PyTuple_SetItem(pargs, ndx++, py_bip32_key_version(bip32_key_version));
	PyTuple_SetItem(pargs, ndx++, py_chainparams(chainparams));
	PyTuple_SetItem(pargs, ndx++, hsm_encryption_key ?
			py_secret(hsm_encryption_key): py_none());
	PyTuple_SetItem(pargs, ndx++,
			privkey ? py_privkey(privkey) : py_none());
	PyTuple_SetItem(pargs, ndx++, seed ? py_secret(seed) : py_none());
	PyTuple_SetItem(pargs, ndx++,
			secrets ? py_secrets(secrets) : py_none());
	PyTuple_SetItem(pargs, ndx++,
			shaseed ? py_sha256(shaseed) : py_none());
	PyTuple_SetItem(pargs, ndx++, py_secret(hsm_secret));
	PyObject *pretval = PyObject_CallObject(pyfunc.init_hsm, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_DECREF(pretval);

	/* FIXME - Need to return something here */
}

bool py_handle_ecdh(struct pubkey *point, struct secret *o_ss)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(2);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_pubkey(point));
	PyObject *pretval = PyObject_CallObject(pyfunc.handle_ecdh, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
		return false;	// not reached
	}
	// None will get returned if the input was bad.  Caller will
	// do the status_broken.
	if (!PyBytes_Check(pretval)) {
		status_debug("%s:%d %s: bad return type",
			     __FILE__, __LINE__, __FUNCTION__);
		Py_DECREF(pretval);
		return false;
	}
	if (PyBytes_Size(pretval) != sizeof(o_ss->data)) {
		status_debug("%s:%d %s: bad return size",
			     __FILE__, __LINE__, __FUNCTION__);
		Py_DECREF(pretval);
		return false;
	}
	memcpy(o_ss->data, PyBytes_AsString(pretval), sizeof(o_ss->data));
	Py_DECREF(pretval);
	return true;
}

void py_handle_cannouncement_sig(u8 *ca, size_t calen,
				 struct node_id *node_id,
				 u64 dbid)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(4);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++,
			PyBytes_FromStringAndSize((char const *) ca, calen));
	PyTuple_SetItem(pargs, ndx++, py_node_id(node_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyObject *pretval =
		PyObject_CallObject(pyfunc.handle_cannouncement_sig, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_DECREF(pretval);

	/* FIXME - Need to return something here */
}

void py_handle_get_channel_basepoints(struct node_id *peer_id, u64 dbid)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(3);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_node_id(peer_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyObject *pretval =
		PyObject_CallObject(
			pyfunc.handle_get_channel_basepoints, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_DECREF(pretval);

	/* FIXME - Need to return something here */
}

void py_handle_sign_remote_commitment_tx(
	struct bitcoin_tx *tx,
	struct pubkey *remote_funding_pubkey,
	struct amount_sat *funding,
	struct node_id *peer_id,
	u64 dbid,
	struct witscript const **output_witscripts,
	struct pubkey *remote_per_commit,
	bool option_static_remotekey,
	u8 ****o_sigs)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(9);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_bitcoin_tx(tx));
	PyTuple_SetItem(pargs, ndx++, py_pubkey(remote_funding_pubkey));
	PyTuple_SetItem(pargs, ndx++, py_amount_sat(funding));
	PyTuple_SetItem(pargs, ndx++, py_node_id(peer_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyTuple_SetItem(pargs, ndx++, py_witscripts(output_witscripts));
	PyTuple_SetItem(pargs, ndx++, py_pubkey(remote_per_commit));
	PyTuple_SetItem(pargs, ndx++, PyBool_FromLong(option_static_remotekey));
	PyObject *pretval = PyObject_CallObject(
		pyfunc.handle_sign_remote_commitment_tx, pargs);
	py_return_sigs(__func__, pretval, o_sigs);
}

void py_handle_sign_remote_htlc_tx(
	struct bitcoin_tx *tx,
	u8 *wscript,
	struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(6);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_bitcoin_tx(tx));
	PyTuple_SetItem(pargs, ndx++, wscript ?
			PyBytes_FromStringAndSize((char const *) wscript,
						  tal_bytelen(wscript)) :
			py_none());
	PyTuple_SetItem(pargs, ndx++, py_pubkey(remote_per_commit_point));
	PyTuple_SetItem(pargs, ndx++, py_node_id(peer_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyObject *pretval =
		PyObject_CallObject(pyfunc.handle_sign_remote_htlc_tx, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_DECREF(pretval);

	/* FIXME - Need to return something here */
}

void py_handle_get_per_commitment_point(struct node_id *peer_id,
					u64 dbid,
					u64 n)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(4);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_node_id(peer_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(n));
	PyObject *pretval =
		PyObject_CallObject(
			pyfunc.handle_get_per_commitment_point, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_XDECREF(pretval);

	/* FIXME - Need to return something here */
}

void py_handle_sign_mutual_close_tx(
	struct bitcoin_tx *tx,
	struct pubkey *remote_funding_pubkey,
	struct amount_sat *funding,
	struct node_id *peer_id,
	u64 dbid)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(6);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_bitcoin_tx(tx));
	PyTuple_SetItem(pargs, ndx++, py_pubkey(remote_funding_pubkey));
	PyTuple_SetItem(pargs, ndx++, py_amount_sat(funding));
	PyTuple_SetItem(pargs, ndx++, py_node_id(peer_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyObject *pretval =
		PyObject_CallObject(pyfunc.handle_sign_mutual_close_tx, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_DECREF(pretval);

	/* FIXME - Need to return something here */
}

void py_handle_pass_client_hsmfd(struct node_id *peer_id,
				 u64 dbid,
				 u64 capabilities)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(4);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_node_id(peer_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyTuple_SetItem(pargs, ndx++,
			PyLong_FromUnsignedLongLong(capabilities));
	PyObject *pretval =
		PyObject_CallObject(pyfunc.handle_pass_client_hsmfd, pargs);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "%s:%d %s failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_XDECREF(pretval);
}

void py_handle_sign_withdrawal_tx(
	struct node_id *peer_id, u64 dbid,
	struct amount_sat *satoshi_out,
	struct amount_sat *change_out,
	u32 change_keyindex,
	struct bitcoin_tx_output **outputs,
	struct utxo **utxos,
	struct bitcoin_tx *tx,
	u8 ****o_sigs)
{
	size_t ndx = 0;
	PyObject *pargs = PyTuple_New(9);
	PyTuple_SetItem(pargs, ndx++, py_node_id(&self_node_id));
	PyTuple_SetItem(pargs, ndx++, py_node_id(peer_id));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLongLong(dbid));
	PyTuple_SetItem(pargs, ndx++, py_amount_sat(satoshi_out));
	PyTuple_SetItem(pargs, ndx++, py_amount_sat(change_out));
	PyTuple_SetItem(pargs, ndx++, PyLong_FromUnsignedLong(change_keyindex));
	PyTuple_SetItem(pargs, ndx++, py_bitcoin_tx_outputs(outputs));
	PyTuple_SetItem(pargs, ndx++, py_utxos(utxos));
	PyTuple_SetItem(pargs, ndx++, py_bitcoin_tx(tx));
	PyObject *pretval =
		PyObject_CallObject(pyfunc.handle_sign_withdrawal_tx, pargs);
	py_return_sigs(__func__, pretval, o_sigs);
}

static PyObject *python_function(PyObject *pmodule, char *funcname)
{
	PyObject *pfunc = PyObject_GetAttrString(pmodule, funcname);
	if (pfunc == NULL || !PyCallable_Check(pfunc)) {
		if (PyErr_Occurred())
			PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s:%d %s cannot find function \"%s\"",
			      __FILE__, __LINE__, __FUNCTION__, funcname);
	}
	return pfunc;
}

void setup_python_functions(void)
{
	Py_Initialize();
	PyObject *pname = PyUnicode_DecodeFSDefault("hsmd");
	PyObject *pmodule = PyImport_Import(pname);
	Py_DECREF(pname);
	if (pmodule == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s:%d %s failed tp load \"hsmd\"",
			      __FILE__, __LINE__, __FUNCTION__);
	}

	pyfunc.setup = python_function(pmodule, "setup");
	pyfunc.init_hsm = python_function(pmodule, "init_hsm");
	pyfunc.handle_pass_client_hsmfd =
		python_function(pmodule, "handle_pass_client_hsmfd");
	pyfunc.handle_ecdh = python_function(pmodule, "handle_ecdh");
	pyfunc.handle_get_channel_basepoints =
		python_function(pmodule, "handle_get_channel_basepoints");
	pyfunc.handle_get_per_commitment_point =
		python_function(pmodule, "handle_get_per_commitment_point");
	pyfunc.handle_cannouncement_sig =
		python_function(pmodule, "handle_cannouncement_sig");
	pyfunc.handle_sign_withdrawal_tx =
		python_function(pmodule, "handle_sign_withdrawal_tx");
	pyfunc.handle_sign_remote_commitment_tx =
		python_function(pmodule, "handle_sign_remote_commitment_tx");
	pyfunc.handle_sign_remote_htlc_tx =
		python_function(pmodule, "handle_sign_remote_htlc_tx");
	pyfunc.handle_sign_mutual_close_tx =
		python_function(pmodule, "handle_sign_mutual_close_tx");

	Py_DECREF(pmodule);

	/* Call the python setup function. */
	PyObject *pretval = PyObject_CallObject(pyfunc.setup, NULL);
	if (pretval == NULL) {
		PyErr_Print();
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s:%d %s python setup failed",
			      __FILE__, __LINE__, __FUNCTION__);
	}
	Py_DECREF(pretval);
}
