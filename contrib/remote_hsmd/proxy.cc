/* This needs to be first */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <sys/types.h>	/* These two only needed for sleep() and getpid() */
#include <unistd.h>

#include <iostream>
#include <sstream>

#include <grpc++/grpc++.h>

extern "C" {
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <common/hash_u5.h>
#include <common/node_id.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/utxo.h>
}

#include "contrib/remote_hsmd/api.pb.h"
#include "contrib/remote_hsmd/api.grpc.pb.h"

#include "contrib/remote_hsmd/dump.h"
#include "contrib/remote_hsmd/proxy.h"

using std::cerr;
using std::endl;
using std::ostringstream;
using std::string;
using std::unique_ptr;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

using rpc::ChannelUpdateSigReq;
using rpc::ChannelUpdateSigRsp;
using rpc::ECDHReq;
using rpc::ECDHRsp;
using rpc::GetPerCommitmentPointReq;
using rpc::GetPerCommitmentPointRsp;
using rpc::InitHSMReq;
using rpc::InitHSMRsp;
using rpc::KeyLocator;
using rpc::PassClientHSMFdReq;
using rpc::PassClientHSMFdRsp;
using rpc::SignDescriptor;
using rpc::SignInvoiceReq;
using rpc::SignInvoiceRsp;
using rpc::SignRemoteCommitmentTxReq;
using rpc::SignRemoteCommitmentTxRsp;
using rpc::SignRemoteHTLCTxReq;
using rpc::SignRemoteHTLCTxRsp;
using rpc::SignWithdrawalTxReq;
using rpc::SignWithdrawalTxRsp;
using rpc::Signature;
using rpc::Signer;

using ::google::protobuf::RepeatedPtrField;

namespace {
unique_ptr<Signer::Stub> stub;
string last_message;
struct node_id self_id;

proxy_stat map_status(StatusCode const & code)
{
	switch (code) {
	case StatusCode::OK:			return PROXY_OK;
	case StatusCode::DEADLINE_EXCEEDED:	return PROXY_TIMEOUT;
	case StatusCode::UNAVAILABLE:		return PROXY_UNAVAILABLE;
	case StatusCode::INVALID_ARGUMENT:	return PROXY_INVALID_ARGUMENT;
	case StatusCode::INTERNAL:		return PROXY_INTERNAL_ERROR;
	default:
		cerr << "UNHANDLED grpc::StatusCode " << int(code) << endl;
		abort();
	}
}

string channel_nonce(struct node_id *peer_id, u64 dbid)
{
	return string((char const *)peer_id->k, sizeof(peer_id->k)) +
		string((char const *)&dbid, sizeof(dbid));
}

u8 ***return_sigs(RepeatedPtrField< ::rpc::Signature > const &isigs)
{
	u8 ***osigs = NULL;
	int nsigs = isigs.size();
	if (nsigs > 0) {
		osigs = tal_arrz(tmpctx, u8**, nsigs);
		for (size_t ii = 0; ii < nsigs; ++ii) {
			Signature const &sig = isigs[ii];
			int nelem = sig.item_size();
			osigs[ii] = tal_arrz(osigs, u8*, nelem);
			for (size_t jj = 0; jj < nelem; ++jj) {
				string const &elem = sig.item(jj);
				size_t elen = elem.size();
				osigs[ii][jj] = tal_arr(osigs[ii], u8, elen);
				memcpy(osigs[ii][jj], &elem[0], elen);
			}
		}
	}
	return osigs;
}

/* BIP144:
 * If the witness is empty, the old serialization format should be used. */
bool uses_witness(const struct bitcoin_tx *tx)
{
	size_t i;
	for (i = 0; i < tx->wtx->num_inputs; i++) {
		if (tx->wtx->inputs[i].witness)
			return true;
	}
	return false;
}

string serialized_tx(struct bitcoin_tx *tx, bool bip144)
{
	int res;
	size_t len, written;
	u8 *serialized;;
	u8 flag = 0;

	if (bip144 && uses_witness(tx))
		flag |= WALLY_TX_FLAG_USE_WITNESS;

	res = wally_tx_get_length(tx->wtx, flag, &len);
	assert(res == WALLY_OK);

	string retval(len, '\0');
	res = wally_tx_to_bytes(tx->wtx, flag, (unsigned char *)&retval[0],
				retval.size(), &written);
	assert(res == WALLY_OK);
	assert(len == written);
	return retval;
}

/* Copied from ccan/mem/mem.h which the c++ compiler doesn't like */
static inline bool memeq(const void *a, size_t al, const void *b, size_t bl)
{
	return al == bl && !memcmp(a, b, bl);
}

} /* end namespace */

extern "C" {
const char *proxy_last_message(void)
{
	return last_message.c_str();
}

void proxy_setup()
{
	status_debug("%s:%d %s", __FILE__, __LINE__, __FUNCTION__);
	auto channel = grpc::CreateChannel("localhost:50051",
					   grpc::InsecureChannelCredentials());
	stub = Signer::NewStub(channel);
	last_message = "";
}

proxy_stat proxy_init_hsm(struct bip32_key_version *bip32_key_version,
			  struct chainparams const *chainparams,
			  struct secret *hsm_encryption_key,
			  struct privkey *privkey,
			  struct secret *seed,
			  struct secrets *secrets,
			  struct sha256 *shaseed,
			  struct secret *hsm_secret,
			  struct node_id *o_node_id)
{
	status_debug("%s:%d %s", __FILE__, __LINE__, __FUNCTION__);

	last_message = "";
	InitHSMReq req;

	auto kv = req.mutable_key_version();
	kv->set_pubkey_version(bip32_key_version->bip32_pubkey_version);
	kv->set_privkey_version(bip32_key_version->bip32_privkey_version);

	auto cp = req.mutable_chainparams();
	cp->set_network_name(chainparams->network_name);
	cp->set_bip173_name(chainparams->bip173_name);
	cp->set_bip70_name(chainparams->bip70_name);
	cp->set_genesis_blockhash(
		&chainparams->genesis_blockhash.shad.sha.u.u8,
		sizeof(chainparams->genesis_blockhash.shad.sha.u.u8));
	cp->set_rpc_port(chainparams->rpc_port);
	cp->set_cli(chainparams->cli);
	cp->set_cli_args(chainparams->cli_args);
	cp->set_cli_min_supported_version(
		chainparams->cli_min_supported_version);
	cp->set_dust_limit_sat(chainparams->dust_limit.satoshis);
	cp->set_max_funding_sat(chainparams->max_funding.satoshis);
	cp->set_max_payment_msat(chainparams->max_payment.millisatoshis);
	cp->set_when_lightning_became_cool(
		chainparams->when_lightning_became_cool);
	cp->set_p2pkh_version(chainparams->p2pkh_version);
	cp->set_p2sh_version(chainparams->p2sh_version);
	cp->set_testnet(chainparams->testnet);

	auto kv2 = cp->mutable_bip32_key_version();
	kv2->set_pubkey_version(
		chainparams->bip32_key_version.bip32_pubkey_version);
	kv2->set_privkey_version(
		chainparams->bip32_key_version.bip32_privkey_version);

	cp->set_is_elements(chainparams->is_elements);
	cp->set_fee_asset_tag(&chainparams->fee_asset_tag,
			      sizeof(chainparams->fee_asset_tag));

	/* FIXME - Sending the secret instead of generating on the remote. */
	req.set_hsm_secret(hsm_secret->data, sizeof(hsm_secret->data));

	ClientContext context;
	InitHSMRsp rsp;
	Status status = stub->InitHSM(&context, req, &rsp);
	if (status.ok()) {
		assert(rsp.self_node_id().length() == sizeof(o_node_id->k));
		memcpy(o_node_id->k, rsp.self_node_id().c_str(),
		       sizeof(o_node_id->k));
		assert(rsp.self_node_id().length() == sizeof(self_id.k));
		memcpy(self_id.k, rsp.self_node_id().c_str(),
		       sizeof(self_id.k));
		status_debug("%s:%d %s node_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(o_node_id).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_ecdh(struct pubkey *point,
			     struct secret *o_ss)
{
	status_debug(
		"%s:%d %s self_id=%s point=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_pubkey(point).c_str()
		);

	last_message = "";
	ECDHReq req;
	req.set_self_node_id((const char *) self_id.k, sizeof(self_id.k));
	req.set_point((const char *) point->pubkey.data,
		      sizeof(point->pubkey.data));

	ClientContext context;
	ECDHRsp rsp;
	Status status = stub->ECDH(&context, req, &rsp);
	if (status.ok()) {
		assert(rsp.shared_secret().length() == sizeof(o_ss->data));
		memcpy(o_ss->data, rsp.shared_secret().c_str(),
		       sizeof(o_ss->data));
		status_debug("%s:%d %s self_id=%s ss=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_hex(o_ss->data, sizeof(o_ss->data)).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_pass_client_hsmfd(
	struct node_id *peer_id,
	u64 dbid,
	u64 capabilities)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"capabilities=%" PRIu64 "",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		capabilities
		);

	last_message = "";
	PassClientHSMFdReq req;
	req.set_self_node_id((const char *) self_id.k, sizeof(self_id.k));
	req.set_channel_nonce(channel_nonce(peer_id, dbid));
	req.set_capabilities(capabilities);

	ClientContext context;
	PassClientHSMFdRsp rsp;
	Status status = stub->PassClientHSMFd(&context, req, &rsp);
	if (status.ok()) {
		status_debug("%s:%d %s self_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_sign_withdrawal_tx(
	struct node_id *peer_id,
	u64 dbid,
	struct amount_sat *satoshi_out,
	struct amount_sat *change_out,
	u32 change_keyindex,
	struct bitcoin_tx_output **outputs,
	struct utxo **utxos,
	struct bitcoin_tx *tx,
	u8 ****o_sigs)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"satoshi_out=%" PRIu64 " change_out=%" PRIu64 " "
		"change_keyindex=%u utxos=%s outputs=%s tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		satoshi_out->satoshis,
		change_out->satoshis,
		change_keyindex,
		dump_utxos((const struct utxo **)utxos).c_str(),
		dump_bitcoin_tx_outputs(
			(const struct bitcoin_tx_output **)outputs).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignWithdrawalTxReq req;
	req.set_self_node_id((const char *) self_id.k, sizeof(self_id.k));
	req.set_channel_nonce(channel_nonce(peer_id, dbid));
	req.set_raw_tx_bytes(serialized_tx(tx, true));

	assert(tx->wtx->num_inputs == tal_count(utxos));
	for (size_t ii = 0; ii < tx->wtx->num_inputs; ii++) {
	 	const struct utxo *in = utxos[ii];
		assert(!in->is_p2sh);
		SignDescriptor *desc = req.add_input_descs();
		desc->mutable_key_loc()->set_key_index(in->keyindex);
		desc->mutable_key_loc()->set_key_family(KeyLocator::layer_one);
		desc->mutable_output()->set_value(in->amount.satoshis);
	}

	/* We expect exactly two total ouputs, with one non-change. */
	assert(tx->wtx->num_outputs == 2);
	assert(tal_count(outputs) == 1);
	for (size_t ii = 0; ii < tx->wtx->num_outputs; ii++) {
	 	const struct wally_tx_output *out = &tx->wtx->outputs[ii];
		SignDescriptor *desc = req.add_output_descs();
		/* Does this output match the funding output? */
		if (memeq(out->script, out->script_len,
			  outputs[0]->script, tal_count(outputs[0]->script))) {
			/* Yes, this is the funding output. */
			desc->mutable_key_loc()->set_key_family(
				KeyLocator::unknown);
		} else {
			/* Nope, this must be the change output. */
			assert(out->satoshi == change_out->satoshis);
			desc->mutable_key_loc()->set_key_index(change_keyindex);
			desc->mutable_key_loc()->set_key_family(
				KeyLocator::layer_one);
		}
	}

	ClientContext context;
	SignWithdrawalTxRsp rsp;
	Status status = stub->SignWithdrawalTx(&context, req, &rsp);
	if (status.ok()) {
		*o_sigs = return_sigs(rsp.sigs());
		status_debug("%s:%d %s self_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_sign_remote_commitment_tx(
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
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"funding=%" PRIu64 " remote_funding_pubkey=%s "
		"output_witscripts=%s remote_per_commit=%s "
		"option_static_remotekey=%s  tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		funding->satoshis,
		dump_pubkey(remote_funding_pubkey).c_str(),
		dump_output_witscripts(output_witscripts).c_str(),
		dump_pubkey(remote_per_commit).c_str(),
		(option_static_remotekey ? "true" : "false"),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignRemoteCommitmentTxReq req;
	req.set_self_node_id((const char *) self_id.k, sizeof(self_id.k));
	req.set_channel_nonce(channel_nonce(peer_id, dbid));
	req.set_remote_funding_pubkey(
		(const char *) remote_funding_pubkey->pubkey.data,
		sizeof(remote_funding_pubkey->pubkey.data));
	req.set_remote_percommit_point(
		(const char *) remote_per_commit->pubkey.data,
		sizeof(remote_per_commit->pubkey.data));
	req.set_option_static_remotekey(option_static_remotekey);
	for (size_t ii = 0; ii < tal_count(output_witscripts); ii++)
		if (output_witscripts[ii]->ptr)
			req.add_output_witscripts(
				(const char *) output_witscripts[ii]->ptr,
				tal_count(output_witscripts[ii]->ptr));
		else
			req.add_output_witscripts("");
	req.set_raw_tx_bytes(serialized_tx(tx, true));

	assert(tx->wtx->num_inputs == 1);
	for (size_t ii = 0; ii < tx->wtx->num_inputs; ii++) {
		SignDescriptor *desc = req.add_input_descs();
		/* FIXME - Do we need to set key_index and key_family here? */
		desc->mutable_output()->set_value(funding->satoshis);
	}

	for (size_t ii = 0; ii < tx->wtx->num_outputs; ii++) {
	 	const struct wally_tx_output *out = &tx->wtx->outputs[ii];
		SignDescriptor *desc = req.add_output_descs();
		/* FIXME - We don't need to set *anything* here? */
	}

	ClientContext context;
	SignRemoteCommitmentTxRsp rsp;
	Status status = stub->SignRemoteCommitmentTx(&context, req, &rsp);
	if (status.ok()) {
		*o_sigs = return_sigs(rsp.sigs());
		status_debug("%s:%d %s self_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_sign_remote_htlc_tx(
	struct bitcoin_tx *tx,
	u8 *wscript,
	struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid,
	u8 ****o_sigs)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"wscript=%s tx=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignRemoteHTLCTxReq req;
	req.set_self_node_id((const char *) self_id.k, sizeof(self_id.k));
	req.set_channel_nonce(channel_nonce(peer_id, dbid));
	req.set_remote_per_commit_point(
		(const char *) remote_per_commit_point->pubkey.data,
		sizeof(remote_per_commit_point->pubkey.data));
	req.set_wscript(wscript, tal_count(wscript));
	req.set_raw_tx_bytes(serialized_tx(tx, true));

	assert(tx->wtx->num_inputs == 1);
	for (size_t ii = 0; ii < tx->wtx->num_inputs; ii++) {
	 	const struct wally_tx_input *in = &tx->wtx->inputs[ii];
		SignDescriptor *desc = req.add_input_descs();
		/* FIXME - Do we need to set key_index and key_family here? */
		desc->mutable_output()->set_value(
			tx->input_amounts[ii]->satoshis);
	}

	for (size_t ii = 0; ii < tx->wtx->num_outputs; ii++) {
	 	const struct wally_tx_output *out = &tx->wtx->outputs[ii];
		SignDescriptor *desc = req.add_output_descs();
		/* FIXME - We don't need to set *anything* here? */
	}

	ClientContext context;
	SignRemoteHTLCTxRsp rsp;
	Status status = stub->SignRemoteHTLCTx(&context, req, &rsp);
	if (status.ok()) {
		*o_sigs = return_sigs(rsp.sigs());
		status_debug("%s:%d %s self_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_get_per_commitment_point(
	struct node_id *peer_id,
	u64 dbid,
	u64 n,
	struct pubkey *o_per_commitment_point,
	struct secret **o_old_secret)
{
	status_debug(
		"%s:%d %s self_id=%s peer_id=%s dbid=%" PRIu64 " "
		"n=%" PRIu64 "",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		n
		);

	last_message = "";
	GetPerCommitmentPointReq req;
	req.set_self_node_id((const char *) self_id.k, sizeof(self_id.k));
	req.set_channel_nonce(channel_nonce(peer_id, dbid));
	req.set_n(n);

	ClientContext context;
	GetPerCommitmentPointRsp rsp;
	Status status = stub->GetPerCommitmentPoint(&context, req, &rsp);
	if (status.ok()) {
		/* per_commitment_point needs to be compressed DER */
		if (!pubkey_from_der(
			    (const u8*)rsp.per_commitment_point().c_str(),
			    rsp.per_commitment_point().length(),
			    o_per_commitment_point)) {
			last_message = "bad returned per_commitment_point";
			return PROXY_INTERNAL_ERROR;
		}
		assert(rsp.old_secret().empty() || (
			       rsp.old_secret().length() ==
			       sizeof((*o_old_secret)->data)));
		if (rsp.old_secret().empty())
			*o_old_secret = NULL;
		else {
			*o_old_secret = tal(tmpctx, struct secret);
			memcpy((*o_old_secret)->data, rsp.old_secret().c_str(),
			       sizeof((*o_old_secret)->data));
		}
		status_debug("%s:%d %s self_id=%s "
			     "per_commitment_point=%s old_secret=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_pubkey(o_per_commitment_point).c_str(),
			     (*o_old_secret ?
			      dump_hex((*o_old_secret)->data,
				       sizeof((*o_old_secret)->data)).c_str() :
			      "<none>"));
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_sign_invoice(
	u5 *u5bytes,
	u8 *hrpu8,
	u8 **o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s u5bytes=%s hrpu8=%s",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(u5bytes, tal_count(u5bytes)).c_str(),
		string((const char *)hrpu8, tal_count(hrpu8)).c_str()
		);

	last_message = "";
	SignInvoiceReq req;
	req.set_data_part(u5bytes, tal_count(u5bytes));
	req.set_human_readable_part((const char *)hrpu8, tal_count(hrpu8));

	ClientContext context;
	SignInvoiceRsp rsp;
	Status status = stub->SignInvoice(&context, req, &rsp);
	if (status.ok()) {
		*o_sig = tal_dup_arr(tmpctx, u8, (const u8*) rsp.sig().data(),
				     rsp.sig().size(), 0);
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_hex(*o_sig, tal_count(*o_sig)).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

proxy_stat proxy_handle_channel_update_sig(
	struct bitcoin_blkid *chain_hash,
	struct short_channel_id *scid,
	u32 timestamp,
	u8 message_flags,
	u8 channel_flags,
	u16 cltv_expiry_delta,
	struct amount_msat *htlc_minimum,
	u32 fee_base_msat,
	u32 fee_proportional_mill,
	struct amount_msat *htlc_maximum,
	secp256k1_ecdsa_signature *o_sig)
{
	status_debug(
		"%s:%d %s self_id=%s "
		"chain_hash=%s scid=%" PRIu64 " timestamp=%u "
		"message_flags=0x%x channel_flags=0x%x "
		"cltv_expiry_delta=%ud htlc_minimum=%" PRIu64 " "
		"fee_base_msat=%u fee_proportional_mill=%u "
		"htlc_maximum=%" PRIu64 "",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(chain_hash->shad.sha.u.u8,
			 sizeof(chain_hash->shad.sha.u.u8)).c_str(),
		scid->u64,
		timestamp,
		static_cast<u32>(message_flags),
		static_cast<u32>(channel_flags),
		static_cast<u32>(cltv_expiry_delta),
		htlc_minimum->millisatoshis,
		fee_base_msat,
		fee_proportional_mill,
		htlc_maximum->millisatoshis
		);

	last_message = "";
	ChannelUpdateSigReq req;
	req.set_self_node_id((const char *) self_id.k, sizeof(self_id.k));
	req.set_chain_hash((const char *) chain_hash->shad.sha.u.u8,
			   sizeof(chain_hash->shad.sha.u.u8));
	req.set_short_channel_id(scid->u64);
	req.set_timestamp(timestamp);
	req.set_message_flags(static_cast<u32>(message_flags));
	req.set_channel_flags(static_cast<u32>(channel_flags));
	req.set_cltv_expiry_delta(static_cast<u32>(cltv_expiry_delta));
	req.set_htlc_minimum(htlc_minimum->millisatoshis);
	req.set_fee_base_msat(fee_base_msat);
	req.set_fee_proportional_mill(fee_proportional_mill);
	req.set_htlc_maximum(htlc_maximum->millisatoshis);

	ClientContext context;
	ChannelUpdateSigRsp rsp;
	Status status = stub->ChannelUpdateSig(&context, req, &rsp);
	if (status.ok()) {
		// FIXME - UNCOMMENT RETURN VALUE WHEN IMPLEMENTED
		// assert(rsp.sig().size() == sizeof(o_sig->data));
		// memcpy(o_sig->data, (const u8*) rsp.sig().data(),
		//        sizeof(o_sig->data));
		status_debug("%s:%d %s self_id=%s sig=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_hex(o_sig, sizeof(o_sig->data)).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status.error_code());
	}
}

} /* extern "C" */
