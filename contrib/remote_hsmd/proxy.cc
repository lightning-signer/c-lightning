/* This needs to be first */
#define __STDC_FORMAT_MACROS

#include "contrib/remote_hsmd/dump.hpp"
#include "contrib/remote_hsmd/proxy.hpp"
#include "contrib/remote_hsmd/remotesigner.grpc.pb.h"
#include "contrib/remote_hsmd/remotesigner.pb.h"
extern "C" {
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <common/channel_type.h>
#include <common/derive_basepoints.h>
#include <common/features.h>
#include <common/hash_u5.h>
#include <common/htlc_wire.h>
#include <common/node_id.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/utxo.h>
}
#include <grpc++/grpc++.h>
#include <inttypes.h>
#include <iostream>
extern "C" {
#include <secp256k1_recovery.h>
}
#include <sstream>
#include <sys/types.h>	/* These two only needed for sleep() and getpid() */
#include <unistd.h>
extern "C" {
#include <wally_bip32.h>
#include <wally_psbt.h>
}


using std::cerr;
using std::endl;
using std::ostringstream;
using std::string;
using std::unique_ptr;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

using ::google::protobuf::RepeatedPtrField;

using namespace remotesigner;

namespace {
unique_ptr<Signer::Stub> stub;
string last_message;
struct node_id self_id;

proxy_stat map_status(Status const & status)
{
	StatusCode code = status.error_code();

	// FIXME - this is bogus, but the pytest framework loses our
	// status_unusual messages.
	if (code != StatusCode::OK) {
		cerr << "PID: " << getpid() << ' '
		     << "PROXY-HSMD grpc::StatusCode " << int(code)
 		     << ": " << status.error_message()
		     << endl;
	}
	switch (code) {
	case StatusCode::OK:			return PROXY_OK;
	case StatusCode::CANCELLED:		return PROXY_CANCELLED;
	case StatusCode::DEADLINE_EXCEEDED:	return PROXY_TIMEOUT;
	case StatusCode::UNAVAILABLE:		return PROXY_UNAVAILABLE;
	case StatusCode::INVALID_ARGUMENT:	return PROXY_INVALID_ARGUMENT;
	case StatusCode::INTERNAL:		return PROXY_INTERNAL_ERROR;
	default:
		cerr << "UNHANDLED grpc::StatusCode " << int(code)
		     << ": " << status.error_message()
		     << endl;
		abort();
	}
}

/* BIP144:
 * If the witness is empty, the old serialization format should be used. */
bool uses_witness(const struct wally_tx *wtx)
{
	size_t i;
	for (i = 0; i < wtx->num_inputs; i++) {
		if (wtx->inputs[i].witness)
			return true;
	}
	return false;
}


string serialized_wtx(struct wally_tx const *wtx, bool bip144)
{
	int res;
	size_t len, written;
	u8 *serialized;;
	u8 flag = 0;

	if (bip144 && uses_witness(wtx))
		flag |= WALLY_TX_FLAG_USE_WITNESS;

	res = wally_tx_get_length(wtx, flag, &len);
	assert(res == WALLY_OK);

	string retval(len, '\0');
	res = wally_tx_to_bytes(wtx, flag, (unsigned char *)&retval[0],
				retval.size(), &written);
	assert(res == WALLY_OK);
	assert(len == written);
	return retval;
}

void marshal_channel_nonce(struct node_id const *peer_id, u64 dbid,
			   ChannelNonce *o_np)
{
	o_np->set_data(string((char const *)peer_id->k, sizeof(peer_id->k)) +
		       string((char const *)&dbid, sizeof(dbid)));
}

void marshal_secret(struct secret const *ss, Secret *o_sp)
{
	o_sp->set_data(ss->data, sizeof(ss->data));
}

void marshal_bip32seed(struct secret const *ss, BIP32Seed *o_sp)
{
	o_sp->set_data(ss->data, sizeof(ss->data));
}

void marshal_node_id(struct node_id const *np, NodeId *o_np)
{
	o_np->set_data(np->k, sizeof(np->k));
}

void marshal_pubkey(struct pubkey const *pp, PubKey *o_pp)
{
	u8 pubkey_der[PUBKEY_CMPR_LEN];
	pubkey_to_der(pubkey_der, pp);

	o_pp->set_data(pubkey_der, sizeof(pubkey_der));
}

void marshal_utxo(struct utxo const *up, InputDescriptor *idesc)
{
	idesc->mutable_key_loc()->add_key_path(up->keyindex);
	idesc->set_value_sat(up->amount.satoshis);
	idesc->set_spend_type(up->is_p2sh
			      ? SpendType::P2SH_P2WPKH
			      : SpendType::P2WPKH);
	if (up->close_info) {
		UnilateralCloseInfo *cinfo =
			idesc->mutable_key_loc()->mutable_close_info();
		marshal_channel_nonce(&up->close_info->peer_id,
				      up->close_info->channel_id,
				      cinfo->mutable_channel_nonce());
		if (up->close_info->commitment_point)
			marshal_pubkey(up->close_info->commitment_point,
				       cinfo->mutable_commitment_point());
	}
}

void marshal_outpoint(struct bitcoin_txid const *txid, u16 txout, Outpoint *o_op)
{
	o_op->set_txid(txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
	o_op->set_index(txout);
}

void marshal_script(u8 const *script, string *o_script)
{
	if (script)
		o_script->assign((char const *)script, tal_count(script));
}

void marshal_bitcoin_signature(struct bitcoin_signature const *sp, BitcoinSignature *o_sig)
{
	u8 der[73];
	size_t len = signature_to_der(der, sp);
	o_sig->set_data(der, len);
}

void marshal_basepoints(struct basepoints const *bps,
			struct pubkey *funding_pubkey,
			Basepoints * o_bps)
{
	marshal_pubkey(&bps->revocation, o_bps->mutable_revocation());
	marshal_pubkey(&bps->payment, o_bps->mutable_payment());
	marshal_pubkey(&bps->htlc, o_bps->mutable_htlc());
	marshal_pubkey(&bps->delayed_payment, o_bps->mutable_delayed_payment());
	marshal_pubkey(funding_pubkey, o_bps->mutable_funding_pubkey());
}

void marshal_single_input_tx(struct bitcoin_tx const *tx,
			     u8 const *redeem_script,
			     Transaction *o_tp)
{
	assert(tx->psbt->num_outputs == tx->wtx->num_outputs);

	o_tp->set_raw_tx_bytes(serialized_wtx(tx->wtx, true));

	assert(tx->wtx->num_inputs == 1);
	assert(tx->psbt->num_inputs == 1);
	InputDescriptor *idesc = o_tp->add_input_descs();
	idesc->set_value_sat(psbt_input_get_amount(tx->psbt, 0).satoshis);
	if (redeem_script)
		idesc->set_redeem_script((const char *) redeem_script,
					 tal_count(redeem_script));

	for (size_t ii = 0; ii < tx->wtx->num_outputs; ii++) {
		OutputDescriptor *odesc = o_tp->add_output_descs();

		// Add witness script
		if (tx->psbt->outputs[ii].witness_script_len)
			odesc->set_witscript(
				(const char *)
				tx->psbt->outputs[ii].witness_script,
				tx->psbt->outputs[ii].witness_script_len);

		// Add keypath
		struct wally_map *mp = &tx->psbt->outputs[ii].keypaths;
		if (mp->num_items == 1) {
			const struct wally_map_item *ip = &mp->items[0];
			size_t npath =
				(ip->value_len - BIP32_KEY_FINGERPRINT_LEN) / sizeof(uint32_t);
			uint32_t *path = (uint32_t *) (ip->value + BIP32_KEY_FINGERPRINT_LEN);
			for (size_t jj = 0; jj < npath; ++jj) {
				odesc->mutable_key_loc()->add_key_path(le32_to_cpu(path[jj]));
			}
		}

	}
}

void marshal_rhashes(const struct sha256 *rhashes,
		     RepeatedPtrField<string> *payment_hashes)
{
	for (size_t ii = 0; ii < tal_count(rhashes); ++ii) {
		payment_hashes->Add(string((const char *) &rhashes[ii],
					   sizeof(struct sha256)));
	}
}

void marshal_htlc(const struct existing_htlc *htlc, HTLCInfo *o_htlc)
{
	o_htlc->set_value_sat(htlc->amount.millisatoshis / 1000);
	o_htlc->set_payment_hash(&htlc->payment_hash, sizeof(htlc->payment_hash));
	o_htlc->set_cltv_expiry(htlc->cltv_expiry);
}

void unmarshal_secret(Secret const &ss, struct secret *o_sp)
{
	assert(ss.data().size() == sizeof(o_sp->data));
	memcpy(o_sp->data, ss.data().data(), sizeof(o_sp->data));

}
void unmarshal_node_id(NodeId const &nn, struct node_id *o_np)
{
	assert(nn.data().size() == sizeof(o_np->k));
	memcpy(o_np->k, nn.data().data(), sizeof(o_np->k));
}

void unmarshal_pubkey(PubKey const &pk, struct pubkey *o_pp)
{
	bool ok = pubkey_from_der((u8 const *)pk.data().data(),
				  pk.data().size(),
				  o_pp);
	assert(ok);
}

void unmarshal_ext_pubkey(ExtPubKey const &xpk, struct ext_key *o_xp)
{
	int rv = bip32_key_from_base58(xpk.encoded().data(), o_xp);
	assert(rv == WALLY_OK);
}

void unmarshal_bitcoin_signature(BitcoinSignature const &bs,
			      struct bitcoin_signature *o_sig)
{
	bool ok = signature_from_der(
		(const u8*)bs.data().data(),
		bs.data().size(),
		o_sig);
	assert(ok);
}

void unmarshal_ecdsa_signature(ECDSASignature const &es,
			    secp256k1_ecdsa_signature *o_sig)
{
	int ok = secp256k1_ecdsa_signature_parse_der(
		secp256k1_ctx,
		o_sig,
		(const u8*)es.data().data(),
		es.data().size());
	assert(ok);
}

void unmarshal_ecdsa_recoverable_signature(ECDSARecoverableSignature const &es,
			    secp256k1_ecdsa_recoverable_signature *o_sig)
{
	assert(es.data().size() == 65);
	int recid = es.data().data()[64];
	int ok = secp256k1_ecdsa_recoverable_signature_parse_compact(
		secp256k1_ctx,
		o_sig,
		(const u8*)es.data().data(),
		recid);
	assert(ok);
}

void unmarshal_witnesses(RepeatedPtrField<Witness> const &wits, u8 ****o_wits)
{
	u8 ***owits = NULL;
	int nwits = wits.size();
	if (nwits > 0) {
		owits = tal_arrz(tmpctx, u8**, nwits);
		for (size_t ii = 0; ii < nwits; ++ii) {
			owits[ii] = tal_arrz(owits, u8*, 2);
			Witness const &wit = wits.Get(ii);
			const string &sig = wit.signature().data();
			const string &pubkey = wit.pubkey().data();
			owits[ii][0] = tal_arr(owits[ii], u8, sig.size());
			memcpy(owits[ii][0], sig.data(), sig.size());
			owits[ii][1] = tal_arr(owits[ii], u8, pubkey.size());
			memcpy(owits[ii][1], pubkey.data(), pubkey.size());
		}
	}
	*o_wits = owits;
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
	const char *endpointvar = getenv("REMOTE_HSMD_ENDPOINT");
	const char *endpoint = endpointvar != NULL ? endpointvar : "localhost:50051";
	STATUS_DEBUG("%s:%d %s pid:%d, endpoint:%s", __FILE__, __LINE__, __FUNCTION__,
		     getpid(), endpoint);
	auto channel = grpc::CreateChannel(endpoint,
					   grpc::InsecureChannelCredentials());
	stub = Signer::NewStub(channel);
	last_message = "";
}

void proxy_set_node_id(const struct node_id *node_id)
{
	self_id = *node_id;
}

proxy_stat proxy_init_hsm(struct bip32_key_version *bip32_key_version,
			  struct chainparams const *chainparams,
			  bool coldstart,
			  struct secret *hsm_secret,
			  struct node_id *o_node_id)
{
	STATUS_DEBUG(
		"%s:%d %s { \"hsm_secret\":%s, \"coldstart\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		hsm_secret != NULL ? dump_secret(hsm_secret).c_str() : "\"\"",
		coldstart ? "true" : "false"
		);

	last_message = "";
	InitRequest req;

	auto nc = req.mutable_node_config();
	nc->set_key_derivation_style(NodeConfig::NATIVE);

	auto cp = req.mutable_chainparams();
	cp->set_network_name(chainparams->network_name);

	req.set_coldstart(coldstart);

	// If we are running integration tests the secret will be forced.
	if (hsm_secret != NULL)
		marshal_bip32seed(hsm_secret, req.mutable_hsm_secret());

	ClientContext context;
	InitReply rsp;
	Status status = stub->Init(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_node_id(rsp.node_id(), o_node_id);
		unmarshal_node_id(rsp.node_id(), &self_id);
		STATUS_DEBUG("%s:%d %s { \"node_id\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(o_node_id).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_get_ext_pub_key(struct ext_key *o_ext_pubkey)
{
	// TODO
	STATUS_DEBUG("%s:%d %s", __FILE__, __LINE__, __FUNCTION__);

	last_message = "";
	GetExtPubKeyRequest req;

	marshal_node_id(&self_id, req.mutable_node_id());

	ClientContext context;
	GetExtPubKeyReply rsp;
	Status status = stub->GetExtPubKey(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ext_pubkey(rsp.xpub(), o_ext_pubkey);
		STATUS_DEBUG("%s:%d %s "
			     "{ \"ext_pubkey\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_ext_pubkey(o_ext_pubkey).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_ecdh(const struct pubkey *point,
			     struct secret *o_ss)
{
	STATUS_DEBUG(
		"%s:%d %s { \"self_id\":%s, \"point\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_pubkey(point).c_str()
		);

	last_message = "";
	ECDHRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_pubkey(point, req.mutable_point());

	ClientContext context;
	ECDHReply rsp;
	Status status = stub->ECDH(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_secret(rsp.shared_secret(), o_ss);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"ss\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secret(o_ss).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_pass_client_hsmfd(
	struct node_id *peer_id,
	u64 dbid,
	u64 capabilities)
{
	STATUS_DEBUG(
		"%s:%d %s "
		"{ \"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"capabilities\":%" PRIu64 " }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		capabilities
		);

/* We used to synthesize NewChannel here, but now have an explicit
 * interface.  This whole method can go away. */
#if 0
	last_message = "";
	NewChannelRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());

	ClientContext context;
	NewChannelReply rsp;
	Status status = stub->NewChannel(&context, req, &rsp);
	if (status.ok()) {
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s }",
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
		return map_status(status);
	}
#else
	last_message = "success";
	return PROXY_OK;
#endif
}

proxy_stat proxy_handle_new_channel(
	struct node_id *peer_id,
	u64 dbid)
{
	STATUS_DEBUG(
		"%s:%d %s "
		"{ \"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 " }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid);

	last_message = "";
	NewChannelRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce0());

	ClientContext context;
	NewChannelReply rsp;
	Status status = stub->NewChannel(&context, req, &rsp);
	if (status.ok()) {
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s }",
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
		return map_status(status);
	}
}

proxy_stat proxy_handle_ready_channel(
	struct node_id *peer_id,
	u64 dbid,
	bool is_outbound,
	struct amount_sat *channel_value,
	struct amount_msat *push_value,
	struct bitcoin_txid *funding_txid,
	u16 funding_txout,
	u16 holder_to_self_delay,
	u8 *holder_shutdown_script,
	struct basepoints *counterparty_basepoints,
	struct pubkey *counterparty_funding_pubkey,
	u16 counterparty_to_self_delay,
	u8 *counterparty_shutdown_script,
	struct channel_type *channel_type)
{
	bool option_static_remotekey = channel_type_has(channel_type, OPT_STATIC_REMOTEKEY);
	bool option_anchor_outputs = channel_type_has(channel_type, OPT_ANCHOR_OUTPUTS);

	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"is_outbound\":%s, \"channel_value\":%" PRIu64 ", "
		"\"push_value\":%" PRIu64 ", "
		"\"funding_txid\":%s, \"funding_txout\":%d, "
		"\"holder_to_self_delay\":%d, \"holder_shutdown_script\":%s, "
		"\"counterparty_basepoints\":%s, "
		"\"counterparty_funding_pubkey\":%s, "
		"\"counterparty_to_self_delay\":%d, "
		"\"counterparty_shutdown_script\":%s, "
		"\"option_static_remotekey\":%s, "
		"\"option_anchor_outputs\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		(is_outbound ? "true" : "false"),
		channel_value->satoshis,
		push_value->millisatoshis,
		dump_bitcoin_txid(funding_txid).c_str(),
		funding_txout,
		holder_to_self_delay,
		dump_hex(holder_shutdown_script,
			 tal_count(holder_shutdown_script)).c_str(),
		dump_basepoints(counterparty_basepoints).c_str(),
		dump_pubkey(counterparty_funding_pubkey).c_str(),
		counterparty_to_self_delay,
		dump_hex(counterparty_shutdown_script,
			 tal_count(counterparty_shutdown_script)).c_str(),
		(option_static_remotekey ? "true" : "false"),
		(option_anchor_outputs ? "true" : "false")
		);

	last_message = "";
	ReadyChannelRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce0());
	req.set_is_outbound(is_outbound);
	req.set_channel_value_sat(channel_value->satoshis);
	req.set_push_value_msat(push_value->millisatoshis);
	marshal_outpoint(funding_txid,
			 funding_txout, req.mutable_funding_outpoint());
	req.set_holder_selected_contest_delay(holder_to_self_delay);
	marshal_script(holder_shutdown_script,
		       req.mutable_holder_shutdown_script());
	marshal_basepoints(counterparty_basepoints, counterparty_funding_pubkey,
			   req.mutable_counterparty_basepoints());
	req.set_counterparty_selected_contest_delay(counterparty_to_self_delay);
	marshal_script(counterparty_shutdown_script,
		       req.mutable_counterparty_shutdown_script());
	if (option_anchor_outputs)
		req.set_commitment_type(ReadyChannelRequest_CommitmentType_ANCHORS);
	else if (option_static_remotekey)
		req.set_commitment_type(ReadyChannelRequest_CommitmentType_STATIC_REMOTEKEY);
	else
		req.set_commitment_type(ReadyChannelRequest_CommitmentType_LEGACY);

	ClientContext context;
	ReadyChannelReply rsp;
	Status status = stub->ReadyChannel(&context, req, &rsp);
	if (status.ok()) {
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s }",
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
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_withdrawal_tx(
	struct bitcoin_tx_output **outputs,
	struct utxo **utxos,
	struct wally_psbt *psbt,
	u8 ****o_wits)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, "
		"\"utxos\":%s, \"outputs\":%s, \"psbt\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_utxos((const struct utxo **)utxos).c_str(),
		dump_bitcoin_tx_outputs(
			(const struct bitcoin_tx_output **)outputs).c_str(),
		dump_wally_psbt(psbt).c_str()
		);

	last_message = "";

	// This code is mimicking psbt_txid at bitcoin/psbt.c:796:
	//
	/* You can *almost* take txid of global tx.  But @niftynei thought
	 * about this far more than me and pointed out that P2SH
	 * inputs would not be represented, so here we go. */
	struct wally_tx *tx;
	tal_wally_start();
	wally_tx_clone_alloc(psbt->tx, 0, &tx);
	for (size_t i = 0; i < tx->num_inputs; i++) {
		if (psbt->inputs[i].final_scriptsig) {
			wally_tx_set_input_script(tx, i,
						  psbt->inputs[i].final_scriptsig,
						  psbt->inputs[i].final_scriptsig_len);
		} else if (psbt->inputs[i].redeem_script) {
			u8 *script;

			/* P2SH requires push of the redeemscript, from libwally src */
			script = tal_arr(tmpctx, u8, 0);
			script_push_bytes(&script,
					  psbt->inputs[i].redeem_script,
					  psbt->inputs[i].redeem_script_len);
			wally_tx_set_input_script(tx, i, script, tal_bytelen(script));
		}
	}
	tal_wally_end(tal_steal(psbt, tx));


	SignFundingTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());

	// Serialize the tx we modified above which includes witscripts.
	req.mutable_tx()->set_raw_tx_bytes(serialized_wtx(tx, true));

	assert(psbt->tx->num_inputs >= tal_count(utxos));
	size_t uu = 0;
	for (size_t ii = 0; ii < psbt->tx->num_inputs; ++ii) {
		InputDescriptor *idesc = req.mutable_tx()->add_input_descs();
		if (uu < tal_count(utxos) &&
		    wally_tx_input_spends(&psbt->tx->inputs[ii],
					  &utxos[uu]->outpoint)) {
			marshal_utxo(utxos[uu], idesc);
			++uu;
		}
	}
	assert(uu == tal_count(utxos));

	for (size_t ii = 0; ii < psbt->tx->num_outputs; ++ii) {
		OutputDescriptor *odesc = req.mutable_tx()->add_output_descs();
		struct wally_map *mp = &psbt->outputs[ii].keypaths;
		if (mp->num_items == 1) {
			const struct wally_map_item *ip = &mp->items[0];
			size_t npath =
				(ip->value_len - BIP32_KEY_FINGERPRINT_LEN) / sizeof(uint32_t);
			uint32_t *path = (uint32_t *) (ip->value + BIP32_KEY_FINGERPRINT_LEN);
			for (size_t jj = 0; jj < npath; ++jj) {
				odesc->mutable_key_loc()->add_key_path(le32_to_cpu(path[jj]));
			}
		}
	}

	ClientContext context;
	SignFundingTxReply rsp;
	Status status = stub->SignFundingTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_witnesses(rsp.witnesses(), o_wits);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"witnesses\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_witnesses((u8 const ***) *o_wits).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_remote_commitment_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *counterparty_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	const struct pubkey *remote_per_commit,
	struct existing_htlc **htlcs,
	u64 commit_num, u32 feerate,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"counterparty_funding_pubkey\":%s, "
		"\"remote_per_commit\":%s, \"tx\":%s, "
		"\"htlcs\":%s, "
		"\"commit_num\":%" PRIu64 ", "
		"\"feerate\":%d }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_pubkey(counterparty_funding_pubkey).c_str(),
		dump_pubkey(remote_per_commit).c_str(),
		dump_tx(tx).c_str(),
		dump_htlcs((const struct existing_htlc **) htlcs, tal_count(htlcs)).c_str(),
		commit_num, feerate
		);

	last_message = "";
	SignCounterpartyCommitmentTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_pubkey(remote_per_commit,
		       req.mutable_remote_per_commit_point());
	marshal_single_input_tx(tx, NULL, req.mutable_tx());
	for (size_t ii = 0; ii < tal_count(htlcs); ++ii) {
		if (htlc_state_owner(htlcs[ii]->state) == REMOTE) {
			marshal_htlc(htlcs[ii], req.add_offered_htlcs());
		} else {
			marshal_htlc(htlcs[ii], req.add_received_htlcs());
		}
	}
	req.set_commit_num(commit_num);
	req.set_feerate_sat_per_kw(feerate);

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignCounterpartyCommitmentTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_get_per_commitment_point(
	struct node_id *peer_id,
	u64 dbid,
	u64 n,
	struct pubkey *o_per_commitment_point,
	struct secret **o_old_secret)
{
	STATUS_DEBUG("%s:%d %s { "
		     "\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		     "\"n\":%" PRIu64 " }",
		     __FILE__, __LINE__, __FUNCTION__,
		     dump_node_id(&self_id).c_str(),
		     dump_node_id(peer_id).c_str(),
		     dbid,
		     n
		);

	last_message = "";
	GetPerCommitmentPointRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_n(n);

	ClientContext context;
	GetPerCommitmentPointReply rsp;
	Status status = stub->GetPerCommitmentPoint(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_pubkey(rsp.per_commitment_point(),
			      o_per_commitment_point);
		if (rsp.old_secret().data().empty()) {
			*o_old_secret = NULL;
		} else {
			*o_old_secret = tal_arr(tmpctx, struct secret, 1);
			unmarshal_secret(rsp.old_secret(), *o_old_secret);
		}
		STATUS_DEBUG("%s:%d %s { "
			     "\"self_id\":%s, "
			     "\"per_commitment_point\":%s, "
			     "\"old_secret\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_pubkey(o_per_commitment_point).c_str(),
			     (*o_old_secret ?
			      dump_secret(*o_old_secret).c_str() : "<none>"));
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_invoice(
	u5 *u5bytes,
	u8 *hrpu8,
	secp256k1_ecdsa_recoverable_signature *o_sig)
{
	STATUS_DEBUG("%s:%d %s { "
		     "\"self_id\":%s, \"u5bytes\":%s \"hrpu8\":%s }",
		     __FILE__, __LINE__, __FUNCTION__,
		     dump_node_id(&self_id).c_str(),
		     dump_hex(u5bytes, tal_count(u5bytes)).c_str(),
		     string((const char *)hrpu8, tal_count(hrpu8)).c_str()
		);

	last_message = "";
	SignInvoiceRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_data_part(u5bytes, tal_count(u5bytes));
	req.set_human_readable_part((const char *)hrpu8, tal_count(hrpu8));

	ClientContext context;
	RecoverableNodeSignatureReply rsp;
	Status status = stub->SignInvoice(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_recoverable_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_recoverable_signature(
				     o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_message(
	u8 *msg,
	secp256k1_ecdsa_recoverable_signature *o_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { \"self_id\":%s, \"msg\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(msg, tal_count(msg)).c_str()
		);

	last_message = "";
	SignMessageRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_message(msg, tal_count(msg));

	ClientContext context;
	RecoverableNodeSignatureReply rsp;
	Status status = stub->SignMessage(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_recoverable_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_recoverable_signature(
				     o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_channel_update_sig(
	u8 *channel_update,
	secp256k1_ecdsa_signature *o_sig)
{
	STATUS_DEBUG("%s:%d %s { "
		     "\"self_id\":%s, \"channel_update\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(channel_update, tal_count(channel_update)).c_str());

	/* Skip the portion of the channel_update that we don't sign */
	size_t offset = 2 + 64;	/* sizeof(type) + sizeof(signature) */
	size_t annsz = tal_count(channel_update);

	last_message = "";
	SignChannelUpdateRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_channel_update(channel_update + offset, annsz - offset);

	ClientContext context;
	NodeSignatureReply rsp;
	Status status = stub->SignChannelUpdate(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_get_channel_basepoints(
	struct node_id *peer_id,
	u64 dbid,
	struct basepoints *o_basepoints,
	struct pubkey *o_funding_pubkey)
{
	STATUS_DEBUG("%s:%d %s { "
		     "\"self_id\":%s, \"peer_id\":%s \"dbid\":%" PRIu64 " }",
		     __FILE__, __LINE__, __FUNCTION__,
		     dump_node_id(&self_id).c_str(),
		     dump_node_id(peer_id).c_str(),
		     dbid
		);

	last_message = "";
	GetChannelBasepointsRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());

	ClientContext context;
	GetChannelBasepointsReply rsp;
	Status status = stub->GetChannelBasepoints(&context, req, &rsp);
	if (status.ok()) {
		Basepoints const & bps = rsp.basepoints();
		unmarshal_pubkey(bps.revocation(), &o_basepoints->revocation);
		unmarshal_pubkey(bps.payment(), &o_basepoints->payment);
		unmarshal_pubkey(bps.htlc(), &o_basepoints->htlc);
		unmarshal_pubkey(bps.delayed_payment(),
				 &o_basepoints->delayed_payment);
		unmarshal_pubkey(bps.funding_pubkey(), o_funding_pubkey);
		STATUS_DEBUG("%s:%d %s { "
			     "\"self_id\":%s, \"basepoints\":%s, "
			     "\"pubkey\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_basepoints(o_basepoints).c_str(),
			     dump_pubkey(o_funding_pubkey).c_str());

		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_mutual_close_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *counterparty_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"counterparty_funding_pubkey\":%s, \"tx\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_pubkey(counterparty_funding_pubkey).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignMutualCloseTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_single_input_tx(tx, NULL, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignMutualCloseTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_commitment_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *counterparty_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	struct existing_htlc **htlcs,
	u64 commit_num, u32 feerate,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"counterparty_funding_pubkey\":%s, \"tx\":%s, "
		"\"htlcs\":%s, "
		"\"commit_num\":%" PRIu64 ", "
		"\"feerate\":%d }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_pubkey(counterparty_funding_pubkey).c_str(),
		dump_tx(tx).c_str(),
		dump_htlcs((const struct existing_htlc **) htlcs, tal_count(htlcs)).c_str(),
		commit_num, feerate
		);

	last_message = "";
	SignHolderCommitmentTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_single_input_tx(tx, NULL, req.mutable_tx());
	for (size_t ii = 0; ii < tal_count(htlcs); ++ii) {
		if (htlc_state_owner(htlcs[ii]->state) == LOCAL) {
			marshal_htlc(htlcs[ii], req.add_offered_htlcs());
		} else {
			marshal_htlc(htlcs[ii], req.add_received_htlcs());
		}
	}
	req.set_commit_num(commit_num);
	req.set_feerate_sat_per_kw(feerate);

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignHolderCommitmentTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_validate_commitment_tx(
	struct bitcoin_tx *tx,
	struct node_id *peer_id,
	u64 dbid,
	struct existing_htlc **htlcs,
	u64 commit_num, u32 feerate,
	struct bitcoin_signature *commit_sig,
	struct bitcoin_signature *htlc_sigs,
	struct secret **o_old_secret,
	struct pubkey *o_next_per_commitment_point)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"tx\":%s, "
		"\"htlcs\":%s, "
		"\"commit_num\":%" PRIu64 ", "
		"\"feerate\":%d, "
		"\"commit_sig\":%s, \"htlc_sigs\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_tx(tx).c_str(),
		dump_htlcs((const struct existing_htlc **) htlcs, tal_count(htlcs)).c_str(),
		commit_num, feerate,
		dump_bitcoin_signature(commit_sig).c_str(),
		dump_htlc_signatures(htlc_sigs).c_str()
		);

	last_message = "";
	ValidateHolderCommitmentTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_single_input_tx(tx, NULL, req.mutable_tx());
	for (size_t ii = 0; ii < tal_count(htlcs); ++ii) {
		if (htlc_state_owner(htlcs[ii]->state) == LOCAL) {
			marshal_htlc(htlcs[ii], req.add_offered_htlcs());
		} else {
			marshal_htlc(htlcs[ii], req.add_received_htlcs());
		}
	}
	req.set_commit_num(commit_num);
	req.set_feerate_sat_per_kw(feerate);
	marshal_bitcoin_signature(commit_sig, req.mutable_commit_signature());
	for (size_t ii = 0; ii < tal_count(htlc_sigs); ++ii) {
		marshal_bitcoin_signature(&htlc_sigs[ii], req.add_htlc_signatures());
	}

	ClientContext context;
	ValidateHolderCommitmentTxReply rsp;
	Status status = stub->ValidateHolderCommitmentTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_pubkey(rsp.next_per_commitment_point(), o_next_per_commitment_point);
		if (rsp.old_secret().data().empty()) {
			*o_old_secret = NULL;
		} else {
			*o_old_secret = tal_arr(tmpctx, struct secret, 1);
			unmarshal_secret(rsp.old_secret(), *o_old_secret);
		}
		STATUS_DEBUG("%s:%d %s { "
			     "\"self_id\":%s, "
			     "\"next_per_commitment_point\":%s, "
			     "\"old_secret\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_pubkey(o_next_per_commitment_point).c_str(),
			     (*o_old_secret ?
			      dump_secret(*o_old_secret).c_str() : "<none>"));
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_validate_revocation(
	struct node_id *peer_id,
	u64 dbid,
	u64 revoke_num,
	struct secret *old_secret)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"revoke_num\":%" PRIu64 ", "
		"\"old_secret\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		revoke_num,
		dump_secret(old_secret).c_str()
		);

	last_message = "";
	ValidateCounterpartyRevocationRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_revoke_num(revoke_num);
	marshal_secret(old_secret, req.mutable_old_secret());

	ClientContext context;
	ValidateCounterpartyRevocationReply rsp;
	Status status = stub->ValidateCounterpartyRevocation(&context, req, &rsp);
	if (status.ok()) {
		STATUS_DEBUG("%s:%d %s { "
			     "\"self_id\":%s } ",
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
		return map_status(status);
	}
}

proxy_stat proxy_handle_cannouncement_sig(
	struct node_id *peer_id,
	u64 dbid,
	u8 *channel_announcement,
	secp256k1_ecdsa_signature *o_node_sig,
	secp256k1_ecdsa_signature *o_bitcoin_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"ca\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(channel_announcement,
			 tal_count(channel_announcement)).c_str()
		);

	/* Skip the portion of the channel_update that we don't sign */
	size_t offset = 2 + 256; /* sizeof(type) + 4*sizeof(signature) */
	size_t annsz = tal_count(channel_announcement);

	last_message = "";
	SignChannelAnnouncementRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_channel_announcement(channel_announcement + offset,
				     annsz - offset);

	ClientContext context;
	SignChannelAnnouncementReply rsp;
	Status status = stub->SignChannelAnnouncement(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_signature(rsp.node_signature(), o_node_sig);
		unmarshal_ecdsa_signature(rsp.bitcoin_signature(), o_bitcoin_sig);
		STATUS_DEBUG("%s:%d %s { "
			     "\"self_id\":%s, \"node_sig\":%s, "
			     "\"bitcoin_sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_signature(o_node_sig).c_str(),
			     dump_secp256k1_ecdsa_signature(o_bitcoin_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_local_htlc_tx(
	struct bitcoin_tx *tx,
	u64 commit_num,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"commit_num\":%" PRIu64 ", \"wscript\":%s, \"tx\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		commit_num,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignHolderHTLCTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_n(commit_num);
	marshal_single_input_tx(tx, wscript, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignHolderHTLCTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str()
			);
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_remote_htlc_tx(
	struct bitcoin_tx *tx,
	u8 *wscript,
	const struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG("%s:%d %s { "
		     "\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		     "\"wscript\":%s, \"tx\":%s }",
		     __FILE__, __LINE__, __FUNCTION__,
		     dump_node_id(&self_id).c_str(),
		     dump_node_id(peer_id).c_str(),
		     dbid,
		     dump_hex(wscript, tal_count(wscript)).c_str(),
		     dump_tx(tx).c_str()
		);

	last_message = "";
	SignCounterpartyHTLCTxRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_pubkey(remote_per_commit_point,
		       req.mutable_remote_per_commit_point());
	marshal_single_input_tx(tx, wscript, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignCounterpartyHTLCTx(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s. \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_delayed_payment_to_us(
	struct bitcoin_tx *tx,
	u64 commit_num,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG("%s:%d %s { "
		     "\"self_id\":%s, \"peer_id\":%s, dbid=%" PRIu64 ", "
		     "\"commit_num\":=%" PRIu64 ", "
		     "\"wscript\":%s, \"tx\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		commit_num,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignDelayedSweepRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_input(0);
	req.set_commitment_number(commit_num);
	marshal_single_input_tx(tx, wscript, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignDelayedSweep(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_remote_htlc_to_us(
	struct bitcoin_tx *tx,
	u8 *wscript,
	const struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG("%s:%d %s { "
		     "\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		     "\"wscript\":%s, \"tx\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignCounterpartyHTLCSweepRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_input(0);
	marshal_pubkey(remote_per_commit_point,
		       req.mutable_remote_per_commit_point());
	marshal_single_input_tx(tx, wscript, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignCounterpartyHTLCSweep(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_penalty_to_us(
	struct bitcoin_tx *tx,
	struct secret *revocation_secret,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { "
		"\"self_id\":%s, \"peer_id\":%s, \"dbid\":%" PRIu64 ", "
		"\"revocation_secret\":%s, \"wscript\":%s, \"tx\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		dump_hex(revocation_secret->data,
			 sizeof(revocation_secret->data)).c_str(),
		dump_hex(wscript, tal_count(wscript)).c_str(),
		dump_tx(tx).c_str()
		);

	last_message = "";
	SignJusticeSweepRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	marshal_secret(revocation_secret, req.mutable_revocation_secret());
	req.set_input(0);
	marshal_single_input_tx(tx, wscript, req.mutable_tx());

	ClientContext context;
	SignatureReply rsp;
	Status status = stub->SignJusticeSweep(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_bitcoin_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_bitcoin_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_check_future_secret(
	struct node_id *peer_id,
	u64 dbid,
	u64 n,
	struct secret *suggested,
	bool *o_correct)
{
	STATUS_DEBUG(
		"%s:%d %s { \"self_id\":%s, \"peer_id\":%s, "
		"\"dbid\":%" PRIu64 ", "
		"\"n\":%" PRIu64 ", \"suggested\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_node_id(peer_id).c_str(),
		dbid,
		n,
		dump_hex(suggested->data, sizeof(suggested->data)).c_str()
		);

	last_message = "";
	CheckFutureSecretRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	marshal_channel_nonce(peer_id, dbid, req.mutable_channel_nonce());
	req.set_n(n);
	marshal_secret(suggested, req.mutable_suggested());

	ClientContext context;
	CheckFutureSecretReply rsp;
	Status status = stub->CheckFutureSecret(&context, req, &rsp);
	if (status.ok()) {
		*o_correct = rsp.correct();
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"correct\":%d }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(), int(*o_correct));
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

proxy_stat proxy_handle_sign_node_announcement(
	u8 *node_announcement,
	secp256k1_ecdsa_signature *o_sig)
{
	STATUS_DEBUG(
		"%s:%d %s { \"self_id\":%s, \"ann\":%s }",
		__FILE__, __LINE__, __FUNCTION__,
		dump_node_id(&self_id).c_str(),
		dump_hex(node_announcement,
			 tal_count(node_announcement)).c_str()
		);

	/* Skip the portion of the channel_update that we don't sign */
	size_t offset = 2 + 64;	/* sizeof(type) + sizeof(signature) */
	size_t annsz = tal_count(node_announcement);

	last_message = "";
	SignNodeAnnouncementRequest req;
	marshal_node_id(&self_id, req.mutable_node_id());
	req.set_node_announcement(node_announcement + offset, annsz - offset);

	ClientContext context;
	NodeSignatureReply rsp;
	Status status = stub->SignNodeAnnouncement(&context, req, &rsp);
	if (status.ok()) {
		unmarshal_ecdsa_signature(rsp.signature(), o_sig);
		STATUS_DEBUG("%s:%d %s { \"self_id\":%s, \"sig\":%s }",
			     __FILE__, __LINE__, __FUNCTION__,
			     dump_node_id(&self_id).c_str(),
			     dump_secp256k1_ecdsa_signature(o_sig).c_str());
		last_message = "success";
		return PROXY_OK;
	} else {
		status_unusual("%s:%d %s: self_id=%s %s",
			       __FILE__, __LINE__, __FUNCTION__,
			       dump_node_id(&self_id).c_str(),
			       status.error_message().c_str());
		last_message = status.error_message();
		return map_status(status);
	}
}

// FIXME - These routines allows us to pretty print to stderr from C
// code.  Probably should remove it in production ...

void print_tx(char const *tag, struct bitcoin_tx const *tx)
{
	fprintf(stderr, "%s: bitcoin_tx=%s\n", tag, dump_tx(tx).c_str());
}

void print_psbt(char const *tag, const struct wally_psbt *psbt)
{
	fprintf(stderr, "%s: wally_psbt=%s\n",
		tag, dump_wally_psbt(psbt).c_str());
}

} /* extern "C" */
