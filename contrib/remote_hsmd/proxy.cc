#include <iostream>

#include <grpc++/grpc++.h>

#include "contrib/remote_hsmd/api.pb.h"
#include "contrib/remote_hsmd/api.grpc.pb.h"

#include "contrib/remote_hsmd/proxy.h"

extern "C" {
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <common/node_id.h>
#include <common/status.h>
}

using std::cerr;
using std::endl;
using std::string;
using std::unique_ptr;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

using rpc::Signer;
using rpc::InitHSMReq;
using rpc::InitHSMRsp;

namespace {
unique_ptr<Signer::Stub> stub;
string last_message;

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

/* type_to_string has issues in the C++ environment, use this to
   dump binary data as hex instead. */
string as_hex(const void *vptr, size_t sz)
{
	static const char hex[] = "0123456789abcdef";
	string retval(sz*2, '\0');
	uint8_t const * ptr = (uint8_t const *) vptr;
	for (size_t ii = 0; ii < sz; ++ii) {
		retval[ii*2+0] = hex[(*ptr) >> 4];
		retval[ii*2+1] = hex[(*ptr) & 0xf];
		ptr++;
	}
	return retval;
}
}

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
		status_debug("%s:%d %s node_id=%s",
			     __FILE__, __LINE__, __FUNCTION__,
			     as_hex(o_node_id->k,
				    sizeof(o_node_id->k)).c_str());
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

} /* extern "C" */

