#include <iostream>

#include <grpc++/grpc++.h>

#include "hsmd/api.pb.h"
#include "hsmd/api.grpc.pb.h"

#include "hsmd/proxy.h"

extern "C" {
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
}

using std::cerr;
using std::endl;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using rpc::Signer;
using rpc::InitHSMReq;
using rpc::InitHSMRsp;

namespace {
	std::unique_ptr<Signer::Stub>	stub;
}

extern "C" {

void proxy_setup()
{
	cerr << "PROXY: setup" << endl;
	auto channel = grpc::CreateChannel("localhost:50051",
					   grpc::InsecureChannelCredentials());
	stub = Signer::NewStub(channel);
}

void proxy_init_hsm(struct bip32_key_version *bip32_key_version,
		    struct chainparams const *chainparams,
		    struct secret *hsm_encryption_key,
		    struct privkey *privkey,
		    struct secret *seed,
		    struct secrets *secrets,
		    struct sha256 *shaseed,
		    struct secret *hsm_secret)
{
	cerr << "PROXY: init_hsm" << endl;
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

	/* FIXME - Sending the secret instead of gnerating on the remote. */
	req.set_hsm_secret(hsm_secret->data, sizeof(hsm_secret->data));

	ClientContext context;
	InitHSMRsp rsp;
	Status status = stub->InitHSM(&context, req, &rsp);
}

} /* extern "C" */
