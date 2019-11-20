#!/usr/bin/env python3

import api_pb2_grpc
import coincurve
import grpc
import pycoin
import struct
import sys

# Needed because pytest loses stderr from the hsmd process.
import functools
import traceback

from api_pb2 import (
    BIP32KeyVersion, ChainParams, SignDescriptor, KeyLocator, TxOut,
    InitHSMReq,
    ECDHReq,
    PassClientHSMFdReq,
    GetPerCommitmentPointReq,
    SignWithdrawalTxReq, 
    SignRemoteCommitmentTxReq,
    SignRemoteHTLCTxReq,
    SignMutualCloseTxReq,
)

from pycoin.symbols.btc import network

import EXFILT

Tx = network.tx

def debug(*objs):
    ff = sys.stdout
    print(*objs, file=ff)
    ff.flush()

# Needed because pytest loses stderr from the hsmd process.
def stdout_exceptions(function):
    """
    A decorator that wraps the passed in function and logs
    exceptions to the debug stream.
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            raise
    return wrapper

stub = None
def setup():
    global stub
    channel = grpc.insecure_channel('localhost:50051')
    stub = api_pb2_grpc.SignerStub(channel)

# message 11
@stdout_exceptions
def init_hsm(bip32_key_version,
             chainparams,
             hsm_encryption_key,
             privkey,
             seed,
             secrets,
             shaseed,
             hsm_secret):
    global stub
    debug("PYHSMD init_hsm", locals())

    req = InitHSMReq()
    req.key_version.pubkey_version = bip32_key_version['bip32_pubkey_version']
    req.key_version.privkey_version = bip32_key_version['bip32_privkey_version']
    req.chainparams.network_name = chainparams['network_name']
    req.chainparams.bip173_name = chainparams['bip173_name']
    req.chainparams.bip70_name = chainparams['bip70_name']
    req.chainparams.genesis_blockhash = \
        chainparams['genesis_blockhash']['shad']['sha']
    req.chainparams.rpc_port = chainparams['rpc_port']
    req.chainparams.cli = chainparams['cli']
    req.chainparams.cli_args = chainparams['cli_args']
    req.chainparams.cli_min_supported_version = \
        chainparams['cli_min_supported_version']
    req.chainparams.dust_limit_sat = chainparams['dust_limit']['satoshis']
    req.chainparams.max_funding_sat = chainparams['max_funding']['satoshis']
    req.chainparams.max_payment_msat = \
        chainparams['max_payment']['millisatoshis']
    req.chainparams.when_lightning_became_cool = \
        chainparams['when_lightning_became_cool']
    req.chainparams.p2pkh_version = chainparams['p2pkh_version']
    req.chainparams.p2sh_version = chainparams['p2sh_version']
    req.chainparams.testnet = chainparams['testnet']
    req.chainparams.bip32_key_version.pubkey_version = \
        chainparams['bip32_key_version']['bip32_pubkey_version']
    req.chainparams.bip32_key_version.privkey_version = \
        chainparams['bip32_key_version']['bip32_privkey_version']
    req.chainparams.is_elements = chainparams['is_elements']
    if chainparams['fee_asset_tag']:
        req.chainparams.fee_asset_tag = chainparams['fee_asset_tag']

    # HACK: send the secret instead of generating on the HSM
    req.hsm_secret = hsm_secret
    
    rsp = stub.InitHSM(req)
    node_id = rsp.self_node_id
    debug("PYHSMD init_hsm =>", node_id.hex())

# message 10
@stdout_exceptions
def handle_get_channel_basepoints(self_id, peer_id, dbid):
    global stub
    debug("PYHSMD handle_get_channel_basepoints", self_id['k'].hex(), locals())
    
    
# message 1
@stdout_exceptions
def handle_ecdh(self_id, point):
    global stub
    debug("PYHSMD handle_ecdh", self_id['k'].hex(), locals())

    req = ECDHReq()
    req.self_node_id = self_id['k']
    req.point = point['pubkey']
    rsp = stub.ECDH(req)
    ss = rsp.shared_secret
    debug("PYHSMD handle_ecdh =>", ss.hex())
    return ss

# message 9
@stdout_exceptions
def handle_pass_client_hsmfd(self_id, peer_id, dbid, capabilities):
    global stub
    debug("PYHSMD handle_pass_client_hsmfd", self_id['k'].hex(), locals())
    
    req = PassClientHSMFdReq()
    req.self_node_id = self_id['k']
    req.channel_nonce = peer_id['k'] + struct.pack("<Q", dbid)
    req.capabilities = capabilities
    rsp = stub.PassClientHSMFd(req)

    return None
    
# message 18
@stdout_exceptions
def handle_get_per_commitment_point(self_id, peer_id, dbid, n):
    global stub
    debug("PYHSMD handle_get_per_commitment_point", self_id['k'].hex(), locals())
    
    req = GetPerCommitmentPointReq()
    req.self_node_id = self_id['k']
    req.channel_nonce = peer_id['k'] + struct.pack("<Q", dbid)
    req.n = n
    rsp = stub.GetPerCommitmentPoint(req)
    return rsp.per_commitment_point, rsp.old_secret

# message 2
@stdout_exceptions
def handle_cannouncement_sig(self_id, ca, node_id, dbid):
    global stub
    debug("PYHSMD handle_cannouncement_sig", self_id['k'].hex(), locals())

# message 7
@stdout_exceptions
def handle_sign_withdrawal_tx(self_id, peer_id, dbid,
                              satoshi_out,
                              change_out,
                              change_keyindex,
                              outputs,
                              utxos,
                              tx):
    global stub
    debug("PYHSMD handle_sign_withdrawal_tx", self_id['k'].hex(), locals())

    assert len(outputs) == 1, "expected a single output"
    req = create_withdrawal_tx(self_id, tx, utxos, change_keyindex, outputs[0], change_out)
    req.channel_nonce = peer_id['k'] + struct.pack("<Q", dbid)

    debug("PYHSMD handle_sign_withdrawal_tx calling server")
    rsp = stub.SignWithdrawalTx(req)
    sigs = rsp.raw_sigs

    for ndx, sig in enumerate(sigs):
        debug("PYHSMD handle_sign_withdrawal_tx sig", ndx, sig.hex())

def create_withdrawal_tx(self_id, tx, utxos, change_keyindex,
                         output, change_output):
    req = SignWithdrawalTxReq()
    req.self_node_id = self_id['k']
    version = tx['wally_tx']['version']
    isds = []
    txs_in = []
    for i, inp in enumerate(tx['wally_tx']['inputs']):
        txs_in.append(Tx.TxIn(inp['txhash'],
                              inp['index'],
                              inp['script'],
                              inp['sequence']))
        utxo = utxos[i]
        assert not utxo['is_p2sh']
        desc = SignDescriptor()
        desc.key_loc.key_index = utxo['keyindex']
        desc.key_loc.key_family = KeyLocator.layer_one
        desc.output.value = utxo['amount']['satoshis']
        isds.append(desc)
    osds = []
    txs_out = []
    for out in tx['wally_tx']['outputs']:
        txs_out.append(Tx.TxOut(out['satoshi'],
                                out['script']))
        desc = SignDescriptor()
        if out['script'] != output['script']:
            assert out['satoshi'] == change_output['satoshis']
            desc.key_loc.key_index = change_keyindex
            desc.key_loc.key_family = KeyLocator.layer_one
        else:
            desc.key_loc.key_family = KeyLocator.unknown
        osds.append(desc)
    tx = Tx(version, txs_in, txs_out)
    debug("PYHSMD handle_sign_withdrawal_tx TX", tx.as_hex())
    req.raw_tx_bytes = tx.as_bin()
    req.input_descs.extend(isds)
    req.output_descs.extend(osds)
    return req

# message 19
@stdout_exceptions
def handle_sign_remote_commitment_tx(self_id, tx,
                                     remote_funding_pubkey,
                                     funding, peer_id, dbid,
                                     output_witscripts, remote_per_commit):
    global stub
    debug("PYHSMD handle_sign_remote_commitment_tx", self_id['k'].hex(), locals())

    req = SignRemoteCommitmentTxReq()
    req.self_node_id = self_id['k']
    req.channel_nonce = peer_id['k'] + struct.pack("<Q", dbid)
    req.remote_funding_pubkey = remote_funding_pubkey['pubkey']
    req.remote_percommit_point = remote_per_commit['pubkey']
    for witscript in output_witscripts:
        if witscript:
            req.output_witscripts.append(witscript)
        else:
            req.output_witscripts.append(b'')
    version = tx['wally_tx']['version']
    isds = []
    txs_in = []
    for i, inp in enumerate(tx['wally_tx']['inputs']):
        txs_in.append(Tx.TxIn(inp['txhash'],
                              inp['index'],
                              inp['script'],
                              inp['sequence']))
        # FIXME - figure out the input SignDescriptor.
        desc = SignDescriptor()
        isds.append(desc)
    osds = []
    txs_out = []
    for out in tx['wally_tx']['outputs']:
        txs_out.append(Tx.TxOut(out['satoshi'],
                                out['script']))
        # FIXME - figure out the output SignDescriptor.
        desc = SignDescriptor()
        osds.append(desc)
    tx = Tx(version, txs_in, txs_out)
    debug("PYHSMD handle_sign_remote_commitment_tx TX", tx.as_hex())
    req.raw_tx_bytes = tx.as_bin()
    req.input_descs.extend(isds)
    req.output_descs.extend(osds)

    rsp = stub.SignRemoteCommitmentTx(req)
    sigs = rsp.raw_sigs

    for ndx, sig in enumerate(sigs):
        debug("PYHSMD handle_sign_remote_commitment_tx sig", ndx, sig.hex())

# message 20
@stdout_exceptions
def handle_sign_remote_htlc_tx(self_id, tx, wscript,
                               remote_per_commit_point,
                               peer_id, dbid):
    global stub
    debug("PYHSMD handle_sign_remote_htlc_tx", self_id['k'].hex(), locals())

    req = SignRemoteHTLCTxReq()
    req.self_node_id = self_id['k']
    req.channel_nonce = peer_id['k'] + struct.pack("<Q", dbid)
    req.remote_per_commit_point = remote_per_commit_point['pubkey']
    if wscript:
        req.wscript = wscript
    version = tx['wally_tx']['version']
    isds = []
    txs_in = []
    for i, inp in enumerate(tx['wally_tx']['inputs']):
        txs_in.append(Tx.TxIn(inp['txhash'],
                              inp['index'],
                              inp['script'],
                              inp['sequence']))
        # FIXME - figure out the input SignDescriptor.
        desc = SignDescriptor()
        isds.append(desc)
    osds = []
    txs_out = []
    for out in tx['wally_tx']['outputs']:
        txs_out.append(Tx.TxOut(out['satoshi'],
                                out['script']))
        # FIXME - figure out the output SignDescriptor.
        desc = SignDescriptor()
        osds.append(desc)
    tx = Tx(version, txs_in, txs_out)
    debug("PYHSMD handle_sign_remote_commitment_tx TX", tx.as_hex())
    req.raw_tx_bytes = tx.as_bin()
    req.input_descs.extend(isds)
    req.output_descs.extend(osds)

    rsp = stub.SignRemoteHTLCTx(req)
    sigs = rsp.raw_sigs

    for ndx, sig in enumerate(sigs):
        debug("PYHSMD handle_sign_remote_htlc_tx sig", ndx, sig.hex())

# message 21
@stdout_exceptions
def handle_sign_mutual_close_tx(self_id, tx,
                                remote_funding_pubkey,
                                funding, peer_id, dbid):
    global stub
    debug("PYHSMD handle_sign_mutual_close_tx", self_id['k'].hex(), locals())

    req = SignMutualCloseTxReq()
    req.self_node_id = self_id['k']
    req.channel_nonce = peer_id['k'] + struct.pack("<Q", dbid)
    req.remote_funding_pubkey = remote_funding_pubkey['pubkey']
    version = tx['wally_tx']['version']
    isds = []
    txs_in = []
    for i, inp in enumerate(tx['wally_tx']['inputs']):
        txs_in.append(Tx.TxIn(inp['txhash'],
                              inp['index'],
                              inp['script'],
                              inp['sequence']))
        # FIXME - figure out the input SignDescriptor.
        desc = SignDescriptor()
        isds.append(desc)
    osds = []
    txs_out = []
    for out in tx['wally_tx']['outputs']:
        txs_out.append(Tx.TxOut(out['satoshi'],
                                out['script']))
        # FIXME - figure out the output SignDescriptor.
        desc = SignDescriptor()
        osds.append(desc)
    tx = Tx(version, txs_in, txs_out)
    debug("PYHSMD handle_sign_mutual_close_tx TX", tx.as_hex())
    req.raw_tx_bytes = tx.as_bin()
    req.input_descs.extend(isds)
    req.output_descs.extend(osds)

    rsp = stub.SignMutualCloseTx(req)
    sigs = rsp.raw_sigs

    for ndx, sig in enumerate(sigs):
        debug("PYHSMD handle_sign_mutual_close_tx sig", ndx, sig.hex())

# message 3
# FIXME - fill in signature
@stdout_exceptions
def handle_channel_update_sig():
    global stub
    debug("PYHSMD handle_channel_update_sig", locals())
