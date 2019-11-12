#!/usr/bin/env python3

import sys
import grpc
import coincurve
import pycoin
import api_pb2_grpc

# Needed because pytest loses stderr from the hsmd process.
import functools
import traceback

from api_pb2 import (
    SignDescriptor, KeyLocator, TxOut,
    ECDHReq,
    SignWithdrawalTxReq, 
    SignRemoteCommitmentTxReq,
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
             shaseed):
    debug("PYHSMD init_hsm", locals())

# message 10
def handle_get_channel_basepoints(self_id, peer_id, dbid):
    debug("PYHSMD handle_get_channel_basepoints", locals())

# message 1
@stdout_exceptions
def handle_ecdh(self_id, point):
    global stub
    debug("PYHSMD handle_ecdh", locals())

    req = ECDHReq()
    req.self_node_id = self_id['k']
    req.point = point['pubkey']
    rsp = stub.ECDH(req)
    ss = rsp.shared_secret
    debug("PYHSMD handle_ecdh =>", ss.hex())

    ## # FIXME - move this computation into the liposig server.
    ## local_priv = coincurve.PrivateKey.from_hex(EXFILT.privkey_hex)
    ## xx = int.from_bytes(point['pubkey'][:32], byteorder='little')
    ## yy = int.from_bytes(point['pubkey'][32:], byteorder='little')
    ## try:
    ##     remote_pub = coincurve.PublicKey.from_point(xx, yy)
    ##     ss = local_priv.ecdh(remote_pub.format())
    ##     debug("PYHSMD handle_ecdh ->", ss.hex())
    ##     return ss
    ## except ValueError as ex:
    ##     debug("PYHSMD handle_ecdh: bad point")
    ##     return None

    return None

# message 9
def handle_pass_client_hsmfd(self_id, id, dbid, capabilities):
    debug("PYHSMD handle_pass_client_hsmfd", locals())
    
# message 18
def handle_get_per_commitment_point(self_id, n, dbid):
    debug("PYHSMD handle_get_per_commitment_point", locals())

# message 2
def handle_cannouncement_sig(self_id, ca, node_id, dbid):
    debug("PYHSMD handle_cannouncement_sig", locals())

# message 7
@stdout_exceptions
def handle_sign_withdrawal_tx(self_id,
                              satoshi_out,
                              change_out,
                              change_keyindex,
                              outputs,
                              utxos,
                              tx):
    debug("PYHSMD handle_sign_withdrawal_tx", locals())

    assert len(outputs) == 1, "expected a single output"
    req = create_withdrawal_tx(self_id, tx, utxos, change_keyindex, outputs[0], change_out)

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
                                     remote_funding_pubkey, funding):
    debug("PYHSMD handle_sign_remote_commitment_tx", locals())

    req = SignRemoteCommitmentTxReq()
    req.self_node_id = self_id['k']
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
        debug("PYHSMD handle_sign_withdrawal_tx sig", ndx, sig.hex())

# message 3
# FIXME - fill in signature
def handle_channel_update_sig():
    debug("PYHSMD handle_channel_update_sig", locals())
