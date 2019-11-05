#!/usr/bin/env python3

import sys
import grpc
import coincurve
import pycoin
import api_pb2_grpc

from api_pb2 import (
    ECDHReq,
    SignWithdrawalTxReq,
)

from pycoin.symbols.btc import network

import EXFILT

Tx = network.tx

def debug(*objs):
    ff = sys.stdout
    print(*objs, file=ff)
    ff.flush()

stub = None
def setup():
    global stub
    channel = grpc.insecure_channel('localhost:50051')
    stub = api_pb2_grpc.SignerStub(channel)

# message 11
def init_hsm(bip32_key_version,
             chainparams,
             hsm_encryption_key,
             privkey,
             seed,
             secrets,
             shaseed):
    debug("PYHSMD init_hsm", locals())

# message 10
def handle_get_channel_basepoints(peer_id, dbid):
    debug("PYHSMD handle_get_channel_basepoints", locals())

# message 1
def handle_ecdh(point):
    global stub
    debug("PYHSMD handle_ecdh", locals())

    req = ECDHReq()
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
def handle_pass_client_hsmfd(id, dbid, capabilities):
    debug("PYHSMD handle_pass_client_hsmfd", locals())
    
# message 18
def handle_get_per_commitment_point(n, dbid):
    debug("PYHSMD handle_get_per_commitment_point", locals())

# message 2
def handle_cannouncement_sig(ca, node_id, dbid):
    debug("PYHSMD handle_cannouncement_sig", locals())

# message 7
def handle_sign_withdrawal_tx(satoshi_out,
                              change_out,
                              change_keyindex,
			      outputs,
                              utxos,
                              tx):
    debug("PYHSMD handle_sign_withdrawal_tx", locals())

    version = tx['wally_tx']['version']

    txs_in = []
    for inp in tx['wally_tx']['inputs']:
        txs_in.append(Tx.TxIn(inp['txhash'],
                              inp['index'],
                              inp['script'],
                              inp['sequence']))

    txs_out = []
    for out in tx['wally_tx']['outputs']:
        txs_out.append(Tx.TxOut(out['satoshi'],
                                out['script']))
    
    tx = Tx(version, txs_in, txs_out)

    debug("PYHSMD tx hex", tx.as_hex())

# message 3
# FIXME - fill in signature
def handle_channel_update_sig():
    debug("PYHSMD handle_channel_update_sig", locals())
