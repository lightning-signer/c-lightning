#!/usr/bin/env python3

def setup():
    pass

# message 11
def init_hsm(bip32_key_version,
             chainparams,
             hsm_encryption_key,
             privkey,
             seed,
             secrets,
             shaseed):
    print("init_hsm", locals())

# message 1
def handle_ecdh(point):
    print("handle_ecdh", locals())

# message 10
def handle_get_channel_basepoints(peer_id, dbid):
    print("handle_get_channel_basepoints", locals())

# message 18
def handle_get_per_commitment_point(n, dbid):
    print("handle_get_per_commitment_point", locals())

# message 2
def handle_cannouncement_sig(ca, node_id, dbid):
    print("handle_cannouncement_sig", locals())
