#!/usr/bin/env python3

import sys

def debug(msg, lcls):
    print(msg, lcls)
    sys.stdout.flush()

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
    debug("PYHSMD init_hsm", locals())

# message 10
def handle_get_channel_basepoints(peer_id, dbid):
    debug("PYHSMD handle_get_channel_basepoints", locals())

# message 1
def handle_ecdh(point):
    debug("PYHSMD handle_ecdh", locals())

# message 9
def handle_pass_client_hsmfd(id, dbid, capabilities):
    debug("PYHSMD handle_pass_client_hsmfd", locals())
    
# message 18
def handle_get_per_commitment_point(n, dbid):
    debug("PYHSMD handle_get_per_commitment_point", locals())

# message 2
def handle_cannouncement_sig(ca, node_id, dbid):
    debug("PYHSMD handle_cannouncement_sig", locals())
