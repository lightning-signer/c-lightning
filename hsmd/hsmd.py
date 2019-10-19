#!/usr/bin/env python3

def setup():
    pass

def init_hsm(bip32_key_version,
             chainparams,
             hsm_encryption_key,
             privkey,
             seed,
             secrets,
             shaseed):
    print(locals())
    
