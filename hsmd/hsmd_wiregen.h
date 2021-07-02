/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
/* Original template can be found at tools/gen/header_template */

#ifndef LIGHTNING_HSMD_HSMD_WIREGEN_H
#define LIGHTNING_HSMD_HSMD_WIREGEN_H
#include <ccan/tal/tal.h>
#include <wire/tlvstream.h>
#include <wire/wire.h>
#include <bitcoin/chainparams.h>
#include <common/bip32.h>
#include <common/derive_basepoints.h>
#include <common/utxo.h>
#include <bitcoin/psbt.h>
#include <common/htlc_wire.h>

enum hsmd_wire {
        /*  Clients should not give a bad request but not the HSM's decision to crash. */
        WIRE_HSMSTATUS_CLIENT_BAD_REQUEST = 1000,
        /*  Start the HSM. */
        WIRE_HSMD_INIT = 11,
        WIRE_HSMD_INIT_REPLY = 111,
        /*  Declare a new channel. */
        WIRE_HSMD_NEW_CHANNEL = 30,
        /*  No value returned. */
        WIRE_HSMD_NEW_CHANNEL_REPLY = 130,
        /*  Get a new HSM FD */
        WIRE_HSMD_CLIENT_HSMFD = 9,
        /*  No content */
        WIRE_HSMD_CLIENT_HSMFD_REPLY = 109,
        /*  Get the basepoints and funding key for this specific channel. */
        WIRE_HSMD_GET_CHANNEL_BASEPOINTS = 10,
        WIRE_HSMD_GET_CHANNEL_BASEPOINTS_REPLY = 110,
        /*  Provide channel parameters. */
        WIRE_HSMD_READY_CHANNEL = 31,
        /*  No value returned. */
        WIRE_HSMD_READY_CHANNEL_REPLY = 131,
        /*  Master asks the HSM to sign a node_announcement */
        WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REQ = 6,
        WIRE_HSMD_NODE_ANNOUNCEMENT_SIG_REPLY = 106,
        /*  Sign a withdrawal request */
        WIRE_HSMD_SIGN_WITHDRAWAL = 7,
        WIRE_HSMD_SIGN_WITHDRAWAL_REPLY = 107,
        /*  Sign an invoice */
        WIRE_HSMD_SIGN_INVOICE = 8,
        WIRE_HSMD_SIGN_INVOICE_REPLY = 108,
        /*  Give me ECDH(node-id-secret */
        WIRE_HSMD_ECDH_REQ = 1,
        WIRE_HSMD_ECDH_RESP = 100,
        WIRE_HSMD_CANNOUNCEMENT_SIG_REQ = 2,
        WIRE_HSMD_CANNOUNCEMENT_SIG_REPLY = 102,
        WIRE_HSMD_CUPDATE_SIG_REQ = 3,
        WIRE_HSMD_CUPDATE_SIG_REPLY = 103,
        /*  Master asks HSM to sign a commitment transaction. */
        WIRE_HSMD_SIGN_COMMITMENT_TX = 5,
        WIRE_HSMD_SIGN_COMMITMENT_TX_REPLY = 105,
        /*  Validate the counterparty's commitment signatures. */
        WIRE_HSMD_VALIDATE_COMMITMENT_TX = 35,
        WIRE_HSMD_VALIDATE_COMMITMENT_TX_REPLY = 135,
        /*  Onchaind asks HSM to sign a spend to-us.  Four variants */
        /*  of keys is derived differently... */
        /*  FIXME: Have master tell hsmd the keyindex */
        WIRE_HSMD_SIGN_DELAYED_PAYMENT_TO_US = 12,
        WIRE_HSMD_SIGN_REMOTE_HTLC_TO_US = 13,
        WIRE_HSMD_SIGN_PENALTY_TO_US = 14,
        /*  Onchaind asks HSM to sign a local HTLC success or HTLC timeout tx. */
        WIRE_HSMD_SIGN_LOCAL_HTLC_TX = 16,
        /*  Openingd/channeld asks HSM to sign the other sides' commitment tx. */
        WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX = 19,
        /*  channeld asks HSM to sign remote HTLC tx. */
        WIRE_HSMD_SIGN_REMOTE_HTLC_TX = 20,
        /*  closingd asks HSM to sign mutual close tx. */
        WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX = 21,
        /*  Reply for all the above requests. */
        WIRE_HSMD_SIGN_TX_REPLY = 112,
        /*  Openingd/channeld/onchaind asks for Nth per_commitment_point */
        WIRE_HSMD_GET_PER_COMMITMENT_POINT = 18,
        WIRE_HSMD_GET_PER_COMMITMENT_POINT_REPLY = 118,
        /*  master -> hsmd: do you have a memleak? */
        WIRE_HSMD_DEV_MEMLEAK = 33,
        WIRE_HSMD_DEV_MEMLEAK_REPLY = 133,
        /*  channeld asks to check if claimed future commitment_secret is correct. */
        WIRE_HSMD_CHECK_FUTURE_SECRET = 22,
        WIRE_HSMD_CHECK_FUTURE_SECRET_REPLY = 122,
        /*  lightningd asks us to sign a string. */
        WIRE_HSMD_SIGN_MESSAGE = 23,
        WIRE_HSMD_SIGN_MESSAGE_REPLY = 123,
        /*  lightningd needs to get a scriptPubkey for a utxo with closeinfo */
        WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY = 24,
        WIRE_HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY = 124,
        /*  Sign a bolt12-style merkle hash */
        WIRE_HSMD_SIGN_BOLT12 = 25,
        WIRE_HSMD_SIGN_BOLT12_REPLY = 125,
};

const char *hsmd_wire_name(int e);

/**
 * Determine whether a given message type is defined as a message.
 *
 * Returns true if the message type is part of the message definitions we have
 * generated parsers for, false if it is a custom message that cannot be
 * handled internally.
 */
bool hsmd_wire_is_defined(u16 type);


/* WIRE: HSMSTATUS_CLIENT_BAD_REQUEST */
/*  Clients should not give a bad request but not the HSM's decision to crash. */
u8 *towire_hsmstatus_client_bad_request(const tal_t *ctx, const struct node_id *id, const wirestring *description, const u8 *msg);
bool fromwire_hsmstatus_client_bad_request(const tal_t *ctx, const void *p, struct node_id *id, wirestring **description, u8 **msg);

/* WIRE: HSMD_INIT */
/*  Start the HSM. */
u8 *towire_hsmd_init(const tal_t *ctx, const struct bip32_key_version *bip32_key_version, const struct chainparams *chainparams, const struct secret *hsm_encryption_key, const struct privkey *dev_force_privkey, const struct secret *dev_force_bip32_seed, const struct secrets *dev_force_channel_secrets, const struct sha256 *dev_force_channel_secrets_shaseed);
bool fromwire_hsmd_init(const tal_t *ctx, const void *p, struct bip32_key_version *bip32_key_version, const struct chainparams **chainparams, struct secret **hsm_encryption_key, struct privkey **dev_force_privkey, struct secret **dev_force_bip32_seed, struct secrets **dev_force_channel_secrets, struct sha256 **dev_force_channel_secrets_shaseed);

/* WIRE: HSMD_INIT_REPLY */
u8 *towire_hsmd_init_reply(const tal_t *ctx, const struct node_id *node_id, const struct ext_key *bip32, const struct pubkey32 *bolt12);
bool fromwire_hsmd_init_reply(const void *p, struct node_id *node_id, struct ext_key *bip32, struct pubkey32 *bolt12);

/* WIRE: HSMD_NEW_CHANNEL */
/*  Declare a new channel. */
u8 *towire_hsmd_new_channel(const tal_t *ctx, const struct node_id *id, u64 dbid);
bool fromwire_hsmd_new_channel(const void *p, struct node_id *id, u64 *dbid);

/* WIRE: HSMD_NEW_CHANNEL_REPLY */
/*  No value returned. */
u8 *towire_hsmd_new_channel_reply(const tal_t *ctx);
bool fromwire_hsmd_new_channel_reply(const void *p);

/* WIRE: HSMD_CLIENT_HSMFD */
/*  Get a new HSM FD */
u8 *towire_hsmd_client_hsmfd(const tal_t *ctx, const struct node_id *id, u64 dbid, u64 capabilities);
bool fromwire_hsmd_client_hsmfd(const void *p, struct node_id *id, u64 *dbid, u64 *capabilities);

/* WIRE: HSMD_CLIENT_HSMFD_REPLY */
/*  No content */
u8 *towire_hsmd_client_hsmfd_reply(const tal_t *ctx);
bool fromwire_hsmd_client_hsmfd_reply(const void *p);

/* WIRE: HSMD_GET_CHANNEL_BASEPOINTS */
/*  Get the basepoints and funding key for this specific channel. */
u8 *towire_hsmd_get_channel_basepoints(const tal_t *ctx, const struct node_id *peerid, u64 dbid);
bool fromwire_hsmd_get_channel_basepoints(const void *p, struct node_id *peerid, u64 *dbid);

/* WIRE: HSMD_GET_CHANNEL_BASEPOINTS_REPLY */
u8 *towire_hsmd_get_channel_basepoints_reply(const tal_t *ctx, const struct basepoints *basepoints, const struct pubkey *funding_pubkey);
bool fromwire_hsmd_get_channel_basepoints_reply(const void *p, struct basepoints *basepoints, struct pubkey *funding_pubkey);

/* WIRE: HSMD_READY_CHANNEL */
/*  Provide channel parameters. */
u8 *towire_hsmd_ready_channel(const tal_t *ctx, bool is_outbound, struct amount_sat channel_value, struct amount_msat push_value, const struct bitcoin_txid *funding_txid, u16 funding_txout, u16 local_to_self_delay, const u8 *local_shutdown_script, const struct basepoints *remote_basepoints, const struct pubkey *remote_funding_pubkey, u16 remote_to_self_delay, const u8 *remote_shutdown_script, bool option_static_remotekey, bool option_anchor_outputs);
bool fromwire_hsmd_ready_channel(const tal_t *ctx, const void *p, bool *is_outbound, struct amount_sat *channel_value, struct amount_msat *push_value, struct bitcoin_txid *funding_txid, u16 *funding_txout, u16 *local_to_self_delay, u8 **local_shutdown_script, struct basepoints *remote_basepoints, struct pubkey *remote_funding_pubkey, u16 *remote_to_self_delay, u8 **remote_shutdown_script, bool *option_static_remotekey, bool *option_anchor_outputs);

/* WIRE: HSMD_READY_CHANNEL_REPLY */
/*  No value returned. */
u8 *towire_hsmd_ready_channel_reply(const tal_t *ctx);
bool fromwire_hsmd_ready_channel_reply(const void *p);

/* WIRE: HSMD_NODE_ANNOUNCEMENT_SIG_REQ */
/*  Master asks the HSM to sign a node_announcement */
u8 *towire_hsmd_node_announcement_sig_req(const tal_t *ctx, const u8 *announcement);
bool fromwire_hsmd_node_announcement_sig_req(const tal_t *ctx, const void *p, u8 **announcement);

/* WIRE: HSMD_NODE_ANNOUNCEMENT_SIG_REPLY */
u8 *towire_hsmd_node_announcement_sig_reply(const tal_t *ctx, const secp256k1_ecdsa_signature *signature);
bool fromwire_hsmd_node_announcement_sig_reply(const void *p, secp256k1_ecdsa_signature *signature);

/* WIRE: HSMD_SIGN_WITHDRAWAL */
/*  Sign a withdrawal request */
u8 *towire_hsmd_sign_withdrawal(const tal_t *ctx, const struct utxo **inputs, const struct wally_psbt *psbt);
bool fromwire_hsmd_sign_withdrawal(const tal_t *ctx, const void *p, struct utxo ***inputs, struct wally_psbt **psbt);

/* WIRE: HSMD_SIGN_WITHDRAWAL_REPLY */
u8 *towire_hsmd_sign_withdrawal_reply(const tal_t *ctx, const struct wally_psbt *psbt);
bool fromwire_hsmd_sign_withdrawal_reply(const tal_t *ctx, const void *p, struct wally_psbt **psbt);

/* WIRE: HSMD_SIGN_INVOICE */
/*  Sign an invoice */
u8 *towire_hsmd_sign_invoice(const tal_t *ctx, const u8 *u5bytes, const u8 *hrp);
bool fromwire_hsmd_sign_invoice(const tal_t *ctx, const void *p, u8 **u5bytes, u8 **hrp);

/* WIRE: HSMD_SIGN_INVOICE_REPLY */
u8 *towire_hsmd_sign_invoice_reply(const tal_t *ctx, const secp256k1_ecdsa_recoverable_signature *sig);
bool fromwire_hsmd_sign_invoice_reply(const void *p, secp256k1_ecdsa_recoverable_signature *sig);

/* WIRE: HSMD_ECDH_REQ */
/*  Give me ECDH(node-id-secret */
u8 *towire_hsmd_ecdh_req(const tal_t *ctx, const struct pubkey *point);
bool fromwire_hsmd_ecdh_req(const void *p, struct pubkey *point);

/* WIRE: HSMD_ECDH_RESP */
u8 *towire_hsmd_ecdh_resp(const tal_t *ctx, const struct secret *ss);
bool fromwire_hsmd_ecdh_resp(const void *p, struct secret *ss);

/* WIRE: HSMD_CANNOUNCEMENT_SIG_REQ */
u8 *towire_hsmd_cannouncement_sig_req(const tal_t *ctx, const u8 *ca);
bool fromwire_hsmd_cannouncement_sig_req(const tal_t *ctx, const void *p, u8 **ca);

/* WIRE: HSMD_CANNOUNCEMENT_SIG_REPLY */
u8 *towire_hsmd_cannouncement_sig_reply(const tal_t *ctx, const secp256k1_ecdsa_signature *node_signature, const secp256k1_ecdsa_signature *bitcoin_signature);
bool fromwire_hsmd_cannouncement_sig_reply(const void *p, secp256k1_ecdsa_signature *node_signature, secp256k1_ecdsa_signature *bitcoin_signature);

/* WIRE: HSMD_CUPDATE_SIG_REQ */
u8 *towire_hsmd_cupdate_sig_req(const tal_t *ctx, const u8 *cu);
bool fromwire_hsmd_cupdate_sig_req(const tal_t *ctx, const void *p, u8 **cu);

/* WIRE: HSMD_CUPDATE_SIG_REPLY */
u8 *towire_hsmd_cupdate_sig_reply(const tal_t *ctx, const u8 *cu);
bool fromwire_hsmd_cupdate_sig_reply(const tal_t *ctx, const void *p, u8 **cu);

/* WIRE: HSMD_SIGN_COMMITMENT_TX */
/*  Master asks HSM to sign a commitment transaction. */
u8 *towire_hsmd_sign_commitment_tx(const tal_t *ctx, const struct node_id *peer_id, u64 channel_dbid, const struct bitcoin_tx *tx, const struct pubkey *remote_funding_key, const struct sha256 *htlc_rhash, u64 commit_num);
bool fromwire_hsmd_sign_commitment_tx(const tal_t *ctx, const void *p, struct node_id *peer_id, u64 *channel_dbid, struct bitcoin_tx **tx, struct pubkey *remote_funding_key, struct sha256 **htlc_rhash, u64 *commit_num);

/* WIRE: HSMD_SIGN_COMMITMENT_TX_REPLY */
u8 *towire_hsmd_sign_commitment_tx_reply(const tal_t *ctx, const struct bitcoin_signature *sig);
bool fromwire_hsmd_sign_commitment_tx_reply(const void *p, struct bitcoin_signature *sig);

/* WIRE: HSMD_VALIDATE_COMMITMENT_TX */
/*  Validate the counterparty's commitment signatures. */
u8 *towire_hsmd_validate_commitment_tx(const tal_t *ctx, const struct bitcoin_tx *tx, const struct existing_htlc **htlcs, u64 commit_num, u32 feerate, const struct bitcoin_signature *sig, const struct bitcoin_signature *htlc_sigs);
bool fromwire_hsmd_validate_commitment_tx(const tal_t *ctx, const void *p, struct bitcoin_tx **tx, struct existing_htlc ***htlcs, u64 *commit_num, u32 *feerate, struct bitcoin_signature *sig, struct bitcoin_signature **htlc_sigs);

/* WIRE: HSMD_VALIDATE_COMMITMENT_TX_REPLY */
u8 *towire_hsmd_validate_commitment_tx_reply(const tal_t *ctx, const struct secret *old_commitment_secret);
bool fromwire_hsmd_validate_commitment_tx_reply(const tal_t *ctx, const void *p, struct secret **old_commitment_secret);

/* WIRE: HSMD_SIGN_DELAYED_PAYMENT_TO_US */
/*  Onchaind asks HSM to sign a spend to-us.  Four variants */
/*  of keys is derived differently... */
/*  FIXME: Have master tell hsmd the keyindex */
u8 *towire_hsmd_sign_delayed_payment_to_us(const tal_t *ctx, u64 commit_num, const struct bitcoin_tx *tx, const u8 *wscript);
bool fromwire_hsmd_sign_delayed_payment_to_us(const tal_t *ctx, const void *p, u64 *commit_num, struct bitcoin_tx **tx, u8 **wscript);

/* WIRE: HSMD_SIGN_REMOTE_HTLC_TO_US */
u8 *towire_hsmd_sign_remote_htlc_to_us(const tal_t *ctx, const struct pubkey *remote_per_commitment_point, const struct bitcoin_tx *tx, const u8 *wscript, bool option_anchor_outputs);
bool fromwire_hsmd_sign_remote_htlc_to_us(const tal_t *ctx, const void *p, struct pubkey *remote_per_commitment_point, struct bitcoin_tx **tx, u8 **wscript, bool *option_anchor_outputs);

/* WIRE: HSMD_SIGN_PENALTY_TO_US */
u8 *towire_hsmd_sign_penalty_to_us(const tal_t *ctx, const struct secret *revocation_secret, const struct bitcoin_tx *tx, const u8 *wscript);
bool fromwire_hsmd_sign_penalty_to_us(const tal_t *ctx, const void *p, struct secret *revocation_secret, struct bitcoin_tx **tx, u8 **wscript);

/* WIRE: HSMD_SIGN_LOCAL_HTLC_TX */
/*  Onchaind asks HSM to sign a local HTLC success or HTLC timeout tx. */
u8 *towire_hsmd_sign_local_htlc_tx(const tal_t *ctx, u64 commit_num, const struct bitcoin_tx *tx, const u8 *wscript, bool option_anchor_outputs);
bool fromwire_hsmd_sign_local_htlc_tx(const tal_t *ctx, const void *p, u64 *commit_num, struct bitcoin_tx **tx, u8 **wscript, bool *option_anchor_outputs);

/* WIRE: HSMD_SIGN_REMOTE_COMMITMENT_TX */
/*  Openingd/channeld asks HSM to sign the other sides' commitment tx. */
u8 *towire_hsmd_sign_remote_commitment_tx(const tal_t *ctx, const struct bitcoin_tx *tx, const struct pubkey *remote_funding_key, const struct pubkey *remote_per_commit, bool option_static_remotekey, const struct sha256 *htlc_rhash, u64 commit_num);
bool fromwire_hsmd_sign_remote_commitment_tx(const tal_t *ctx, const void *p, struct bitcoin_tx **tx, struct pubkey *remote_funding_key, struct pubkey *remote_per_commit, bool *option_static_remotekey, struct sha256 **htlc_rhash, u64 *commit_num);

/* WIRE: HSMD_SIGN_REMOTE_HTLC_TX */
/*  channeld asks HSM to sign remote HTLC tx. */
u8 *towire_hsmd_sign_remote_htlc_tx(const tal_t *ctx, const struct bitcoin_tx *tx, const u8 *wscript, const struct pubkey *remote_per_commit_point, bool option_anchor_outputs);
bool fromwire_hsmd_sign_remote_htlc_tx(const tal_t *ctx, const void *p, struct bitcoin_tx **tx, u8 **wscript, struct pubkey *remote_per_commit_point, bool *option_anchor_outputs);

/* WIRE: HSMD_SIGN_MUTUAL_CLOSE_TX */
/*  closingd asks HSM to sign mutual close tx. */
u8 *towire_hsmd_sign_mutual_close_tx(const tal_t *ctx, const struct bitcoin_tx *tx, const struct pubkey *remote_funding_key);
bool fromwire_hsmd_sign_mutual_close_tx(const tal_t *ctx, const void *p, struct bitcoin_tx **tx, struct pubkey *remote_funding_key);

/* WIRE: HSMD_SIGN_TX_REPLY */
/*  Reply for all the above requests. */
u8 *towire_hsmd_sign_tx_reply(const tal_t *ctx, const struct bitcoin_signature *sig);
bool fromwire_hsmd_sign_tx_reply(const void *p, struct bitcoin_signature *sig);

/* WIRE: HSMD_GET_PER_COMMITMENT_POINT */
/*  Openingd/channeld/onchaind asks for Nth per_commitment_point */
u8 *towire_hsmd_get_per_commitment_point(const tal_t *ctx, u64 n);
bool fromwire_hsmd_get_per_commitment_point(const void *p, u64 *n);

/* WIRE: HSMD_GET_PER_COMMITMENT_POINT_REPLY */
u8 *towire_hsmd_get_per_commitment_point_reply(const tal_t *ctx, const struct pubkey *per_commitment_point, const struct secret *old_commitment_secret);
bool fromwire_hsmd_get_per_commitment_point_reply(const tal_t *ctx, const void *p, struct pubkey *per_commitment_point, struct secret **old_commitment_secret);

/* WIRE: HSMD_DEV_MEMLEAK */
/*  master -> hsmd: do you have a memleak? */
u8 *towire_hsmd_dev_memleak(const tal_t *ctx);
bool fromwire_hsmd_dev_memleak(const void *p);

/* WIRE: HSMD_DEV_MEMLEAK_REPLY */
u8 *towire_hsmd_dev_memleak_reply(const tal_t *ctx, bool leak);
bool fromwire_hsmd_dev_memleak_reply(const void *p, bool *leak);

/* WIRE: HSMD_CHECK_FUTURE_SECRET */
/*  channeld asks to check if claimed future commitment_secret is correct. */
u8 *towire_hsmd_check_future_secret(const tal_t *ctx, u64 n, const struct secret *commitment_secret);
bool fromwire_hsmd_check_future_secret(const void *p, u64 *n, struct secret *commitment_secret);

/* WIRE: HSMD_CHECK_FUTURE_SECRET_REPLY */
u8 *towire_hsmd_check_future_secret_reply(const tal_t *ctx, bool correct);
bool fromwire_hsmd_check_future_secret_reply(const void *p, bool *correct);

/* WIRE: HSMD_SIGN_MESSAGE */
/*  lightningd asks us to sign a string. */
u8 *towire_hsmd_sign_message(const tal_t *ctx, const u8 *msg);
bool fromwire_hsmd_sign_message(const tal_t *ctx, const void *p, u8 **msg);

/* WIRE: HSMD_SIGN_MESSAGE_REPLY */
u8 *towire_hsmd_sign_message_reply(const tal_t *ctx, const secp256k1_ecdsa_recoverable_signature *sig);
bool fromwire_hsmd_sign_message_reply(const void *p, secp256k1_ecdsa_recoverable_signature *sig);

/* WIRE: HSMD_GET_OUTPUT_SCRIPTPUBKEY */
/*  lightningd needs to get a scriptPubkey for a utxo with closeinfo */
u8 *towire_hsmd_get_output_scriptpubkey(const tal_t *ctx, u64 channel_id, const struct node_id *peer_id, const struct pubkey *commitment_point);
bool fromwire_hsmd_get_output_scriptpubkey(const tal_t *ctx, const void *p, u64 *channel_id, struct node_id *peer_id, struct pubkey **commitment_point);

/* WIRE: HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY */
u8 *towire_hsmd_get_output_scriptpubkey_reply(const tal_t *ctx, const u8 *script);
bool fromwire_hsmd_get_output_scriptpubkey_reply(const tal_t *ctx, const void *p, u8 **script);

/* WIRE: HSMD_SIGN_BOLT12 */
/*  Sign a bolt12-style merkle hash */
u8 *towire_hsmd_sign_bolt12(const tal_t *ctx, const wirestring *messagename, const wirestring *fieldname, const struct sha256 *merkleroot, const u8 *publictweak);
bool fromwire_hsmd_sign_bolt12(const tal_t *ctx, const void *p, wirestring **messagename, wirestring **fieldname, struct sha256 *merkleroot, u8 **publictweak);

/* WIRE: HSMD_SIGN_BOLT12_REPLY */
u8 *towire_hsmd_sign_bolt12_reply(const tal_t *ctx, const struct bip340sig *sig);
bool fromwire_hsmd_sign_bolt12_reply(const void *p, struct bip340sig *sig);


#endif /* LIGHTNING_HSMD_HSMD_WIREGEN_H */
// SHA256STAMP:29a6c2bfe0761ff715ebd631fa50a3b3efe897e091ec82c87be47c6ace13d117
