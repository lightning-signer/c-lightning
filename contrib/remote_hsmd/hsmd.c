/*~ Welcome to the hsm daemon: keeper of our secrets!
 *
 * This is a separate daemon which keeps a root secret from which all others
 * are generated.  It starts with one client: lightningd, which can ask for
 * new sockets for other clients.  Each client has a simple capability map
 * which indicates what it's allowed to ask for.  We're entirely driven
 * by request, response.
 */
#include <bitcoin/address.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/intmap/intmap.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/derive_basepoints.h>
#include <common/hash_u5.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/node_id.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <contrib/remote_hsmd/proxy.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/capabilities.h>
#include <inttypes.h>
#include <secp256k1_ecdh.h>
#include <sodium.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wally_psbt.h>
#include <wire/gen_peer_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire_io.h>

/*~ Each subdaemon is started with stdin connected to lightningd (for status
 * messages), and stderr untouched (for emergency printing).  File descriptors
 * 3 and beyond are set up on other sockets: for hsmd, fd 3 is the request
 * stream from lightningd. */
#define REQ_FD 3

/* This used to be secretstuff, now has no secrets ... */
static struct {
	struct ext_key bip32;	/* Only has public part */
} pubstuff;

/* Version codes for BIP32 extended keys in libwally-core.
 * It's not suitable to add this struct into client struct,
 * so set it static.*/
static struct  bip32_key_version  bip32_key_version;

/* These are no longer used, but handle_memleak seems to need them. */
#if DEVELOPER
/* If they specify --dev-force-privkey it ends up in here. */
static struct privkey *dev_force_privkey;
/* If they specify --dev-force-bip32-seed it ends up in here. */
static struct secret *dev_force_bip32_seed;
#endif

/* FIXME - REMOVE THIS WHEN NO LONGER NEEDED */
#if 0
static void print_hex(char const *tag, void const *vptr, size_t sz)
{
	fprintf(stderr, "%s: ", tag);
	uint8_t const *ptr = (uint8_t const *) vptr;
	for (size_t ii = 0; ii < sz; ++ii) {
		fprintf(stderr, "%02x", (int) ptr[ii]);
	}
	fprintf(stderr, "\n");
}
#endif

/*~ We keep track of clients, but there's not much to keep. */
struct client {
	/* The ccan/io async io connection for this client: it closes, we die. */
	struct io_conn *conn;

	/*~ io_read_wire needs a pointer to store incoming messages until
	 * it has the complete thing; this is it. */
	u8 *msg_in;

	/*~ Useful for logging, but also used to derive the per-channel seed. */
	struct node_id id;

	/*~ This is a unique value handed to us from lightningd, used for
	 * per-channel seed generation (a single id may have multiple channels
	 * over time).
	 *
	 * It's actually zero for the initial lightningd client connection and
	 * the ones for gossipd and connectd, which don't have channels
	 * associated. */
	u64 dbid;

	/* What is this client allowed to ask for? */
	u64 capabilities;

	/* Params to apply to all transactions for this client */
	const struct chainparams *chainparams;
};

/*~ We keep a map of nonzero dbid -> clients, mainly for leak detection.
 * This is ccan/uintmap, which maps u64 to some (non-NULL) pointer.
 * I really dislike these kinds of declaration-via-magic macro things, as
 * tags can't find them without special hacks, but the payoff here is that
 * the map is typesafe: the compiler won't let you put anything in but a
 * struct client pointer. */
static UINTMAP(struct client *) clients;
/*~ Plus the three zero-dbid clients: master, gossipd and connnectd. */
static struct client *dbid_zero_clients[3];
static size_t num_dbid_zero_clients;

/*~ We need this deep inside bad_req_fmt, and for memleak, so we make it a
 * global. */
static struct daemon_conn *status_conn;

/* This is used for various assertions and error cases. */
static bool is_lightningd(const struct client *client)
{
	return client == dbid_zero_clients[0];
}

/* FIXME: This is used by debug.c.  Doesn't apply to us, but lets us link. */
extern void dev_disconnect_init(int fd);
void dev_disconnect_init(int fd UNUSED) { }

/* Pre-declare this, due to mutual recursion */
static struct io_plan *handle_client(struct io_conn *conn, struct client *c);

/*~ ccan/compiler.h defines PRINTF_FMT as the gcc compiler hint so it will
 * check that fmt and other trailing arguments really are the correct type.
 *
 * This is a convenient helper to tell lightningd we've received a bad request
 * and closes the client connection.  This should never happen, of course, but
 * we definitely want to log if it does.
 */
static struct io_plan *bad_req_fmt(struct io_conn *conn,
				   struct client *c,
				   const u8 *msg_in,
				   const char *fmt, ...)
	PRINTF_FMT(4,5);

static struct io_plan *bad_req_fmt(struct io_conn *conn,
				   struct client *c,
				   const u8 *msg_in,
				   const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_fmt(tmpctx, fmt, ap);
	va_end(ap);

	/*~ If the client was actually lightningd, it's Game Over; we actually
	 * fail in this case, and it will too. */
	if (is_lightningd(c)) {
		status_broken("%s", str);
		master_badmsg(fromwire_peektype(msg_in), msg_in);
	}

	/*~ Nobody should give us bad requests; it's a sign something is broken */
	status_broken("%s: %s", type_to_string(tmpctx, struct node_id, &c->id), str);

	/*~ Note the use of NULL as the ctx arg to towire_hsmstatus_: only
	 * use NULL as the allocation when we're about to immediately free it
	 * or hand it off with take(), as here.  That makes it clear we don't
	 * expect it to linger, and in fact our memleak detection will
	 * complain if it does (unlike using the deliberately-transient
	 * tmpctx). */
	daemon_conn_send(status_conn,
			 take(towire_hsmstatus_client_bad_request(NULL,
								  &c->id,
								  str,
								  msg_in)));

	/*~ The way ccan/io works is that you return the "plan" for what to do
	 * next (eg. io_read).  io_close() is special: it means to close the
	 * connection. */
	return io_close(conn);
}

/* Convenience wrapper for when we simply can't parse. */
static struct io_plan *bad_req(struct io_conn *conn,
			       struct client *c,
			       const u8 *msg_in)
{
	return bad_req_fmt(conn, c, msg_in, "could not parse request");
}

/*~ This plan simply says: read the next packet into 'c->msg_in' (parent 'c'),
 * and then call handle_client with argument 'c' */
static struct io_plan *client_read_next(struct io_conn *conn, struct client *c)
{
	return io_read_wire(conn, c, &c->msg_in, handle_client, c);
}

/*~ This is the destructor on our client: we may call it manually, but
 * generally it's called because the io_conn associated with the client is
 * closed by the other end. */
static void destroy_client(struct client *c)
{
	if (!uintmap_del(&clients, c->dbid))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed to remove client dbid %"PRIu64, c->dbid);
}

static struct client *new_client(const tal_t *ctx,
				 const struct chainparams *chainparams,
				 const struct node_id *id,
				 u64 dbid,
				 const u64 capabilities,
				 int fd)
{
	struct client *c = tal(ctx, struct client);

	/*~ All-zero pubkey is used for the initial master connection */
	if (id) {
		c->id = *id;
		if (!node_id_valid(id))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Invalid node id %s",
				      type_to_string(tmpctx, struct node_id,
						     id));
	} else {
		memset(&c->id, 0, sizeof(c->id));
	}
	c->dbid = dbid;

	c->capabilities = capabilities;
	c->chainparams = chainparams;

	/*~ This is the core of ccan/io: the connection creation calls a
	 * callback which returns the initial plan to execute: in our case,
	 * read a message.*/
	c->conn = io_new_conn(ctx, fd, client_read_next, c);

	/*~ tal_steal() moves a pointer to a new parent.  At this point, the
	 * hierarchy is:
	 *
	 *   ctx -> c
	 *   ctx -> c->conn
	 *
	 * We want to the c->conn to own 'c', so that if the io_conn closes,
	 * the client is freed:
	 *
	 *   ctx -> c->conn -> c.
	 */
	tal_steal(c->conn, c);

	/* We put the special zero-db HSM connections into an array, the rest
	 * go into the map. */
	if (dbid == 0) {
		assert(num_dbid_zero_clients < ARRAY_SIZE(dbid_zero_clients));
		dbid_zero_clients[num_dbid_zero_clients++] = c;
	} else {
		struct client *old_client = uintmap_get(&clients, dbid);

		/* Close conn and free any old client of this dbid. */
		if (old_client)
			io_close(old_client->conn);

		if (!uintmap_add(&clients, dbid, c))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed inserting dbid %"PRIu64, dbid);
		tal_add_destructor(c, destroy_client);
	}

	return c;
}

/* This is the common pattern for the tail of each handler in this file. */
static struct io_plan *req_reply(struct io_conn *conn,
				 struct client *c,
				 const u8 *msg_out TAKES)
{
	/*~ Write this out, then read the next one.  This works perfectly for
	 * a simple request/response system like this.
	 *
	 * Internally, the ccan/io subsystem gathers all the file descriptors,
	 * figures out which want to write and read, asks the OS which ones
	 * are available, and for those file descriptors, tries to do the
	 * reads/writes we've asked it.  It handles retry in the case where a
	 * read or write is done partially.
	 *
	 * Since the OS does buffering internally (on my system, over 100k
	 * worth) writes will normally succeed immediately.  However, if the
	 * client is slow or malicious, and doesn't read from the socket as
	 * fast as we're writing, eventually the socket buffer will fill up;
	 * we don't care, because ccan/io will wait until there's room to
	 * write this reply before it will read again.  The client just hurts
	 * themselves, and there's no Denial of Service on us.
	 *
	 * If we were to queue outgoing messages ourselves, we *would* have to
	 * consider such scenarios; this is why our daemons generally avoid
	 * buffering from untrusted parties. */
	return io_write_wire(conn, msg_out, client_read_next, c);
}

/* The c-lightning testing framework imbues the hsm_secret with a
 * file created before hsmd starts.  For now we use the secret from
 * the testing framework rather than generating in the remote signer.
 *
 * Returns true if test seed fetched.  If false is returned test seed not
 * present, use random instead.
 */
static bool read_test_seed(struct secret *hsm_secret)
{
	struct stat st;
	int fd = open("hsm_secret", O_RDONLY);
	if (fd < 0)
		return false;
	if (stat("hsm_secret", &st) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "stating: %s", strerror(errno));

	/* If the seed is stored in clear. */
	if (st.st_size > 32)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "hsm_secret not in clear");

	if (!read_all(fd, hsm_secret, sizeof(*hsm_secret)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "reading: %s", strerror(errno));
	close(fd);
	return true;
}

// TODO - Add support for bolt12 to remote signer and remove this
// entire routine.  This does not actually setup a usable BOLT12
// context; it always uses an empty hsm_secret.
static void bogus_bolt12_placeholder(struct point32 *bolt12out)
{
	struct secret bad_hsm_secret;
	u8 bip32_seed[BIP32_ENTROPY_LEN_256];
	u32 salt = 0;
	struct ext_key master_extkey, child_extkey;
	secp256k1_keypair bolt12;

	// This needs to be computed on the remote server!
	memset(&bad_hsm_secret, 0, sizeof(bad_hsm_secret));

	/* Fill in the BIP32 tree for bitcoin addresses. */
	/* In libwally-core, the version BIP32_VER_TEST_PRIVATE is for testnet/regtest,
	 * and BIP32_VER_MAIN_PRIVATE is for mainnet. For litecoin, we also set it like
	 * bitcoin else.*/
	do {
		hkdf_sha256(bip32_seed, sizeof(bip32_seed),
			    &salt, sizeof(salt),
			    &bad_hsm_secret,
			    sizeof(bad_hsm_secret),
			    "bip32 seed", strlen("bip32 seed"));
		salt++;
	} while (bip32_key_from_seed(bip32_seed, sizeof(bip32_seed),
				     bip32_key_version.bip32_privkey_version,
				     0, &master_extkey) != WALLY_OK);

	if (bip32_key_from_parent(&master_extkey,
				  BIP32_INITIAL_HARDENED_CHILD|9735,
				  BIP32_FLAG_KEY_PRIVATE,
				  &child_extkey) != WALLY_OK)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't derive bolt12 bip32 key");

	/* libwally says: The private key with prefix byte 0; remove it
	 * for libsecp256k1. */
	if (secp256k1_keypair_create(secp256k1_ctx, &bolt12,
				     child_extkey.priv_key+1) != 1)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't derive bolt12 keypair");

	/* We also give it the base key for bolt12 payerids */
	if (secp256k1_keypair_xonly_pub(secp256k1_ctx, &bolt12out->pubkey, NULL,
					&bolt12) != 1)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "Could derive bolt12 public key.");
}

// TODO - Add support for onion_reply_secret to remote signer and remove this
// entire routine.  This does not actually setup a usable onion_reply_secret
// context; it always uses an empty hsm_secret.
static void bogus_onion_reply_secret_placeholder(struct secret *onion_reply_secret)
{
	// This needs to be computed on the remote server!
	memset(&onion_reply_secret, 0, sizeof(onion_reply_secret));
}

static void persist_node_id(const struct node_id *node_id)
{
	char *node_id_str = tal_fmt(tmpctx, "%s\n",
				    type_to_string(tmpctx, struct node_id, node_id));
	int fd = open("NODE_ID", O_WRONLY|O_TRUNC|O_CREAT, 0666);
	assert(fd != -1);
	write_all(fd, node_id_str, strlen(node_id_str));
	close(fd);
}

static bool restore_node_id(struct node_id *node_id)
{
	if (access("NODE_ID", F_OK) == -1) {
		// This is a cold start, we don't have a node_id yet.
		return false;
	}

	char *buffer = grab_file(tmpctx, "NODE_ID");
	assert(buffer != NULL);
	size_t len = tal_bytelen(buffer) - 2;
	assert(buffer[len] == '\n');
	bool ok = node_id_from_hexstr(buffer, len, node_id);
	assert(ok);
	return true;
}

/*~ This is the response to lightningd's HSM_INIT request, which is the first
 * thing it sends. */
static struct io_plan *init_hsm(struct io_conn *conn,
				struct client *c,
				const u8 *msg_in)
{
	struct node_id node_id;
	struct point32 bolt12;
	struct secret onion_reply_secret;
	struct privkey *force_privkey;
	struct secret *force_bip32_seed;
	struct secrets *force_channel_secrets;
	struct sha256 *force_channel_secrets_shaseed;
	struct secret *hsm_encryption_key;
	struct secret hsm_secret;
	bool coldstart;

	/* This must be lightningd. */
	assert(is_lightningd(c));

	/*~ The fromwire_* routines are autogenerated, based on the message
	 * definitions in hsm_client_wire.csv.  The format of those files is
	 * an extension of the simple comma-separated format output by the
	 * BOLT tools/extract-formats.py tool. */
	if (!fromwire_hsm_init(NULL, msg_in, &bip32_key_version, &chainparams,
	                       &hsm_encryption_key, &force_privkey,
			       &force_bip32_seed, &force_channel_secrets,
			       &force_channel_secrets_shaseed))
		return bad_req(conn, c, msg_in);

#if DEVELOPER
	dev_force_privkey = force_privkey;
	dev_force_bip32_seed = force_bip32_seed;
	dev_force_channel_secrets = force_channel_secrets;
	dev_force_channel_secrets_shaseed = force_channel_secrets_shaseed;
#endif

	// We can't force any of these secrets individually, we only
	// can set the seed (for testnet integration tests).  If we
	// see anything being set fail fast.
	assert(force_privkey == NULL);
	assert(force_bip32_seed == NULL);
	assert(force_channel_secrets == NULL);
	assert(force_channel_secrets_shaseed == NULL);

	/* The hsm_encryption_key doesn't make any sense with the
	 * remote signer, fail-fast if it's set.
	 */
	assert(hsm_encryption_key == NULL);

	/* Once we have read the init message we know which params the master
	 * will use */
	c->chainparams = chainparams;

	/* To support integration tests we honor any seed provided
	 * in the hsm_secret file (testnet only). Otherwise we
	 * generate a random seed.
	 */
	if (!read_test_seed(&hsm_secret)) {
		randombytes_buf(&hsm_secret, sizeof(hsm_secret));
	}

	/* Is this a warm start (restart) or a cold start (first time)? */
	coldstart = access("WARM", F_OK) == -1;

	proxy_stat rv = proxy_init_hsm(&bip32_key_version, chainparams,
				       coldstart, &hsm_secret,
				       &node_id, &pubstuff.bip32);
	if (PROXY_PERMANENT(rv)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	}
	else if (!PROXY_SUCCESS(rv)) {
		status_unusual("proxy_%s failed: %s", __FUNCTION__,
			       proxy_last_message());
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());
	}

	// TODO - add support for bolt12
	bogus_bolt12_placeholder(&bolt12);

	// TODO - add support for onion_reply_secret
	bogus_onion_reply_secret_placeholder(&onion_reply_secret);

	/* Now we can consider ourselves initialized, and we won't get
	 * upset if we get a non-init message. */
	initialized = true;

	/* Mark this node as already inited. */
	int fd = open("WARM", O_WRONLY|O_TRUNC|O_CREAT, 0666);
	assert(fd != -1);
	close(fd);

	return req_reply(conn, c,
			 take(towire_hsmd_init_reply(NULL, &node_id,
						     &pubstuff.bip32,
						     &bolt12, &onion_reply_secret)));
}

/*~ The client has asked us to extract the shared secret from an EC Diffie
 * Hellman token.  This doesn't leak any information, but requires the private
 * key, so the hsmd performs it.  It's used to set up an encryption key for the
 * connection handshaking (BOLT #8) and for the onion wrapping (BOLT #4). */
static struct io_plan *handle_ecdh(struct io_conn *conn,
				   struct client *c,
				   const u8 *msg_in)
{
	struct pubkey point;
	struct secret ss;

	if (!fromwire_hsm_ecdh_req(msg_in, &point))
		return bad_req(conn, c, msg_in);

	proxy_stat rv = proxy_handle_ecdh(&point, &ss);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	/*~ In the normal case, we return the shared secret, and then read
	 * the next msg. */
	return req_reply(conn, c, take(towire_hsm_ecdh_resp(NULL, &ss)));
}

/*~ The specific routine to sign the channel_announcement message.  This is
 * defined in BOLT #7, and requires *two* signatures: one from this node's key
 * (to prove it's from us), and one from the bitcoin key used to create the
 * funding transaction (to prove we own the output). */
static struct io_plan *handle_cannouncement_sig(struct io_conn *conn,
						struct client *c,
						const u8 *msg_in)
{
	/*~ Our autogeneration code doesn't define field offsets, so we just
	 * copy this from the spec itself.
	 *
	 * Note that 'check-source' will actually find and check this quote
	 * against the spec (if available); whitespace is ignored and
	 * "..." means some content is skipped, but it works remarkably well to
	 * track spec changes. */

	/* BOLT #7:
	 *
	 * - MUST compute the double-SHA256 hash `h` of the message, beginning
	 *   at offset 256, up to the end of the message.
	 *     - Note: the hash skips the 4 signatures but hashes the rest of the
	 *       message, including any future fields appended to the end.
	 */
	/* First type bytes are the msg type */
	size_t offset = 2 + 256;
	secp256k1_ecdsa_signature node_sig, bitcoin_sig;
	u8 *reply;
	u8 *ca;

	/*~ You'll find FIXMEs like this scattered through the code.
	 * Sometimes they suggest simple improvements which someone like
	 * yourself should go ahead an implement.  Sometimes they're deceptive
	 * quagmires which will cause you nothing but grief.  You decide! */

	/*~ Christian uses TODO(cdecker) or FIXME(cdecker), but I'm sure he won't
	 * mind if you fix this for him! */

	/*~ fromwire_ routines which need to do allocation take a tal context
	 * as their first field; tmpctx is good here since we won't need it
	 * after this function. */
	if (!fromwire_hsm_cannouncement_sig_req(tmpctx, msg_in, &ca))
		return bad_req(conn, c, msg_in);

	if (tal_count(ca) < offset)
		return bad_req_fmt(conn, c, msg_in,
				   "bad cannounce length %zu",
				   tal_count(ca));

	if (fromwire_peektype(ca) != WIRE_CHANNEL_ANNOUNCEMENT)
		return bad_req_fmt(conn, c, msg_in,
				   "Invalid channel announcement");

	proxy_stat rv = proxy_handle_cannouncement_sig(
		&c->id, c->dbid, ca,
		&node_sig, &bitcoin_sig
		);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	reply = towire_hsm_cannouncement_sig_reply(NULL, &node_sig,
						   &bitcoin_sig);
	return req_reply(conn, c, take(reply));
}

/*~ The specific routine to sign the channel_update message. */
static struct io_plan *handle_channel_update_sig(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	/* BOLT #7:
	 *
	 * - MUST set `signature` to the signature of the double-SHA256 of the
	 *   entire remaining packet after `signature`, using its own
	 *   `node_id`.
	 */
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	secp256k1_ecdsa_signature sig;
	struct short_channel_id scid;
	u32 timestamp, fee_base_msat, fee_proportional_mill;
	struct amount_msat htlc_minimum, htlc_maximum;
	u8 message_flags, channel_flags;
	u16 cltv_expiry_delta;
	struct bitcoin_blkid chain_hash;
	u8 *cu;

	if (!fromwire_hsm_cupdate_sig_req(tmpctx, msg_in, &cu))
		return bad_req(conn, c, msg_in);

	if (!fromwire_channel_update_option_channel_htlc_max(cu, &sig,
			&chain_hash, &scid, &timestamp, &message_flags,
			&channel_flags, &cltv_expiry_delta,
			&htlc_minimum, &fee_base_msat,
			&fee_proportional_mill, &htlc_maximum)) {
		return bad_req_fmt(conn, c, msg_in, "Bad inner channel_update");
	}
	if (tal_count(cu) < offset)
		return bad_req_fmt(conn, c, msg_in,
				   "inner channel_update too short");

	proxy_stat rv = proxy_handle_channel_update_sig(cu, &sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	cu = towire_channel_update_option_channel_htlc_max(tmpctx, &sig, &chain_hash,
				   &scid, timestamp, message_flags, channel_flags,
				   cltv_expiry_delta, htlc_minimum,
				   fee_base_msat, fee_proportional_mill,
				   htlc_maximum);
	return req_reply(conn, c, take(towire_hsm_cupdate_sig_reply(NULL, cu)));
}

/*~ This gets the basepoints for a channel; it's not private information really
 * (we tell the peer this to establish a channel, as it sets up the keys used
 * for each transaction).
 *
 * Note that this is asked by lightningd, so it tells us what channels it wants.
 */
static struct io_plan *handle_get_channel_basepoints(struct io_conn *conn,
						     struct client *c,
						     const u8 *msg_in)
{
	struct node_id peer_id;
	u64 dbid;
	struct basepoints basepoints;
	struct pubkey funding_pubkey;

	if (!fromwire_hsm_get_channel_basepoints(msg_in, &peer_id, &dbid))
		return bad_req(conn, c, msg_in);

	proxy_stat rv = proxy_handle_get_channel_basepoints(
		&peer_id, dbid, &basepoints, &funding_pubkey);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c,
			 take(towire_hsm_get_channel_basepoints_reply(NULL,
							      &basepoints,
							      &funding_pubkey)));
}

/*~ This is another lightningd-only interface; signing a commit transaction.
 * This is dangerous, since if we sign a revoked commitment tx we'll lose
 * funds, thus it's only available to lightningd.
 *
 *
 * Oh look, another FIXME! */
/* FIXME: Ensure HSM never does this twice for same dbid! */
static struct io_plan *handle_sign_commitment_tx(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	struct pubkey remote_funding_pubkey;
	struct node_id peer_id;
	u64 dbid;
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;

	if (!fromwire_hsm_sign_commitment_tx(tmpctx, msg_in,
					     &peer_id, &dbid,
					     &tx,
					     &remote_funding_pubkey))
		return bad_req(conn, c, msg_in);

	tx->chainparams = c->chainparams;

	/* Basic sanity checks. */
	if (tx->wtx->num_inputs != 1)
		return bad_req_fmt(conn, c, msg_in, "tx must have 1 input");
	if (tx->wtx->num_outputs == 0)
		return bad_req_fmt(conn, c, msg_in, "tx must have > 0 outputs");

	proxy_stat rv = proxy_handle_sign_commitment_tx(
		tx, &remote_funding_pubkey, &peer_id, dbid, &sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c,
			 take(towire_hsm_sign_commitment_tx_reply(NULL, &sig)));
}

/*~ This is used by channeld to create signatures for the remote peer's
 * commitment transaction.  It's functionally identical to signing our own,
 * but we expect to do this repeatedly as commitment transactions are
 * updated.
 *
 * The HSM almost certainly *should* do more checks before signing!
 */
/* FIXME: make sure it meets some criteria? */
static struct io_plan *handle_sign_remote_commitment_tx(struct io_conn *conn,
							struct client *c,
							const u8 *msg_in)
{
	struct pubkey remote_funding_pubkey;
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;
	struct pubkey remote_per_commit;
	bool option_static_remotekey;

	if (!fromwire_hsm_sign_remote_commitment_tx(tmpctx, msg_in,
						    &tx,
						    &remote_funding_pubkey,
						    &remote_per_commit,
						    &option_static_remotekey))
		bad_req(conn, c, msg_in);
	tx->chainparams = c->chainparams;

	/* Basic sanity checks. */
	if (tx->wtx->num_inputs != 1)
		return bad_req_fmt(conn, c, msg_in, "tx must have 1 input");
	if (tx->wtx->num_outputs == 0)
		return bad_req_fmt(conn, c, msg_in, "tx must have > 0 outputs");

	proxy_stat rv = proxy_handle_sign_remote_commitment_tx(
		tx, &remote_funding_pubkey,
		&c->id, c->dbid,
		&remote_per_commit,
		option_static_remotekey,
		&sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	STATUS_DEBUG("%s:%d %s: signature: %s",
		     __FILE__, __LINE__, __FUNCTION__,
		     type_to_string(tmpctx, struct bitcoin_signature, &sig));

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/*~ This is used by channeld to create signatures for the remote peer's
 * HTLC transactions. */
static struct io_plan *handle_sign_remote_htlc_tx(struct io_conn *conn,
						  struct client *c,
						  const u8 *msg_in)
{
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;
	struct pubkey remote_per_commit_point;
	u8 *wscript;

	if (!fromwire_hsm_sign_remote_htlc_tx(tmpctx, msg_in,
					      &tx, &wscript,
					      &remote_per_commit_point))
		return bad_req(conn, c, msg_in);
	tx->chainparams = c->chainparams;

	proxy_stat rv = proxy_handle_sign_remote_htlc_tx(
		tx,
		wscript,
		&remote_per_commit_point,
		&c->id,
		c->dbid,
		&sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/*~ When we send a commitment transaction onchain (unilateral close), there's
 * a delay before we can spend it.  onchaind does an explicit transaction to
 * transfer it to the wallet so that doesn't need to remember how to spend
 * this complex transaction. */
static struct io_plan *handle_sign_delayed_payment_to_us(struct io_conn *conn,
							 struct client *c,
							 const u8 *msg_in)
{
	u64 commit_num;
	struct bitcoin_tx *tx;
	u8 *wscript;

	/*~ We don't derive the wscript ourselves, but perhaps we should? */
	if (!fromwire_hsm_sign_delayed_payment_to_us(tmpctx, msg_in,
						     &commit_num,
						     &tx, &wscript))
		return bad_req(conn, c, msg_in);
	tx->chainparams = c->chainparams;

	struct bitcoin_signature sig;
	proxy_stat rv = proxy_handle_sign_delayed_payment_to_us(
		tx, commit_num, wscript, &c->id, c->dbid, &sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/*~ This is used when a commitment transaction is onchain, and has an HTLC
 * output paying to us (because we have the preimage); this signs that
 * transaction, which lightningd will broadcast to collect the funds. */
static struct io_plan *handle_sign_remote_htlc_to_us(struct io_conn *conn,
						     struct client *c,
						     const u8 *msg_in)
{
	struct bitcoin_tx *tx;
	struct pubkey remote_per_commitment_point;
	u8 *wscript;

	if (!fromwire_hsm_sign_remote_htlc_to_us(tmpctx, msg_in,
						 &remote_per_commitment_point,
						 &tx, &wscript))
		return bad_req(conn, c, msg_in);

	tx->chainparams = c->chainparams;

	struct bitcoin_signature sig;
	proxy_stat rv = proxy_handle_sign_remote_htlc_to_us(
		tx,
		wscript,
		&remote_per_commitment_point,
		&c->id,
		c->dbid,
		&sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/*~ This is used when the remote peer's commitment transaction is revoked;
 * we can use the revocation secret to spend the outputs.  For simplicity,
 * we do them one at a time, though. */
static struct io_plan *handle_sign_penalty_to_us(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	struct secret revocation_secret;
	struct bitcoin_tx *tx;
	u8 *wscript;

	if (!fromwire_hsm_sign_penalty_to_us(tmpctx, msg_in,
					     &revocation_secret,
					     &tx, &wscript))
		return bad_req(conn, c, msg_in);
	tx->chainparams = c->chainparams;

	struct bitcoin_signature sig;
	proxy_stat rv = proxy_handle_sign_penalty_to_us(
		tx, &revocation_secret, wscript, &c->id, c->dbid, &sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/*~ This is used when a commitment transaction is onchain, and has an HTLC
 * output paying to them, which has timed out; this signs that transaction,
 * which lightningd will broadcast to collect the funds. */
static struct io_plan *handle_sign_local_htlc_tx(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	u64 commit_num;
	struct bitcoin_tx *tx;
	u8 *wscript;
	struct bitcoin_signature sig;

	if (!fromwire_hsm_sign_local_htlc_tx(tmpctx, msg_in,
					     &commit_num, &tx, &wscript))
		return bad_req(conn, c, msg_in);

	tx->chainparams = c->chainparams;

	proxy_stat rv = proxy_handle_sign_local_htlc_tx(
		tx, commit_num, wscript, &c->id, c->dbid, &sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/*~ This get the Nth a per-commitment point, and for N > 2, returns the
 * grandparent per-commitment secret.  This pattern is because after
 * negotiating commitment N-1, we send them the next per-commitment point,
 * and reveal the previous per-commitment secret as a promise not to spend
 * the previous commitment transaction. */
static struct io_plan *handle_get_per_commitment_point(struct io_conn *conn,
						       struct client *c,
						       const u8 *msg_in)
{
	struct pubkey per_commitment_point;
	u64 n;
	struct secret *old_secret;

	if (!fromwire_hsm_get_per_commitment_point(msg_in, &n))
		return bad_req(conn, c, msg_in);

	proxy_stat rv = proxy_handle_get_per_commitment_point(
		&c->id, c->dbid, n,
		&per_commitment_point, &old_secret);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	/*~ hsm_client_wire.csv marks the secret field here optional, so it only
	 * gets included if the parameter is non-NULL.  We violate 80 columns
	 * pretty badly here, but it's a recommendation not a religion. */
	return req_reply(conn, c,
			 take(towire_hsm_get_per_commitment_point_reply(NULL,
									&per_commitment_point,
									old_secret)));
}

/*~ This is used when the remote peer claims to have knowledge of future
 * commitment states (option_data_loss_protect in the spec) which means we've
 * been restored from backup or something, and may have already revealed
 * secrets.  We carefully check that this is true, here. */
static struct io_plan *handle_check_future_secret(struct io_conn *conn,
						  struct client *c,
						  const u8 *msg_in)
{
	u64 n;
	struct secret suggested;

	if (!fromwire_hsm_check_future_secret(msg_in, &n, &suggested))
		return bad_req(conn, c, msg_in);

	bool correct;
	proxy_stat rv = proxy_handle_check_future_secret(
		&c->id, c->dbid, n, &suggested, &correct);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c,
			 take(towire_hsm_check_future_secret_reply(NULL,
								   correct)));
}

/* This is used by closingd to sign off on a mutual close tx. */
static struct io_plan *handle_sign_mutual_close_tx(struct io_conn *conn,
						   struct client *c,
						   const u8 *msg_in)
{
	struct bitcoin_tx *tx;
	struct pubkey remote_funding_pubkey;
	struct bitcoin_signature sig;

	if (!fromwire_hsm_sign_mutual_close_tx(tmpctx, msg_in,
					       &tx,
					       &remote_funding_pubkey))
		return bad_req(conn, c, msg_in);

	tx->chainparams = c->chainparams;

	proxy_stat rv = proxy_handle_sign_mutual_close_tx(
		tx, &remote_funding_pubkey, &c->id, c->dbid, &sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c, take(towire_hsm_sign_tx_reply(NULL, &sig)));
}

/*~ Since we process requests then service them in strict order, and because
 * only lightningd can request a new client fd, we can get away with a global
 * here!  But because we are being tricky, I set it to an invalid value when
 * not in use, and sprinkle assertions around. */
static int pending_client_fd = -1;

/*~ This is the callback from below: having sent the reply, we now send the
 * fd for the client end of the new socketpair. */
static struct io_plan *send_pending_client_fd(struct io_conn *conn,
					      struct client *master)
{
	int fd = pending_client_fd;
	/* This must be the master. */
	assert(is_lightningd(master));
	assert(fd != -1);

	/* This sanity check shouldn't be necessary, but it's cheap. */
	pending_client_fd = -1;

	/*~There's arcane UNIX magic to send an open file descriptor over a
	 * UNIX domain socket.  There's no great way to autogenerate this
	 * though; especially for the receive side, so we always pass these
	 * manually immediately following the message.
	 *
	 * io_send_fd()'s third parameter is whether to close the local one
	 * after sending; that saves us YA callback.
	 */
	return io_send_fd(conn, fd, true, client_read_next, master);
}

/*~ This is used by the master to create a new client connection (which
 * becomes the HSM_FD for the subdaemon after forking). */
static struct io_plan *pass_client_hsmfd(struct io_conn *conn,
					 struct client *c,
					 const u8 *msg_in)
{
	int fds[2];
	u64 dbid, capabilities;
	struct node_id id;

	/* This must be lightningd itself. */
	assert(is_lightningd(c));

	if (!fromwire_hsm_client_hsmfd(msg_in, &id, &dbid, &capabilities))
		return bad_req(conn, c, msg_in);

	/* socketpair is a bi-directional pipe, which is what we want. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR, "creating fds: %s",
			      strerror(errno));

	STATUS_DEBUG("new_client: %"PRIu64, dbid);
	new_client(c, c->chainparams, &id, dbid, capabilities, fds[0]);

	// Skip zero dbid (master, gossipd, connectd).
	if (dbid != 0) {
		proxy_stat rv = proxy_handle_pass_client_hsmfd(&id, dbid, capabilities);
		if (PROXY_PERMANENT(rv))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "proxy_%s failed: %s", __FUNCTION__,
				      proxy_last_message());
		else if (!PROXY_SUCCESS(rv))
			return bad_req_fmt(conn, c, msg_in,
					   "proxy_%s error: %s", __FUNCTION__,
					   proxy_last_message());
	}

	/*~ We stash this in a global, because we need to get both the fd and
	 * the client pointer to the callback.  The other way would be to
	 * create a boutique structure and hand that, but we don't need to. */
	pending_client_fd = fds[1];
	return io_write_wire(conn, take(towire_hsm_client_hsmfd_reply(NULL)),
			     send_pending_client_fd, c);
}

/*~ This is used to declare a new channel. */
static struct io_plan *handle_new_channel(struct io_conn *conn,
					  struct client *c,
					  const u8 *msg_in)
{
	struct node_id peer_id;
	u64 dbid;

	if (!fromwire_hsm_new_channel(msg_in, &peer_id, &dbid))
		return bad_req(conn, c, msg_in);

	proxy_stat rv = proxy_handle_new_channel(&peer_id, dbid);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c,
			 take(towire_hsm_new_channel_reply(NULL)));
}

/*~ This is used to provide all unchanging public channel parameters. */
static struct io_plan *handle_ready_channel(struct io_conn *conn,
					    struct client *c,
					    const u8 *msg_in)
{
	bool is_outbound;
	struct amount_sat channel_value;
	struct amount_msat push_value;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	u16 local_to_self_delay;
	u8 *local_shutdown_script;
	struct basepoints remote_basepoints;
	struct pubkey remote_funding_pubkey;
	u16 remote_to_self_delay;
	u8 *remote_shutdown_script;
	bool option_static_remotekey;

	if (!fromwire_hsm_ready_channel(tmpctx, msg_in, &is_outbound,
					&channel_value, &push_value, &funding_txid,
					&funding_txout, &local_to_self_delay,
					&local_shutdown_script,
					&remote_basepoints,
					&remote_funding_pubkey,
					&remote_to_self_delay,
					&remote_shutdown_script,
					&option_static_remotekey))
		return bad_req(conn, c, msg_in);

	proxy_stat rv = proxy_handle_ready_channel(
		&c->id, c->dbid,
		is_outbound,
		&channel_value,
		&push_value,
		&funding_txid,
		funding_txout,
		local_to_self_delay,
		local_shutdown_script,
		&remote_basepoints,
		&remote_funding_pubkey,
		remote_to_self_delay,
		remote_shutdown_script,
		option_static_remotekey);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());
	return req_reply(conn, c,
			 take(towire_hsm_ready_channel_reply(NULL)));
}

/*~ lightningd asks us to sign a withdrawal; same as above but in theory
 * we can do more to check the previous case is valid. */
static struct io_plan *handle_sign_withdrawal_tx(struct io_conn *conn,
						 struct client *c,
						 const u8 *msg_in)
{
	struct utxo **utxos;
	struct wally_psbt *psbt;

	if (!fromwire_hsm_sign_withdrawal(tmpctx, msg_in,
					  &utxos, &psbt))
		return bad_req(conn, c, msg_in);

	struct bitcoin_tx_output **outputs;
	outputs = tal_arr(tmpctx, struct bitcoin_tx_output *, psbt->num_outputs);
	for (size_t ii = 0; ii < psbt->num_outputs; ++ii) {
		outputs[ii] = tal(outputs, struct bitcoin_tx_output);
		outputs[ii]->amount.satoshis = psbt->tx->outputs[ii].satoshi; /* Raw: from wally_tx_output */
		outputs[ii]->script =
			tal_dup_arr(outputs[ii], u8,
				    psbt->tx->outputs[ii].script,
				    psbt->tx->outputs[ii].script_len, 0);
	}

	u8 *** wits;
	proxy_stat rv = proxy_handle_sign_withdrawal_tx(
		&c->id, c->dbid, outputs, utxos, psbt, &wits);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	/* We must have one witness element for each input. */
	assert(tal_count(wits) == psbt->num_inputs);

	/* Witnesses and inputs are in the same order. */
	for (size_t kk = 0; kk < tal_count(wits); ++kk) {
		struct wally_psbt_input *input = &psbt->inputs[kk];
		u8 *sig = wits[kk][0];
		u8 *pubkey = wits[kk][1];
		int ret;

		/* If this is a PSBT, we should skip any inputs that
		 * have an empty signature. */
		if (tal_count(sig) == 0)
			continue;

		struct pubkey spubkey;
		pubkey_from_der(pubkey, EC_PUBLIC_KEY_LEN, &spubkey);
		psbt_input_add_pubkey(psbt, kk, &spubkey);

		if (!input->partial_sigs) {
			ret = wally_partial_sigs_map_init_alloc(
				1, &input->partial_sigs);
			assert(ret == WALLY_OK);
		}

		ret = wally_add_new_partial_sig(
			input->partial_sigs,
			pubkey, EC_PUBLIC_KEY_LEN,
			sig, tal_count(sig));
		assert(ret == WALLY_OK);
	}

	return req_reply(conn, c,
			 take(towire_hsm_sign_withdrawal_reply(NULL, psbt)));
}

/*~ Lightning invoices, defined by BOLT 11, are signed.  This has been
 * surprisingly controversial; it means a node needs to be online to create
 * invoices.  However, it seems clear to me that in a world without
 * intermedaries you need proof that you have received an offer (the
 * signature), as well as proof that you've paid it (the preimage). */
static struct io_plan *handle_sign_invoice(struct io_conn *conn,
					   struct client *c,
					   const u8 *msg_in)
{
	/*~ We make up a 'u5' type to represent BOLT11's 5-bits-per-byte
	 * format: it's only for human consumption, as typedefs are almost
	 * entirely transparent to the C compiler. */
	u5 *u5bytes;
	u8 *hrpu8;
        secp256k1_ecdsa_recoverable_signature rsig;

	if (!fromwire_hsm_sign_invoice(tmpctx, msg_in, &u5bytes, &hrpu8))
		return bad_req(conn, c, msg_in);

	proxy_stat rv = proxy_handle_sign_invoice(u5bytes, hrpu8, &rsig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c,
			 take(towire_hsm_sign_invoice_reply(NULL, &rsig)));
}

/*~ It's optional for nodes to send node_announcement, but it lets us set our
 * favourite color and cool alias!  Plus other minor details like how to
 * connect to us. */
static struct io_plan *handle_sign_node_announcement(struct io_conn *conn,
						     struct client *c,
						     const u8 *msg_in)
{
	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 * - MUST set `signature` to the signature of the double-SHA256 of the
	 *   entire remaining packet after `signature` (using the key given by
	 *   `node_id`).
	 */
	/* 2 bytes msg type + 64 bytes signature */
	size_t offset = 66;
	secp256k1_ecdsa_signature sig;
	u8 *reply;
	u8 *ann;

	if (!fromwire_hsm_node_announcement_sig_req(tmpctx, msg_in, &ann))
		return bad_req(conn, c, msg_in);

	if (tal_count(ann) < offset)
		return bad_req_fmt(conn, c, msg_in,
				   "Node announcement too short");

	if (fromwire_peektype(ann) != WIRE_NODE_ANNOUNCEMENT)
		return bad_req_fmt(conn, c, msg_in,
				   "Invalid announcement");

	proxy_stat rv = proxy_handle_sign_node_announcement(ann, &sig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	reply = towire_hsm_node_announcement_sig_reply(NULL, &sig);
	return req_reply(conn, c, take(reply));
}

/*~ lightningd asks us to sign a message.  I tweeted the spec
 * in https://twitter.com/rusty_twit/status/1182102005914800128:
 *
 * @roasbeef & @bitconner point out that #lnd algo is:
 *    zbase32(SigRec(SHA256(SHA256("Lightning Signed Message:" + msg)))).
 * zbase32 from https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
 * and SigRec has first byte 31 + recovery id, followed by 64 byte sig.  #specinatweet
 */
static struct io_plan *handle_sign_message(struct io_conn *conn,
					   struct client *c,
					   const u8 *msg_in)
{
	u8 *msg;
	secp256k1_ecdsa_recoverable_signature rsig;

	if (!fromwire_hsm_sign_message(tmpctx, msg_in, &msg))
		return bad_req(conn, c, msg_in);

	proxy_stat rv = proxy_handle_sign_message(msg, &rsig);
	if (PROXY_PERMANENT(rv))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
		              "proxy_%s failed: %s", __FUNCTION__,
			      proxy_last_message());
	else if (!PROXY_SUCCESS(rv))
		return bad_req_fmt(conn, c, msg_in,
				   "proxy_%s error: %s", __FUNCTION__,
				   proxy_last_message());

	return req_reply(conn, c,
			 take(towire_hsm_sign_message_reply(NULL, &rsig)));
}

#if DEVELOPER
static struct io_plan *handle_memleak(struct io_conn *conn,
				      struct client *c,
				      const u8 *msg_in)
{
	struct htable *memtable;
	bool found_leak;
	u8 *reply;

	memtable = memleak_enter_allocations(tmpctx, msg_in, msg_in);

	/* Now delete clients and anything they point to. */
	memleak_remove_referenced(memtable, c);
	memleak_scan_region(memtable,
			    dbid_zero_clients, sizeof(dbid_zero_clients));
	memleak_remove_uintmap(memtable, &clients);
	memleak_scan_region(memtable, status_conn, tal_bytelen(status_conn));

	memleak_scan_region(memtable, dev_force_privkey, 0);
	memleak_scan_region(memtable, dev_force_bip32_seed, 0);

	found_leak = dump_memleak(memtable, memleak_status_broken);
	reply = towire_hsmd_dev_memleak_reply(NULL, found_leak);
	return req_reply(conn, c, take(reply));
}
#endif /* DEVELOPER */

/*~ This routine checks that a client is allowed to call the handler. */
static bool check_client_capabilities(struct client *client,
				      enum hsm_wire_type t)
{
	/*~ Here's a useful trick: enums in C are not real types, they're
	 * semantic sugar sprinkled over an int, bascally (in fact, older
	 * versions of gcc used to convert the values ints in the parser!).
	 *
	 * But GCC will do one thing for us: if we have a switch statement
	 * with a controlling expression which is an enum, it will warn us
	 * if a declared enum value is *not* handled in the switch, eg:
	 *     enumeration value ‘FOOBAR’ not handled in switch [-Werror=switch]
	 *
	 * This only works if there's no 'default' label, which is sometimes
	 * hard, as we *can* have non-enum values in our enum.  But the tradeoff
	 * is worth it so the compiler tells us everywhere we have to fix when
	 * we add a new enum identifier!
	 */
	switch (t) {
	case WIRE_HSM_ECDH_REQ:
		return (client->capabilities & HSM_CAP_ECDH) != 0;

	case WIRE_HSM_CANNOUNCEMENT_SIG_REQ:
	case WIRE_HSM_CUPDATE_SIG_REQ:
	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REQ:
		return (client->capabilities & HSM_CAP_SIGN_GOSSIP) != 0;

	case WIRE_HSM_SIGN_DELAYED_PAYMENT_TO_US:
	case WIRE_HSM_SIGN_REMOTE_HTLC_TO_US:
	case WIRE_HSM_SIGN_PENALTY_TO_US:
	case WIRE_HSM_SIGN_LOCAL_HTLC_TX:
		return (client->capabilities & HSM_CAP_SIGN_ONCHAIN_TX) != 0;

	case WIRE_HSM_GET_PER_COMMITMENT_POINT:
	case WIRE_HSM_CHECK_FUTURE_SECRET:
	case WIRE_HSM_READY_CHANNEL:
		return (client->capabilities & HSM_CAP_COMMITMENT_POINT) != 0;

	case WIRE_HSM_SIGN_REMOTE_COMMITMENT_TX:
	case WIRE_HSM_SIGN_REMOTE_HTLC_TX:
		return (client->capabilities & HSM_CAP_SIGN_REMOTE_TX) != 0;

	case WIRE_HSM_SIGN_MUTUAL_CLOSE_TX:
		return (client->capabilities & HSM_CAP_SIGN_CLOSING_TX) != 0;

	case WIRE_HSM_INIT:
	case WIRE_HSM_NEW_CHANNEL:
	case WIRE_HSM_CLIENT_HSMFD:
	case WIRE_HSM_SIGN_WITHDRAWAL:
	case WIRE_HSM_SIGN_INVOICE:
	case WIRE_HSM_SIGN_COMMITMENT_TX:
	case WIRE_HSM_GET_CHANNEL_BASEPOINTS:
	case WIRE_HSM_DEV_MEMLEAK:
	case WIRE_HSM_SIGN_MESSAGE:
		return (client->capabilities & HSM_CAP_MASTER) != 0;

	/*~ These are messages sent by the HSM so we should never receive them. */
	/* FIXME: Since we autogenerate these, we should really generate separate
	 * enums for replies to avoid this kind of clutter! */
	case WIRE_HSM_ECDH_RESP:
	case WIRE_HSM_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_CUPDATE_SIG_REPLY:
	case WIRE_HSM_CLIENT_HSMFD_REPLY:
	case WIRE_HSM_NEW_CHANNEL_REPLY:
	case WIRE_HSM_READY_CHANNEL_REPLY:
	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSM_SIGN_INVOICE_REPLY:
	case WIRE_HSM_INIT_REPLY:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
	case WIRE_HSM_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSM_SIGN_TX_REPLY:
	case WIRE_HSM_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSM_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSM_GET_CHANNEL_BASEPOINTS_REPLY:
	case WIRE_HSM_DEV_MEMLEAK_REPLY:
	case WIRE_HSM_SIGN_MESSAGE_REPLY:
		break;
	}
	return false;
}

/*~ This is the core of the HSM daemon: handling requests. */
static struct io_plan *handle_client(struct io_conn *conn, struct client *c)
{
	enum hsm_wire_type t = fromwire_peektype(c->msg_in);

	STATUS_DEBUG("Client: Received message %d from client", t);

	/* Before we do anything else, is this client allowed to do
	 * what he asks for? */
	if (!check_client_capabilities(c, t)) {
		return bad_req_fmt(conn, c, c->msg_in,
				   "does not have capability to run %d", t);
	}

	/* Now actually go and do what the client asked for */
	switch (t) {
	case WIRE_HSM_INIT:
		return init_hsm(conn, c, c->msg_in);

	case WIRE_HSM_CLIENT_HSMFD:
		return pass_client_hsmfd(conn, c, c->msg_in);

	case WIRE_HSM_NEW_CHANNEL:
		return handle_new_channel(conn, c, c->msg_in);

	case WIRE_HSM_READY_CHANNEL:
		return handle_ready_channel(conn, c, c->msg_in);

	case WIRE_HSM_GET_CHANNEL_BASEPOINTS:
		return handle_get_channel_basepoints(conn, c, c->msg_in);

	case WIRE_HSM_ECDH_REQ:
		return handle_ecdh(conn, c, c->msg_in);

	case WIRE_HSM_CANNOUNCEMENT_SIG_REQ:
		return handle_cannouncement_sig(conn, c, c->msg_in);

	case WIRE_HSM_CUPDATE_SIG_REQ:
		return handle_channel_update_sig(conn, c, c->msg_in);

	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REQ:
		return handle_sign_node_announcement(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_INVOICE:
		return handle_sign_invoice(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_WITHDRAWAL:
		return handle_sign_withdrawal_tx(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_COMMITMENT_TX:
		return handle_sign_commitment_tx(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_DELAYED_PAYMENT_TO_US:
		return handle_sign_delayed_payment_to_us(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_REMOTE_HTLC_TO_US:
		return handle_sign_remote_htlc_to_us(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_PENALTY_TO_US:
		return handle_sign_penalty_to_us(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_LOCAL_HTLC_TX:
		return handle_sign_local_htlc_tx(conn, c, c->msg_in);

	case WIRE_HSM_GET_PER_COMMITMENT_POINT:
		return handle_get_per_commitment_point(conn, c, c->msg_in);

	case WIRE_HSM_CHECK_FUTURE_SECRET:
		return handle_check_future_secret(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_REMOTE_COMMITMENT_TX:
		return handle_sign_remote_commitment_tx(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_REMOTE_HTLC_TX:
		return handle_sign_remote_htlc_tx(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_MUTUAL_CLOSE_TX:
		return handle_sign_mutual_close_tx(conn, c, c->msg_in);

	case WIRE_HSM_SIGN_MESSAGE:
		return handle_sign_message(conn, c, c->msg_in);
#if DEVELOPER
	case WIRE_HSM_DEV_MEMLEAK:
		return handle_memleak(conn, c, c->msg_in);
#else
	case WIRE_HSM_DEV_MEMLEAK:
#endif /* DEVELOPER */
	case WIRE_HSM_ECDH_RESP:
	case WIRE_HSM_CANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_CUPDATE_SIG_REPLY:
	case WIRE_HSM_CLIENT_HSMFD_REPLY:
	case WIRE_HSM_NEW_CHANNEL_REPLY:
	case WIRE_HSM_READY_CHANNEL_REPLY:
	case WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REPLY:
	case WIRE_HSM_SIGN_WITHDRAWAL_REPLY:
	case WIRE_HSM_SIGN_INVOICE_REPLY:
	case WIRE_HSM_INIT_REPLY:
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
	case WIRE_HSM_SIGN_COMMITMENT_TX_REPLY:
	case WIRE_HSM_SIGN_TX_REPLY:
	case WIRE_HSM_GET_PER_COMMITMENT_POINT_REPLY:
	case WIRE_HSM_CHECK_FUTURE_SECRET_REPLY:
	case WIRE_HSM_GET_CHANNEL_BASEPOINTS_REPLY:
	case WIRE_HSM_DEV_MEMLEAK_REPLY:
	case WIRE_HSM_SIGN_MESSAGE_REPLY:
		break;
	}

	return bad_req_fmt(conn, c, c->msg_in, "Unknown request");
}

static void master_gone(struct io_conn *unused UNUSED, struct client *c UNUSED)
{
	daemon_shutdown();
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	struct client *master;

	setup_locale();

	/* This sets up tmpctx, various DEVELOPER options, backtraces, etc. */
	subdaemon_setup(argc, argv);

	/* A trivial daemon_conn just for writing. */
	status_conn = daemon_conn_new(NULL, STDIN_FILENO, NULL, NULL, NULL);
	status_setup_async(status_conn);
	uintmap_init(&clients);

	master = new_client(NULL, NULL, NULL, 0,
			    HSM_CAP_MASTER | HSM_CAP_SIGN_GOSSIP | HSM_CAP_ECDH,
			    REQ_FD);

	/* First client == lightningd. */
	assert(is_lightningd(master));

	/* When conn closes, everything is freed. */
	io_set_finish(master->conn, master_gone, master);

	/* Setup the remote proxy */
	proxy_setup();

	/*~ The two NULL args are a list of timers, and the timer which expired:
	 * we don't have any timers. */
	io_loop(NULL, NULL);

	/*~ This should never be reached: io_loop only exits on io_break which
	 * we don't call, a timer expiry which we don't have, or all connections
	 * being closed, and closing the master calls master_gone. */
	abort();
}

/*~ Congratulations on making it through the first of the seven dwarves!
 * (And Christian wondered why I'm so fond of having separate daemons!).
 *
 * We continue our story in the next-more-complex daemon: connectd/connectd.c
 */
