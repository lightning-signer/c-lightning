#ifdef __cplusplus
extern "C" {
#endif

enum proxy_status {
	/* SUCCESS */
	PROXY_OK = 0,

	/* TRANSIENT */
	PROXY_TIMEOUT = 32,
	PROXY_UNAVAILABLE = 33,

	/* PERMANENT */
	PROXY_INVALID_ARGUMENT = 100,
	PROXY_INTERNAL_ERROR = 200,
};
typedef enum proxy_status proxy_stat;

#define PROXY_SUCCESS(rv)	((rv) < 32)
#define PROXY_TRANSIENT(rv)	((rv) >= 32 && (rv) < 100)
#define PROXY_PERMANENT(rv)	((rv) >= 100)

char const *proxy_last_message(void);

void proxy_setup(void);
proxy_stat proxy_init_hsm(struct bip32_key_version *bip32_key_version,
			  struct chainparams const *chainparams,
			  struct secret *hsm_encryption_key,
			  struct privkey *privkey,
			  struct secret *seed,
			  struct secrets *secrets,
			  struct sha256 *shaseed,
			  struct secret *hsm_secret,
			  struct node_id *o_node_id);

#ifdef __cplusplus
} /* extern C */
#endif
