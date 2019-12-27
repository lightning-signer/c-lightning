#ifdef __cplusplus
extern "C" {
#endif
void proxy_setup(void);
void proxy_init_hsm(struct bip32_key_version *bip32_key_version,
		    struct chainparams const *chainparams,
		    struct secret *hsm_encryption_key,
		    struct privkey *privkey,
		    struct secret *seed,
		    struct secrets *secrets,
		    struct sha256 *shaseed,
		    struct secret *hsm_secret);
#ifdef __cplusplus
} /* extern C */
#endif
