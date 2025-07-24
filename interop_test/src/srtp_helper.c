#include <srtp2/srtp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int initialized = 0;

static void init_once() {
    if (!initialized) {
        srtp_init();
        initialized = 1;
    }
}

// This enum is identically mapped to integers in lib.rs on CryptoPolicyKind 
enum crypto_policy_kind {
    Aes128CmHmacSha180 = 0,
    Aes128CmHmacSha132,
    Aes128CmNullAuth,
    Aes192CmHmacSha180,
    Aes192CmHmacSha132,
    Aes192CmNullAuth,
    Aes256CmHmacSha180,
    Aes256CmHmacSha132,
    Aes256CmNullAuth,
    NullCipherHmacSha180,
    AeadAes128Gcm,
    AeadAes256Gcm,
};

static void set_policy_from_kind(srtp_crypto_policy_t *p, int kind) {
    switch (kind) {
        case Aes128CmHmacSha180:
		srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(p);
            break;
        case Aes128CmHmacSha132:
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(p);
            break;
        case Aes128CmNullAuth:
            srtp_crypto_policy_set_aes_cm_128_null_auth(p);
            break;
        case Aes192CmHmacSha180:
		srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(p);
            break;
        case Aes192CmHmacSha132:
            srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(p);
            break;
        case Aes192CmNullAuth:
            srtp_crypto_policy_set_aes_cm_192_null_auth(p);
            break;
        case Aes256CmHmacSha180:
		srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(p);
            break;
        case Aes256CmHmacSha132:
            srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(p);
            break;
        case Aes256CmNullAuth:
            srtp_crypto_policy_set_aes_cm_256_null_auth(p);
            break;
        case NullCipherHmacSha180:
            srtp_crypto_policy_set_null_cipher_hmac_sha1_80(p);
            break;
        case AeadAes128Gcm:
            srtp_crypto_policy_set_aes_gcm_128_16_auth(p);
            break;
        case AeadAes256Gcm:
            srtp_crypto_policy_set_aes_gcm_256_16_auth(p);
            break;
    }
}

typedef struct {
    srtp_t session;
} srtp_session_wrapper;

void* c_srtp_create_session(const unsigned char *key,
                            int inbound,
                            int rtp_policy_kind,
                            int rtcp_policy_kind) {
    init_once();

    srtp_policy_t policy;
    memset(&policy, 0, sizeof(policy));

    set_policy_from_kind(&policy.rtp, rtp_policy_kind);
    set_policy_from_kind(&policy.rtcp, rtcp_policy_kind);

    policy.ssrc.type = inbound ? ssrc_any_inbound : ssrc_any_outbound;
    policy.key = (uint8_t*)key;
    policy.next = NULL;

    srtp_t session;
    srtp_err_status_t status = srtp_create(&session, &policy);
    if (status != srtp_err_status_ok) {
        return NULL;
    }

    srtp_session_wrapper *wrapper = malloc(sizeof(srtp_session_wrapper));
    if (!wrapper) {
        srtp_dealloc(session);
        return NULL;
    }
    wrapper->session = session;
    return wrapper;
}

int c_srtp_protect(void *ctx, unsigned char *pkt, int *pkt_len) {
    if (!ctx) return -1;
    srtp_session_wrapper *wrapper = (srtp_session_wrapper*)ctx;
    return srtp_protect(wrapper->session, pkt, pkt_len);
}

int c_srtp_unprotect(void *ctx, unsigned char *pkt, int *pkt_len) {
    if (!ctx) return -1;
    srtp_session_wrapper *wrapper = (srtp_session_wrapper*)ctx;
    return srtp_unprotect(wrapper->session, pkt, pkt_len);
}

int c_srtp_protect_rtcp(void *ctx, unsigned char *pkt, int *pkt_len) {
    if (!ctx) return -1;
    srtp_session_wrapper *wrapper = (srtp_session_wrapper*)ctx;
    return srtp_protect_rtcp(wrapper->session, pkt, pkt_len);
}

int c_srtp_unprotect_rtcp(void *ctx, unsigned char *pkt, int *pkt_len) {
    if (!ctx) return -1;
    srtp_session_wrapper *wrapper = (srtp_session_wrapper*)ctx;
    return srtp_unprotect_rtcp(wrapper->session, pkt, pkt_len);
}

void c_srtp_free_session(void *ctx) {
    if (!ctx) return;
    srtp_session_wrapper *wrapper = (srtp_session_wrapper*)ctx;
    srtp_dealloc(wrapper->session);
    free(wrapper);
}

typedef struct {
    const unsigned char *key;
    int key_len;
    const unsigned char *mki;
    int mki_len;
} c_srtp_master_key_t;

void* c_srtp_create_session_mki(const c_srtp_master_key_t *keys,
                                int num_keys,
                                int inbound,
                            int rtp_policy_kind,
                            int rtcp_policy_kind) {
    init_once();
    srtp_policy_t policy;
    memset(&policy, 0, sizeof(policy));

    set_policy_from_kind(&policy.rtp, rtp_policy_kind);
    set_policy_from_kind(&policy.rtcp, rtcp_policy_kind);
    policy.ssrc.type = inbound ? ssrc_any_inbound : ssrc_any_outbound;

    // allocate keys
    policy.num_master_keys = num_keys;
    policy.keys = (srtp_master_key_t**)calloc(num_keys, sizeof(srtp_master_key_t *));

    for (int i = 0; i < num_keys; i++) {
	policy.keys[i] = (srtp_master_key_t *)malloc(sizeof(srtp_master_key_t));
        policy.keys[i]->key = (unsigned char *)malloc(keys[i].key_len);
        memcpy(policy.keys[i]->key, keys[i].key, keys[i].key_len);

        if (keys[i].mki && keys[i].mki_len > 0) {
            policy.keys[i]->mki_id = (unsigned char *)malloc(keys[i].mki_len);
            memcpy(policy.keys[i]->mki_id, keys[i].mki, keys[i].mki_len);
            policy.keys[i]->mki_size = keys[i].mki_len;
        }
    }

    srtp_t session;
    srtp_err_status_t status = srtp_create(&session, &policy);

    // cleanup temporary allocations in policy
    for (int i = 0; i < num_keys; i++) {
        free((void*)policy.keys[i]->key);
        if (policy.keys[i]->mki_id) {
            free((void*)policy.keys[i]->mki_id);
        }
	free(policy.keys[i]);
    }
    free(policy.keys);

    if (status != srtp_err_status_ok) {
        return NULL;
    }

    srtp_session_wrapper *wrapper = malloc(sizeof(srtp_session_wrapper));
    if (!wrapper) {
        srtp_dealloc(session);
        return NULL;
    }
    wrapper->session = session;
    return wrapper;
}

int c_srtp_unprotect_mki(void *ctx, unsigned char *pkt, int *pkt_len) {
    if (!ctx) return -1;
    srtp_session_wrapper *wrapper = (srtp_session_wrapper*)ctx;
    return srtp_unprotect_mki(wrapper->session, pkt, pkt_len, 1);
}

int c_srtp_unprotect_rtcp_mki(void *ctx, unsigned char *pkt, int *pkt_len) {
    if (!ctx) return -1;
    srtp_session_wrapper *wrapper = (srtp_session_wrapper*)ctx;
    return srtp_unprotect_rtcp_mki(wrapper->session, pkt, pkt_len, 1);
}

unsigned int c_srtp_get_version_number() {
	return srtp_get_version();
}
