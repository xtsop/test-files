//
// Created by Christos Tsopokis on 05/07/2017.
//

#ifndef HELLO_LIBS_HELLO_LIBS_H
#define HELLO_LIBS_HELLO_LIBS_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>

#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "OSA Test Application:\t", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "OSA Test Application:\t", __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "OSA Test Application:\t", __VA_ARGS__))

typedef struct crypto_ctx_st_
{
    unsigned char *pt;
    int pt_len;

    unsigned char *ct;
    int ct_len;

    unsigned char salt[8];
    unsigned char iv[16];
    unsigned int iv_len;
    unsigned char key[16];
    unsigned int key_len;

    EVP_CIPHER_CTX *e_ctx;
    EVP_CIPHER_CTX *d_ctx;
} crypto_ctx_st;

int aes_128_cbc_init(unsigned char *dkey, int ldkey, crypto_ctx_st *cctx);
unsigned char *my_aes_128_cbc_encrypt(crypto_ctx_st *cctx);
unsigned char *my_aes_128_cbc_decrypt(crypto_ctx_st *cctx);


#endif //HELLO_LIBS_HELLO_LIBS_H
