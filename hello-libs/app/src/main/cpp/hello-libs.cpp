#include <cstring>
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <cinttypes>
#include <android/log.h>
#include <gmath.h>
#include <gperf.h>

#include "hello-libs.h"

//#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "OSA Test Application:\t", __VA_ARGS__))

unsigned char plaintext[] = "plaintext to be decrypted as part of the testing app for the PoC";

/* This is a trivial JNI example where we use a native method
 * to return a new VM String. See the corresponding Java source
 * file located at:
 *
 *   app/src/main/java/com/example/hellolibs/MainActivity.java
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_hellolibs_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz)
{
    // Just for simplicity, we do this right away; correct way would do it in
    // another thread...
    auto ticks = GetTicks();

    for (auto exp = 0; exp < 32; ++exp) {
        volatile unsigned val = gpower(exp);
        (void) val;  // to silence compiler warning
    }
    ticks = GetTicks() - ticks;

    LOGI("calculation time: %" PRIu64, ticks);

    return env->NewStringUTF("Cryptographic operations completed successfully");
}

#if 1
extern "C" JNIEXPORT jint JNICALL
Java_com_example_hellolibs_MainActivity_doCryptOps(JNIEnv *env, jobject thiz) {
    unsigned char *dkey = NULL;
    crypto_ctx_st *crypto_ctx = NULL;

    crypto_ctx = (crypto_ctx_st *) malloc(sizeof(struct crypto_ctx_st_));
    memset(crypto_ctx, '\0', sizeof(crypto_ctx_st));
    dkey = (unsigned char *) malloc(16);
    if ((dkey == NULL) || (crypto_ctx == NULL)) {
        LOGE("Allocation error\n");
        return -1;
    }

    aes_128_cbc_init(dkey, 16, crypto_ctx);
    LOGD("[plaintext = %s]\n[crypto_ctx->pt = %s]\n", plaintext, crypto_ctx->pt);
    LOGD("[crypto_ctx->pt_len = %d]\n\n", crypto_ctx->pt_len);

    crypto_ctx->ct = my_aes_128_cbc_encrypt(crypto_ctx);
    LOGD("[crypto_ctx->ct = %s]\n", crypto_ctx->ct);
    LOGD("[crypto_ctx->ct_len = %d]\n\n", crypto_ctx->ct_len);

    crypto_ctx->pt = my_aes_128_cbc_decrypt(crypto_ctx);
    LOGD("[crypto_ctx->pt = %s]\n", crypto_ctx->pt);
    LOGD("[crypto_ctx->pt_len = %d]\n\n", crypto_ctx->pt_len);

    if (strncmp((char *) crypto_ctx->pt, (char *) plaintext, crypto_ctx->pt_len) == 0) {
        LOGI("Decryption successful\n");
    } else {
        LOGE("Decryption failed\n");
        return -1;
    }

    if (crypto_ctx && dkey) {
        EVP_CIPHER_CTX_cleanup(crypto_ctx->e_ctx);
        EVP_CIPHER_CTX_cleanup(crypto_ctx->d_ctx);

        free(crypto_ctx->ct);
        free(crypto_ctx->pt);

        crypto_ctx->pt = NULL;
        crypto_ctx->ct = NULL;

        free(crypto_ctx);
        free(dkey);

        crypto_ctx = NULL;
        dkey = NULL;
    }

    return 0;
}
#endif

#if 1
int aes_128_cbc_init(unsigned char *dkey, int ldkey, crypto_ctx_st *cctx)
{
    const EVP_CIPHER *cipher;
    int i, rounds = 8;

    cipher = EVP_aes_128_cbc();
    cctx->key_len = EVP_CIPHER_key_length(cipher);
    cctx->iv_len = EVP_CIPHER_iv_length(cipher);

    cctx->e_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cctx->e_ctx);

    cctx->d_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cctx->d_ctx);

    if (RAND_bytes(cctx->salt, sizeof(cctx->salt)) == 0 ||
        RAND_bytes(dkey, ldkey) == 0)
    {
        return -1;
    }

    i = EVP_BytesToKey(cipher, EVP_sha1(), cctx->salt, dkey, ldkey, rounds, cctx->key, cctx->iv);
    if (i !=16 )
    {
        LOGE("Key size is %d bytes instead of 16\n", i);
        return -1;
    }

    cctx->pt = plaintext;
    cctx->pt_len = sizeof(plaintext) + 1;

    return 0;
}

unsigned char *my_aes_128_cbc_encrypt(crypto_ctx_st *cctx)
{
    int lf = 0;
    unsigned char *ct = NULL;

    cctx->ct_len = cctx->pt_len + EVP_MAX_BLOCK_LENGTH;
    ct = (unsigned char *) malloc(cctx->ct_len);

    if (EVP_EncryptInit_ex(cctx->e_ctx, EVP_aes_128_cbc(), NULL, cctx->key, cctx->iv) != 1)
    {
        LOGE("EVP_EncryptInit_ex error.\n");
        return NULL;
    }

    if (EVP_EncryptUpdate(cctx->e_ctx, ct, &cctx->ct_len, cctx->pt, cctx->pt_len) != 1)
    {
        LOGE("EVP_EncryptUpdate error.\n");
        return NULL;
    }

    if (EVP_EncryptFinal_ex(cctx->e_ctx, ct + cctx->ct_len, &lf) != 1)
    {
        LOGE("EVP_EncryptFinal_ex error.\n");
        return NULL;
    }

    cctx->ct_len += lf;
    return ct;
}

unsigned char *my_aes_128_cbc_decrypt(crypto_ctx_st *cctx)
{
    int lf = 0;
    unsigned char *pt = (unsigned char *) malloc(cctx->pt_len);

    if (EVP_DecryptInit_ex(cctx->d_ctx, EVP_aes_128_cbc(), NULL, cctx->key, cctx->iv) != 1)
    {
        LOGE("EVP_DecryptInit_ex error.\n");
        return NULL;
    }

    if (EVP_DecryptUpdate(cctx->d_ctx, pt, &cctx->pt_len, cctx->ct, cctx->ct_len) != 1)
    {
        LOGE("EVP_EncryptUpdate error.\n");
        return NULL;
    }

    if (EVP_DecryptFinal_ex(cctx->d_ctx, pt + cctx->pt_len, &lf) != 1)
    {
        LOGE("EVP_EncryptFinal_ex error.\n");
        return NULL;
    }

    cctx->pt_len += lf;
    return pt;
}
#endif