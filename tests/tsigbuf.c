/* Copyright (C) 2026 Hansaem Wi <hansaemw@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "util.h"

#define SHA256_LEN 32

/* A signature operation given an output buffer that is too small makes the
 * token return CKR_BUFFER_TOO_SMALL, which leaves the operation active on
 * the PKCS#11 session. The provider must not hand such a session back to
 * the pool, or all following signatures made on it fail. */

static int pkey_sign(EVP_PKEY *key, bool pss, size_t bufsize, size_t *siglen)
{
    unsigned char tbs[SHA256_LEN] = { 0x01, 0x02, 0x03 };
    unsigned char *sig;
    EVP_PKEY_CTX *ctx;
    int ret = 0;

    sig = OPENSSL_zalloc(bufsize);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!sig || !ctx) {
        PRINTERROSSL("Failed to allocate sign context or buffer\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_sign_init(ctx) != 1
        || EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) != 1
        || (pss
            && (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, SHA256_LEN) != 1))) {
        PRINTERROSSL("Failed to init EVP_PKEY_sign\n");
        exit(EXIT_FAILURE);
    }

    *siglen = bufsize;
    ret = EVP_PKEY_sign(ctx, sig, siglen, tbs, sizeof(tbs));

    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(sig);
    return ret;
}

static int digest_sign(EVP_PKEY *key, size_t bufsize, size_t *siglen)
{
    const unsigned char data[] = "Sign Me!";
    unsigned char *sig;
    EVP_MD_CTX *mdctx;
    int ret = 0;

    sig = OPENSSL_zalloc(bufsize);
    mdctx = EVP_MD_CTX_new();
    if (!sig || !mdctx) {
        PRINTERROSSL("Failed to allocate digest context or buffer\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestSignInit_ex(mdctx, NULL, "SHA256", NULL, NULL, key, NULL) != 1
        || EVP_DigestSignUpdate(mdctx, data, sizeof(data)) != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign\n");
        exit(EXIT_FAILURE);
    }

    *siglen = bufsize;
    ret = EVP_DigestSignFinal(mdctx, sig, siglen);

    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(sig);
    return ret;
}

/* Sign with a buffer one byte too small, then check that signing works with
 * a correctly sized buffer on a fresh context, as the same pooled session
 * may be reused. */
static void check_small_then_good(EVP_PKEY *key, const char *name, bool pss,
                                  bool digest)
{
    size_t size = EVP_PKEY_get_size(key);
    size_t siglen;
    int ret;

    ret = digest ? digest_sign(key, size - 1, &siglen)
                 : pkey_sign(key, pss, size - 1, &siglen);
    if (ret == 1) {
        PRINTERR("%s: sign into a too small buffer unexpectedly succeeded\n",
                 name);
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    ret = digest ? digest_sign(key, size, &siglen)
                 : pkey_sign(key, pss, size, &siglen);
    if (ret != 1 || siglen != size) {
        PRINTERROSSL("%s: sign after a too small buffer failed (ret=%d,"
                     " siglen=%zu)\n",
                     name, ret, siglen);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    const char *uri = getenv("PRIURI");
    EVP_PKEY *key;
    size_t siglen;

    /* optional first argument is the private key URI to test */
    if (argc > 1) {
        uri = argv[1];
    }
    if (uri == NULL) {
        PRINTERR("No PRIURI\n");
        exit(EXIT_FAILURE);
    }
    key = load_key(uri);

    check_small_then_good(key, "RSA PKCS#1 v1.5 sign", false, false);
    check_small_then_good(key, "RSA-PSS sign", true, false);
    check_small_then_good(key, "RSA DigestSign", false, true);

    /* all kinds of signatures must still work afterwards */
    if (pkey_sign(key, false, EVP_PKEY_get_size(key), &siglen) != 1
        || pkey_sign(key, true, EVP_PKEY_get_size(key), &siglen) != 1
        || digest_sign(key, EVP_PKEY_get_size(key), &siglen) != 1) {
        PRINTERROSSL("Final signatures failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_free(key);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
