/* Copyright (C) 2026 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "util.h"

static const unsigned char data[] = "Sign Me!";

static bool sign_op(EVP_PKEY *key, unsigned char *sig, size_t *siglen)
{
    EVP_MD_CTX *ctx;
    int ret;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        PRINTERR("Failed to allocate EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }
    ret = EVP_DigestSignInit_ex(ctx, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret == 1) {
        ret = EVP_DigestSign(ctx, sig, siglen, data, sizeof(data));
    }
    EVP_MD_CTX_free(ctx);

    return ret == 1;
}

static bool verify_op(EVP_PKEY *key, unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *ctx;
    int ret;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        PRINTERR("Failed to allocate EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }
    ret = EVP_DigestVerifyInit_ex(ctx, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret == 1) {
        ret = EVP_DigestVerify(ctx, sig, siglen, data, sizeof(data));
    }
    EVP_MD_CTX_free(ctx);

    return ret == 1;
}

static void expect_sign(EVP_PKEY *key, EVP_PKEY *pub, bool expected,
                        const char *stage)
{
    size_t siglen = EVP_PKEY_get_size(key);
    unsigned char sig[siglen];
    bool ok;

    ok = sign_op(key, sig, &siglen);
    if (ok != expected) {
        PRINTERROSSL("Sign %s unexpectedly (%s)\n", ok ? "succeeded" : "failed",
                     stage);
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();
    if (!ok) {
        return;
    }

    if (!verify_op(pub, sig, siglen)) {
        PRINTERROSSL("Failed to verify signature (%s)\n", stage);
        exit(EXIT_FAILURE);
    }
}

static EVP_PKEY *export_pubkey(EVP_PKEY *key)
{
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pub = NULL;

    if (EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &params) != 1) {
        PRINTERROSSL("Failed to export public key\n");
        exit(EXIT_FAILURE);
    }
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default");
    if (!ctx || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &pub, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        PRINTERROSSL("Failed to import public key\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);

    return pub;
}

int main(int argc, char *argv[])
{
    EVP_PKEY *other;
    EVP_PKEY *other_pub;
    EVP_PKEY *key;
    EVP_PKEY *pub;

    other = util_gen_key("RSA 2048", "Device-Error-Other");
    key = util_gen_key("RSA 2048", "Device-Error-Test");
    pub = export_pubkey(key);
    other_pub = export_pubkey(other);

    expect_sign(key, pub, true, "initial");

    /* the operation that hits the error fails, the next one recovers */
    setenv("P11SHIM_FAIL", "1", 1);
    expect_sign(key, pub, false, "device lost");
    expect_sign(key, pub, true, "device recovered");
    expect_sign(other, other_pub, true, "other key");

    /* re-init is retried until the device is back */
    setenv("P11SHIM_FAIL", "1", 1);
    setenv("P11SHIM_DOWN", "1", 1);
    expect_sign(key, pub, false, "device lost again");
    expect_sign(key, pub, false, "device still down");
    unsetenv("P11SHIM_DOWN");
    expect_sign(key, pub, true, "device back");

    EVP_PKEY_free(other_pub);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(key);
    EVP_PKEY_free(other);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
