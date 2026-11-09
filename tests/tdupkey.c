/* Copyright (C) 2026 Jakub Jelen <jjelen@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "util.h"

static void fail(const char *what)
{
    fprintf(stderr, "%s failed\n", what);
    ossl_err_print();
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    const unsigned char data[] = "data to be signed";
    unsigned char sig[8192];
    size_t siglen = sizeof(sig);
    EVP_PKEY *orig, *dup, *pub, *params;
    EVP_MD_CTX *ctx;
    char group1[64], group2[64];

    if (argc != 3) {
        fprintf(stderr, "Usage: tdupkey [priv-keyuri] [pub-keyuri]\n");
        exit(EXIT_FAILURE);
    }

    orig = load_key(argv[1]);
    pub = load_key(argv[2]);

    dup = EVP_PKEY_dup(orig);
    if (!dup) {
        fail("EVP_PKEY_dup");
    }
    if (EVP_PKEY_eq(orig, dup) != 1) {
        fail("EVP_PKEY_eq");
    }

    /* A parameter copy must work without copying the key */
    if (EVP_PKEY_is_a(orig, "EC")) {
        params = EVP_PKEY_new();
        if (!params || EVP_PKEY_copy_parameters(params, orig) != 1) {
            fail("EVP_PKEY_copy_parameters");
        }
        if (!EVP_PKEY_get_group_name(orig, group1, sizeof(group1), NULL)
            || !EVP_PKEY_get_group_name(params, group2, sizeof(group2), NULL)
            || strcmp(group1, group2) != 0) {
            fail("compare the group of the parameter copy");
        }
        EVP_PKEY_free(params);
    }

    /* The copy must keep working on its own */
    EVP_PKEY_free(orig);

    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestSignInit(ctx, NULL, NULL, NULL, dup) != 1
        || EVP_DigestSign(ctx, sig, &siglen, data, sizeof(data)) != 1) {
        fail("sign with the duplicated key");
    }
    EVP_MD_CTX_free(ctx);

    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) != 1
        || EVP_DigestVerify(ctx, sig, siglen, data, sizeof(data)) != 1) {
        fail("verify the signature of the duplicated key");
    }
    EVP_MD_CTX_free(ctx);

    EVP_PKEY_free(dup);
    EVP_PKEY_free(pub);
    fprintf(stderr, "ALL A-OK\n");
    exit(EXIT_SUCCESS);
}
