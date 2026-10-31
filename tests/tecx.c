/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include "util.h"

static void ecdh_test(EVP_PKEY *a, EVP_PKEY *b)
{
    unsigned char secret[16], secret2[16];
    size_t secretlen = 16, secret2len = 16;
    EVP_PKEY_CTX *derivectx, *dup_ctx, *dup_ctx2;

    derivectx = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL);
    if (!derivectx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive_init(derivectx) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_init failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive_set_peer(derivectx, b) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    /* Trigger the context duplication to verify it works */
    dup_ctx = EVP_PKEY_CTX_dup(derivectx);
    if (!dup_ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_dup failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    /* Do derivation with original context */
    if (EVP_PKEY_derive(derivectx, secret, &secretlen) != 1) {
        fprintf(stderr, "EVP_PKEY_derive failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    /* Do derivation with duplicate context */
    if (EVP_PKEY_derive(dup_ctx, secret2, &secret2len) != 1) {
        fprintf(stderr, "EVP_PKEY_derive failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    /* Duplicate also already completed derivation */
    dup_ctx2 = EVP_PKEY_CTX_dup(derivectx);
    if (!dup_ctx2) {
        fprintf(stderr, "EVP_PKEY_CTX_dup of finalized context failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(derivectx);
    EVP_PKEY_CTX_free(dup_ctx);
    EVP_PKEY_CTX_free(dup_ctx2);

    if (secretlen != secret2len || memcmp(secret, secret2, secretlen) != 0) {
        fprintf(stderr, "Secret from duplicated context does not match!\n");
        exit(EXIT_FAILURE);
    }
}

/* A buffer larger than the shared secret must still get just the secret */
static void ecdh_outlen_test(EVP_PKEY *a, EVP_PKEY *b)
{
    unsigned char secret[128], bigsecret[256];
    size_t secretlen = 0, bigsecretlen = sizeof(bigsecret);
    EVP_PKEY_CTX *derivectx = NULL;
    bool ok = false;

    derivectx = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL);
    if (!derivectx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed!\n");
        goto done;
    }

    if (EVP_PKEY_derive_init(derivectx) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_init failed!\n");
        goto done;
    }

    if (EVP_PKEY_derive_set_peer(derivectx, b) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer failed!\n");
        goto done;
    }

    if (EVP_PKEY_derive(derivectx, NULL, &secretlen) != 1) {
        fprintf(stderr, "EVP_PKEY_derive size query failed!\n");
        goto done;
    }

    if (secretlen > sizeof(secret)) {
        fprintf(stderr, "Secret size %zu exceeds the %zu-byte test buffer!\n",
                secretlen, sizeof(secret));
        goto done;
    }

    if (EVP_PKEY_derive(derivectx, secret, &secretlen) != 1) {
        fprintf(stderr, "EVP_PKEY_derive with exact buffer failed!\n");
        goto done;
    }

    /* derive again on the same context, into a larger buffer */
    if (EVP_PKEY_derive(derivectx, bigsecret, &bigsecretlen) != 1) {
        fprintf(stderr, "EVP_PKEY_derive with larger buffer failed!\n");
        goto done;
    }

    if (bigsecretlen != secretlen) {
        fprintf(stderr,
                "Secret derived into a %zu-byte buffer has %zu bytes, "
                "expected %zu!\n",
                sizeof(bigsecret), bigsecretlen, secretlen);
        goto done;
    }

    if (memcmp(secret, bigsecret, secretlen) != 0) {
        fprintf(stderr, "Secret derived into a larger buffer differs!\n");
        goto done;
    }

    ok = true;

done:
    if (!ok) {
        ossl_err_print();
    }
    EVP_PKEY_CTX_free(derivectx);
    if (!ok) {
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    EVP_PKEY *a, *b;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [privkey-uri] [pubkey-uri]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    a = load_key(argv[1]);
    b = load_key(argv[2]);

    ecdh_test(a, b);
    ecdh_outlen_test(a, b);

    EVP_PKEY_free(a);
    EVP_PKEY_free(b);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
