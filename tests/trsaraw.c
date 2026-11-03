/* Copyright (C) 2026 Hansaem Wi <hansaemw@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "util.h"

#define CANARY 0xA5

static int raw_sign(EVP_PKEY *key, const unsigned char *tbs, size_t tbslen,
                    unsigned char *sig, size_t *siglen)
{
    EVP_PKEY_CTX *ctx;
    int ret;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) {
        PRINTERROSSL("Failed to create a sign context\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_sign_init(ctx) != 1) {
        PRINTERROSSL("Failed to init raw RSA sign\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) != 1) {
        PRINTERROSSL("Failed to set no padding\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);

    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* Sign with a buffer twice as large as the modulus: the signature is as
 * large as the modulus, the length returned is the modulus size and the
 * rest of the buffer is left alone. */
static void check_large_buffer(EVP_PKEY *key, const char *name,
                               const unsigned char *tbs, size_t modsize,
                               unsigned char *sig)
{
    size_t siglen = 2 * modsize;

    memset(sig, CANARY, 2 * modsize);
    if (raw_sign(key, tbs, modsize, sig, &siglen) != 1) {
        PRINTERROSSL("%s: raw sign into a buffer larger than the modulus"
                     " failed\n",
                     name);
        exit(EXIT_FAILURE);
    }
    if (siglen != modsize) {
        PRINTERR("%s: unexpected signature length %zu, expected %zu\n", name,
                 siglen, modsize);
        exit(EXIT_FAILURE);
    }
    for (size_t i = modsize; i < 2 * modsize; i++) {
        if (sig[i] != CANARY) {
            PRINTERR("%s: data written past the signature length\n", name);
            exit(EXIT_FAILURE);
        }
    }
}

static EVP_PKEY *default_prikey(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default");
    if (ctx == NULL) {
        PRINTERROSSL("Failed to create a default provider keygen context\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        PRINTERROSSL("Failed to init keygen\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1) {
        PRINTERROSSL("Failed to set keygen bits\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_keygen(ctx, &key) != 1) {
        PRINTERROSSL("Failed to generate default provider key\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Recover the data from a raw signature using the default provider, which
 * must give back the data that was signed on the token. Fetching the
 * operation from the default provider exports the token public key to it. */
static void check_recover(EVP_PKEY *pubkey, const unsigned char *tbs,
                          size_t modsize, const unsigned char *sig,
                          size_t siglen)
{
    unsigned char *rec;
    size_t reclen = 2 * modsize;
    EVP_PKEY_CTX *ctx;

    rec = OPENSSL_zalloc(reclen);
    if (rec == NULL) {
        PRINTERR("Failed to allocate the recover buffer\n");
        exit(EXIT_FAILURE);
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, "provider=default");
    if (ctx == NULL) {
        PRINTERROSSL("Failed to create a default provider context\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_verify_recover_init(ctx) != 1) {
        PRINTERROSSL("Failed to init verify recover\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) != 1) {
        PRINTERROSSL("Failed to set no padding for verify recover\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_verify_recover(ctx, rec, &reclen, sig, siglen) != 1) {
        PRINTERROSSL("Failed to recover data with the default provider\n");
        exit(EXIT_FAILURE);
    }
    if (reclen != modsize) {
        PRINTERR("Recovered %zu bytes, expected %zu\n", reclen, modsize);
        exit(EXIT_FAILURE);
    }
    if (memcmp(rec, tbs, modsize) != 0) {
        PRINTERR("Default provider recovered different data than signed\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(rec);
}

int main(int argc, char *argv[])
{
    const char *priuri = getenv("PRIURI");
    const char *puburi = getenv("PUBURI");
    EVP_PKEY *prikey, *pubkey, *defpri;
    unsigned char *tbs, *sig;
    size_t modsize, siglen;

    /* optional arguments are the private and public key URIs to test */
    if (argc == 3) {
        priuri = argv[1];
        puburi = argv[2];
    }
    if (priuri == NULL || puburi == NULL) {
        PRINTERR("No PRIURI or PUBURI\n");
        exit(EXIT_FAILURE);
    }
    prikey = load_key(priuri);
    pubkey = load_key(puburi);
    modsize = EVP_PKEY_get_size(prikey);

    /* one extra byte to also try data longer than the modulus */
    tbs = OPENSSL_zalloc(modsize + 1);
    sig = OPENSSL_zalloc(2 * modsize);
    if (tbs == NULL || sig == NULL) {
        PRINTERR("Failed to allocate buffers\n");
        exit(EXIT_FAILURE);
    }
    /* Raw RSA needs data smaller than the modulus, so keep the first byte
     * 0. The rest is a fixed pattern to make the result deterministic. */
    for (size_t i = 1; i < modsize; i++) {
        tbs[i] = (unsigned char)(i * 31 + 7);
    }

    /* Buffer of exactly the modulus size */
    siglen = modsize;
    if (raw_sign(prikey, tbs, modsize, sig, &siglen) != 1) {
        PRINTERROSSL("Raw sign with a modulus size buffer failed\n");
        exit(EXIT_FAILURE);
    }
    if (siglen != modsize) {
        PRINTERR("Unexpected signature length %zu, expected %zu\n", siglen,
                 modsize);
        exit(EXIT_FAILURE);
    }

    /* Buffer twice the modulus size, on the token and on the default
     * provider. */
    defpri = default_prikey();
    check_large_buffer(defpri, "default provider", tbs, modsize, sig);
    check_large_buffer(prikey, "pkcs11 provider", tbs, modsize, sig);

    /* The signature made on the token is the one the default provider
     * recovers the data from. */
    check_recover(pubkey, tbs, modsize, sig, modsize);

    /* Data shorter than the modulus is still refused */
    siglen = 2 * modsize;
    if (raw_sign(prikey, tbs, modsize - 1, sig, &siglen) == 1) {
        PRINTERR("Raw sign of data shorter than the modulus succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* Data longer than the modulus is refused too */
    siglen = 2 * modsize;
    if (raw_sign(prikey, tbs, modsize + 1, sig, &siglen) == 1) {
        PRINTERR("Raw sign of data longer than the modulus succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    OPENSSL_free(tbs);
    OPENSSL_free(sig);
    EVP_PKEY_free(prikey);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(defpri);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
