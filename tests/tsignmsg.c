/* Copyright (C) 2026
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include "util.h"

int main(int argc, char *argv[])
{
#if !OPENSSL_VERSION_PREREQ(3, 4)
    fprintf(stderr, "The interface to be tested is not implemented in the "
                    "openssl version present\n");
    exit(EXIT_FAILURE);
#else
    int ret = EXIT_FAILURE;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    unsigned char *data = NULL;
    size_t datalen;
    unsigned char *sig = NULL;
    size_t siglen;

    if (argc != 5) {
        fprintf(stderr, "Usage: %s [keyuri] [algo] [data-file] [sig-file]\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    pkey = load_key(argv[1]);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to load key via uri \"%s\"\n", argv[1]);
        goto done;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        PRINTERROSSL("EVP_PKEY_CTX_new() failed\n");
        goto done;
    }
    alg = EVP_SIGNATURE_fetch(NULL, argv[2], "provider=pkcs11");
    if (alg == NULL) {
        PRINTERROSSL("Failed to fetch algorithm \"%s\"\n", argv[2]);
        goto done;
    }

    if (EVP_PKEY_sign_message_init(pkey_ctx, alg, NULL) < 0) {
        PRINTERROSSL("EVP_PKEY_sign_message_init() failed\n");
        goto done;
    }

    data = util_read_file(argv[3], &datalen);
    if (data == NULL) {
        fprintf(stderr, "Failed to read data-file \"%s\"\n", argv[3]);
        goto done;
    }

    if (EVP_PKEY_sign(pkey_ctx, NULL, &siglen, data, datalen) < 0) {
        PRINTERROSSL("EVP_PKEY_sign() for sigsize failed\n");
        goto done;
    }

    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        fprintf(stderr, "OPENSSL_malloc() failed\n");
        goto done;
    }

    if (EVP_PKEY_sign(pkey_ctx, sig, &siglen, data, datalen) < 0) {
        fprintf(stderr, "EVP_PKEY_sign() failed\n");
        goto done;
    }

    if (util_write_file(argv[4], siglen, sig) != siglen) {
        fprintf(stderr, "Failed to write sig-file \"%s\"\n", argv[4]);
        goto done;
    }

    ret = EXIT_SUCCESS;

done:
    OPENSSL_free(sig);
    if (data != NULL) {
        free(data);
    }
    EVP_SIGNATURE_free(alg);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);

    exit(ret);
#endif
}
