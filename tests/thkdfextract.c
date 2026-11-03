/* Copyright (C) 2026 Hansaem Wi <hansaemw@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

/* HKDF and TLS13-KDF in extract-only mode produce exactly one digest of
 * output, like the default provider. Any other output length must be
 * refused, and the output buffer must be left untouched. */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "util.h"

#define FILL 0xA5

enum api { API_KDF, API_PKEY };

struct test_case {
    const char *name;
    const char *kdf;
    const char *digest;
    size_t digest_len;
    enum api api;
};

static const struct test_case test_cases[] = {
    { "HKDF SHA256 via EVP_KDF", "HKDF", "SHA256", 32, API_KDF },
    { "HKDF SHA256 via EVP_PKEY", "HKDF", "SHA256", 32, API_PKEY },
    { "HKDF SHA512 via EVP_KDF", "HKDF", "SHA512", 64, API_KDF },
    { "HKDF SHA512 via EVP_PKEY", "HKDF", "SHA512", 64, API_PKEY },
    { "TLS13-KDF SHA256", "TLS13-KDF", "SHA256", 32, API_KDF },
    { "TLS13-KDF SHA512", "TLS13-KDF", "SHA512", 64, API_KDF },
};

/* Sets *derived to whether the extract-only derivation succeeded. Returns
 * false only if the context could not be set up, which must not be mistaken
 * for a refused derivation. */
static bool extract_only(OSSL_LIB_CTX *libctx, const char *propq,
                         const struct test_case *tc, unsigned char *out,
                         size_t outlen, bool *derived)
{
    unsigned char ikm[64];
    OSSL_PARAM params[4];
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t len = outlen;
    bool ok = false;
    int p = 0;

    *derived = false;
    memset(ikm, 0x11, sizeof(ikm));
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   (char *)tc->digest, 0);
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,
                                                   (char *)"EXTRACT_ONLY", 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm,
                                                    tc->digest_len);
    params[p++] = OSSL_PARAM_construct_end();

    if (tc->api == API_KDF) {
        kdf = EVP_KDF_fetch(libctx, tc->kdf, propq);
        if (!kdf) {
            PRINTERROSSL("EVP_KDF_fetch(%s) failed\n", tc->kdf);
            goto done;
        }

        kctx = EVP_KDF_CTX_new(kdf);
        if (!kctx) {
            PRINTERROSSL("EVP_KDF_CTX_new failed\n");
            goto done;
        }

        *derived = EVP_KDF_derive(kctx, out, outlen, params) == 1;
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, tc->kdf, propq);
        if (!pctx) {
            PRINTERROSSL("EVP_PKEY_CTX_new_from_name(%s) failed\n", tc->kdf);
            goto done;
        }

        if (EVP_PKEY_derive_init(pctx) != 1) {
            PRINTERROSSL("EVP_PKEY_derive_init failed\n");
            goto done;
        }

        if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
            PRINTERROSSL("EVP_PKEY_CTX_set_params failed\n");
            goto done;
        }

        *derived = EVP_PKEY_derive(pctx, out, &len) == 1;
    }

    ok = true;

done:
    EVP_PKEY_CTX_free(pctx);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
}

static bool check_case(OSSL_LIB_CTX *def_libctx, OSSL_LIB_CTX *p11_libctx,
                       const struct test_case *tc)
{
    unsigned char expected[64];
    unsigned char out[128];
    size_t lens[4];
    size_t nlens = 0;
    bool derived = false;

    PRINTERR("  %s ...\n", tc->name);

    /* one digest of output works and matches the default provider */
    if (!extract_only(def_libctx, "provider=default", tc, expected,
                      tc->digest_len, &derived)) {
        return false;
    }
    if (!derived) {
        PRINTERROSSL("%s: default provider extract failed\n", tc->name);
        return false;
    }

    if (!extract_only(p11_libctx, "provider=pkcs11", tc, out, tc->digest_len,
                      &derived)) {
        return false;
    }
    if (!derived) {
        PRINTERROSSL("%s: pkcs11 extract failed\n", tc->name);
        return false;
    }

    if (memcmp(out, expected, tc->digest_len) != 0) {
        PRINTERR("%s: pkcs11 output differs from the default provider\n",
                 tc->name);
        return false;
    }

    /* anything shorter is refused, as the default provider does */
    lens[nlens++] = 1;
    lens[nlens++] = tc->digest_len / 2;
    lens[nlens++] = tc->digest_len - 1;
    /* a longer length is refused too. Through EVP_PKEY_derive the default
     * provider cuts it to the digest size instead, so only check EVP_KDF */
    if (tc->api == API_KDF) {
        lens[nlens++] = tc->digest_len + 1;
    }

    for (size_t i = 0; i < nlens; i++) {
        size_t len = lens[i];

        memset(out, FILL, sizeof(out));

        if (!extract_only(p11_libctx, "provider=pkcs11", tc, out, len,
                          &derived)) {
            return false;
        }
        if (derived) {
            PRINTERR("%s, output length %zu: derivation was not refused\n",
                     tc->name, len);
            return false;
        }
        ERR_clear_error();

        for (size_t j = 0; j < sizeof(out); j++) {
            if (out[j] != FILL) {
                PRINTERR("%s, output length %zu: output buffer modified at "
                         "offset %zu\n",
                         tc->name, len, j);
                return false;
            }
        }
    }

    return true;
}

int main(int argc, char *argv[])
{
    OSSL_LIB_CTX *def_libctx = NULL;
    OSSL_LIB_CTX *p11_libctx = NULL;
    OSSL_PROVIDER *def_prov = NULL;
    OSSL_PROVIDER *p11_def_prov = NULL;
    OSSL_PROVIDER *p11_prov = NULL;
    bool ok = true;

#if CAN_LOAD_PKCS11_PROVIDER
    def_libctx = util_load_default_libctx(&def_prov);
    p11_libctx = util_load_pkcs11_libctx(&p11_def_prov, &p11_prov, NULL);
#else
    PRINTERR("OSSL_PROVIDER_load_ex() not available in this version\n");
    exit(77);
#endif

    PRINTERR("Testing extract-only output length ...\n");
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        if (!check_case(def_libctx, p11_libctx, &test_cases[i])) {
            ok = false;
            break;
        }
    }

    OSSL_PROVIDER_unload(p11_prov);
    OSSL_PROVIDER_unload(p11_def_prov);
    OSSL_LIB_CTX_free(p11_libctx);
    OSSL_PROVIDER_unload(def_prov);
    OSSL_LIB_CTX_free(def_libctx);

    if (!ok) {
        exit(EXIT_FAILURE);
    }
    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
