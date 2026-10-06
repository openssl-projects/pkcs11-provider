/* Copyright (C) 2026 Jakub Jelen <jjelen@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"

int main(void)
{
    static const char *valid_uris[] = {
        "pkcs11:",
        "pkcs11:object=my-cert;type=cert",
        "pkcs11:model=Model%20A;token=Token%20B",
        "pkcs11:id=%01%02%03%04;object=key",
        "pkcs11:token=The%20Token;id=%01%02%03%04;pin-value=1234",
        "pkcs11:slot-id=1;library-version=2.20",
        "pkcs11:token=foo/bar",
        NULL,
    };

    static const char *invalid_uris[] = {
        "pkcs11:token=foo\nbar",
        "pkcs11:token=foo\rbar",
        "pkcs11:token=foo\tbar",
        "pkcs11:token=foo\x01"
        "bar",
        "pkcs11:token=foo bar",
        "pkcs11:token=foo\x80"
        "bar",
        "pkcs11:unknown\nattr=foo",
        "pkcs11:token=foo%2",
        "pkcs11:token=foo%2G",
        "pkcs11:slot-id= 1",
        "pkcs11:slot-id=-1",
        "pkcs11:library-version=1.2.3",
        /* Corner cases: characters not in RFC 7512 p11-char */
        "pkcs11:token=<foo>",
        "pkcs11:token=\"foo\"",
        "pkcs11:token=foo#bar",
        "pkcs11:token=[foo]",
        "pkcs11:token=foo\\bar",
        "pkcs11:token=foo^bar",
        "pkcs11:token=foo`bar",
        "pkcs11:token={foo}",
        "pkcs11:token=foo|bar",
        "pkcs11:unknown<attr>=foo",
        /* Duplicate attributes */
        "pkcs11:token=foo;token=bar",
        "pkcs11:model=A;model=B",
        "pkcs11:pin-value=1234;pin-value=5678",
        "pkcs11:pin-value=1234;pin-source=file:pin",
        "pkcs11:type=cert;object-type=cert",
        "pkcs11:id=%01;id=%02",
        NULL,
    };

    P11PROV_URI *uri;
    int failed = 0;

    for (int i = 0; valid_uris[i] != NULL; i++) {
        uri = p11prov_parse_uri(NULL, valid_uris[i]);
        if (uri == NULL) {
            fprintf(stderr, "FAIL: Valid URI rejected: %s\n", valid_uris[i]);
            failed++;
        } else {
            p11prov_uri_free(uri);
        }
    }

    for (int i = 0; invalid_uris[i] != NULL; i++) {
        uri = p11prov_parse_uri(NULL, invalid_uris[i]);
        if (uri != NULL) {
            fprintf(stderr, "FAIL: Invalid URI accepted: %s\n",
                    invalid_uris[i]);
            p11prov_uri_free(uri);
            failed++;
        }
    }

    if (failed > 0) {
        fprintf(stderr, "%d tests failed\n", failed);
        return 1;
    }

    printf("All URI parser tests passed successfully.\n");
    return 0;
}
