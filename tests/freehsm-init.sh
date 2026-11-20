#!/bin/bash -e
# Copyright (C) 2026 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

title SECTION "Searching for FreeHSM module"

find_freehsm() {
    for _lib in "$@" ; do
        if test -f "$_lib" ; then
            echo "Using FreeHSM path $_lib"
            export P11LIB="${_lib}"
            return
        fi
    done
    echo "skipped: Unable to find FreeHSM PKCS#11 library"
    exit 0
}

find_freehsm \
    "${FREEHSM}/libfreehsm.so" \
    /usr/local/lib/libfreehsm.so \
    /opt/freehsm/lib/libfreehsm.so \
    /usr/lib64/pkcs11/libfreehsm.so \
    /usr/lib/pkcs11/libfreehsm.so \
    /usr/lib/x86_64-linux-gnu/pkcs11/libfreehsm.so

title LINE "Creating FreeHSM token directory"

# FreeHSM refuses a token directory that others can read. The audit log is
# written there too unless FHSM_AUDIT_LOG says otherwise.
chmod 700 "$TOKDIR"
export FHSM_TOKENS_DIR="$TOKDIR"
# Do not pick up the system configuration of an installed FreeHSM
: > "$TMPPDIR/freehsm.conf"
export FHSM_CONF="$TMPPDIR/freehsm.conf"
# A build from source is not signed, so the module skips its integrity check
# and serves every mechanism from the OpenSSL default provider. "permissive"
# lets it run the mechanisms NIST has not approved (RSA-PKCS, SHA-1, ...), as
# the tests expect of a software token.
export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export FHSM_MODE=permissive

export TOKENLABEL="${TOKENLABEL:-FreeHSM Token}"
export TOKENLABELURI="${TOKENLABELURI:-FreeHSM%20Token}"

# init token
ptool --init-token --label "${TOKENLABEL}" --so-pin "${PINVALUE}" 2>&1
# set user pin
ptool --so-pin "${PINVALUE}" --login --login-type so \
      --init-pin --pin "${PINVALUE}" 2>&1

export TOKENCONFIGVARS="export FHSM_TOKENS_DIR=${TOKDIR} FHSM_CONF=${FHSM_CONF} FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_MODE=permissive"
export TESTPORT="36000"

# A key copied with C_CopyObject (which the key cache uses) refuses the
# mechanisms its CKA_ALLOWED_MECHANISMS lists, so do not cache keys
export TOKENOPTIONS="${TOKENOPTIONS}\npkcs11-module-cache-keys = false"

export SUPPORT_ALLOWED_MECHANISMS=1

# FreeHSM signs pure Ed25519/Ed448 only and refuses CK_EDDSA_PARAMS with a
# context string or phFlag (Ed25519ctx/Ed25519ph)
export SUPPORT_EDDSA_PARAMS=0

# FreeHSM's ECDH accepts only CKD_NULL, not the ANSI X9.63 KDFs that CMS uses
export SUPPORT_ECDH_X963_KDF=0
