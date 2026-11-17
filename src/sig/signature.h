/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SIGNATURE_H
#define _SIGNATURE_H

CK_MECHANISM_TYPE p11prov_digest_to_rsapss_mech(CK_MECHANISM_TYPE digest);
CK_RSA_PKCS_MGF_TYPE p11prov_digest_to_mgf(CK_MECHANISM_TYPE digest);
CK_MECHANISM_TYPE p11prov_mgf_to_digest(CK_RSA_PKCS_MGF_TYPE mgf);

CK_RV p11prov_register_signatures(P11PROV_CTX *ctx, bool mechs[TBID_SIZE],
                                  bool fips_property);

#endif /* _SIGNATURE_H */
