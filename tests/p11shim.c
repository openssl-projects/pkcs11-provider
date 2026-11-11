/* Copyright (C) 2026 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

/* Forwards to P11SHIM_MODULE and simulates device loss:
 *  P11SHIM_FAIL: name of the call (GetSessionInfo, SignInit, SignFinal)
 *                that restarts the real module and fails once
 *  P11SHIM_DOWN: fail C_Initialize while set */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"

static CK_FUNCTION_LIST *real;
static CK_FUNCTION_LIST shim;
static CK_C_INITIALIZE_ARGS init_args;
static bool have_init_args;

static bool device_lost(const char *name)
{
    const char *fail = getenv("P11SHIM_FAIL");

    if (!fail || strcmp(fail, name) != 0) {
        return false;
    }
    unsetenv("P11SHIM_FAIL");

    (void)real->C_Finalize(NULL);
    if (!getenv("P11SHIM_DOWN")) {
        (void)real->C_Initialize(have_init_args ? &init_args : NULL);
    }
    return true;
}

static CK_RV shim_Initialize(void *args)
{
    if (getenv("P11SHIM_DOWN")) {
        return CKR_DEVICE_ERROR;
    }
    if (args) {
        init_args = *(CK_C_INITIALIZE_ARGS *)args;
        have_init_args = true;
    }
    return real->C_Initialize(args);
}

static CK_RV shim_GetSessionInfo(CK_SESSION_HANDLE session,
                                 CK_SESSION_INFO *info)
{
    if (device_lost("GetSessionInfo")) {
        return CKR_DEVICE_ERROR;
    }
    return real->C_GetSessionInfo(session, info);
}

static CK_RV shim_SignInit(CK_SESSION_HANDLE session, CK_MECHANISM *mech,
                           CK_OBJECT_HANDLE key)
{
    if (device_lost("SignInit")) {
        return CKR_DEVICE_ERROR;
    }
    return real->C_SignInit(session, mech, key);
}

static CK_RV shim_SignFinal(CK_SESSION_HANDLE session, CK_BYTE *sig,
                            CK_ULONG *siglen)
{
    if (device_lost("SignFinal")) {
        return CKR_DEVICE_ERROR;
    }
    return real->C_SignFinal(session, sig, siglen);
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST **list)
{
    CK_C_GetFunctionList get_list;
    const char *path;
    void *handle;
    CK_RV ret;

    if (!real) {
        path = getenv("P11SHIM_MODULE");
        if (!path) {
            fprintf(stderr, "p11shim: P11SHIM_MODULE is not set\n");
            return CKR_GENERAL_ERROR;
        }
        handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "p11shim: dlopen failed: %s\n", dlerror());
            return CKR_GENERAL_ERROR;
        }
        get_list = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
        if (!get_list) {
            fprintf(stderr, "p11shim: no C_GetFunctionList in %s\n", path);
            return CKR_GENERAL_ERROR;
        }
        ret = get_list(&real);
        if (ret != CKR_OK) {
            return ret;
        }

        shim = *real;
        shim.version.major = 2;
        shim.version.minor = 40;
        shim.C_Initialize = shim_Initialize;
        shim.C_GetFunctionList = C_GetFunctionList;
        shim.C_GetSessionInfo = shim_GetSessionInfo;
        shim.C_SignInit = shim_SignInit;
        shim.C_SignFinal = shim_SignFinal;
    }

    *list = &shim;
    return CKR_OK;
}
