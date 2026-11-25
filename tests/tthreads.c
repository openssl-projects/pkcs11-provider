/* Copyright (C) 2026 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "util.h"

#define NUM_THREADS 8
#define NUM_KEYS 2
#define NUM_OPS 50

static const unsigned char data[] = "Sign Me!";

static pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;
static bool started;

struct thread_data {
    pthread_t thread;
    int num;
    EVP_PKEY *key;
    EVP_PKEY *pub;
    bool ok;
};

static void wait_for_start(void)
{
    pthread_mutex_lock(&start_lock);
    while (!started) {
        pthread_cond_wait(&start_cond, &start_lock);
    }
    pthread_mutex_unlock(&start_lock);
}

static void set_started(bool value)
{
    pthread_mutex_lock(&start_lock);
    started = value;
    pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&start_lock);
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
    ctx = EVP_PKEY_CTX_new_from_name(NULL, EVP_PKEY_get0_type_name(key),
                                     "provider=default");
    if (!ctx || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &pub, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        PRINTERROSSL("Failed to import public key\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);

    return pub;
}

static bool sign_verify_op(struct thread_data *td)
{
    size_t siglen = EVP_PKEY_get_size(td->key);
    unsigned char sig[siglen];
    EVP_MD_CTX *ctx;
    bool ok = false;
    int ret;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        PRINTERR("Failed to allocate EVP_MD_CTX (thread %d)\n", td->num);
        return false;
    }
    ret = EVP_DigestSignInit_ex(ctx, NULL, "SHA256", NULL, NULL, td->key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign (thread %d)\n", td->num);
        goto done;
    }
    ret = EVP_DigestSign(ctx, sig, &siglen, data, sizeof(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSign (thread %d)\n", td->num);
        goto done;
    }
    EVP_MD_CTX_free(ctx);

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        PRINTERR("Failed to allocate EVP_MD_CTX (thread %d)\n", td->num);
        return false;
    }
    ret =
        EVP_DigestVerifyInit_ex(ctx, NULL, "SHA256", NULL, NULL, td->pub, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestVerify (thread %d)\n", td->num);
        goto done;
    }
    ret = EVP_DigestVerify(ctx, sig, siglen, data, sizeof(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to verify signature (thread %d)\n", td->num);
        goto done;
    }
    ok = true;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* all threads hit the uninitialized provider at the same time */
static void *first_use_thread(void *arg)
{
    struct thread_data *td = arg;

    wait_for_start();

    td->key = util_gen_key("P-256", "Threads-First-Use");
    td->pub = export_pubkey(td->key);
    td->ok = sign_verify_op(td);

    EVP_PKEY_free(td->pub);
    EVP_PKEY_free(td->key);
    return NULL;
}

/* threads share the keys */
static void *shared_keys_thread(void *arg)
{
    struct thread_data *td = arg;

    wait_for_start();

    for (int i = 0; i < NUM_OPS; i++) {
        if (!sign_verify_op(td)) {
            return NULL;
        }
    }
    td->ok = true;
    return NULL;
}

static void run_threads(struct thread_data *td, void *(*fn)(void *))
{
    set_started(false);
    for (int i = 0; i < NUM_THREADS; i++) {
        td[i].num = i;
        td[i].ok = false;
        if (pthread_create(&td[i].thread, NULL, fn, &td[i]) != 0) {
            PRINTERR("Failed to create thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }
    set_started(true);
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(td[i].thread, NULL) != 0) {
            PRINTERR("Failed to join thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!td[i].ok) {
            PRINTERR("Thread %d failed\n", i);
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    const char *types[NUM_KEYS] = { "RSA 2048", "P-256" };
    struct thread_data td[NUM_THREADS] = { 0 };
    EVP_PKEY *keys[NUM_KEYS];
    EVP_PKEY *pubs[NUM_KEYS];

    run_threads(td, first_use_thread);

    for (int i = 0; i < NUM_KEYS; i++) {
        keys[i] = util_gen_key(types[i], "Threads-Shared");
        pubs[i] = export_pubkey(keys[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        td[i].key = keys[i % NUM_KEYS];
        td[i].pub = pubs[i % NUM_KEYS];
    }
    run_threads(td, shared_keys_thread);

    for (int i = 0; i < NUM_KEYS; i++) {
        EVP_PKEY_free(pubs[i]);
        EVP_PKEY_free(keys[i]);
    }

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
