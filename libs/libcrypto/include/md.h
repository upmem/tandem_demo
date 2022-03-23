/**
 * \file md.h
 *
 * \brief This file contains the generic message-digest wrapper.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef DPU_CRYPTO_MD_H
#define DPU_CRYPTO_MD_H

#include <stddef.h>

#include "config.h"
#include "sha256.h"

#define DPU_CRYPTO_ERR_MD_FEATURE_UNAVAILABLE -0x5080 /**< The selected feature is not available. */
#define DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA -0x5100 /**< Bad input parameters to function. */
#define DPU_CRYPTO_ERR_MD_ALLOC_FAILED -0x5180 /**< Failed to allocate memory. */
#define DPU_CRYPTO_ERR_MD_FILE_IO_ERROR -0x5200 /**< Opening or reading of file failed. */

/* DPU_CRYPTO_ERR_MD_HW_ACCEL_FAILED is deprecated and should not be used. */
#define DPU_CRYPTO_ERR_MD_HW_ACCEL_FAILED -0x5280 /**< MD hardware accelerator failed. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The generic message-digest context.
 */
typedef struct dpu_crypto_md_context_t {
    /** The digest-specific context. */
    dpu_crypto_sha256_context md_ctx;

    /** The HMAC part of the context. */
    unsigned char hmac_ctx[2 * SHA256_HASH_BLOCK_SIZE];
} dpu_crypto_md_context_t;

/**
 * \brief           This function initializes a message-digest context without
 *                  binding it to a particular message-digest algorithm.
 *
 *                  This function should always be called first. It prepares the
 *                  context for dpu_crypto_md_setup() for binding it to a
 *                  message-digest algorithm.
 */
void
dpu_crypto_md_init(dpu_crypto_md_context_t *ctx);

/**
 * \brief           This function clears the internal structure of \p ctx,
 *                  but does not free \p ctx itself.
 *
 *                  If you have called dpu_crypto_md_setup() on \p ctx, you must
 *                  call dpu_crypto_md_free() when you are no longer using the
 *                  context.
 *                  Calling this function if you have previously
 *                  called dpu_crypto_md_init() and nothing else is optional.
 *                  You must not call this function if you have not called
 *                  dpu_crypto_md_init().
 */
void
dpu_crypto_md_free(dpu_crypto_md_context_t *ctx);

/**
 * \brief           This function allocates sha256 internal structure.
 *
 *                  It should be called after dpu_crypto_md_init() or
 *                  dpu_crypto_md_free(). Makes it necessary to call
 *                  dpu_crypto_md_free() later.
 *
 * \param ctx       The context to set up.
 *
 * \return          \c 0 on success.
 * \return          #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int
dpu_crypto_md_setup(dpu_crypto_md_context_t *ctx);

/**
 * \brief           This function starts a message-digest computation.
 *
 *                  You must call this function after setting up the context
 *                  with dpu_crypto_md_setup(), and before passing data with
 *                  dpu_crypto_md_update().
 *
 * \param ctx       The generic message-digest context.
 *
 * \return          \c 0 on success.
 * \return          #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int
dpu_crypto_md_starts(dpu_crypto_md_context_t *ctx);

/**
 * \brief           This function feeds an input buffer into an ongoing
 *                  message-digest computation.
 *
 *                  You must call dpu_crypto_md_starts() before calling this
 *                  function. You may call this function multiple times.
 *                  Afterwards, call dpu_crypto_md_finish().
 *
 * \param ctx       The generic message-digest context.
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int
dpu_crypto_md_update(dpu_crypto_md_context_t *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief           This function finishes the digest operation,
 *                  and writes the result to the output buffer.
 *
 *                  Call this function after a call to dpu_crypto_md_starts(),
 *                  followed by any number of calls to dpu_crypto_md_update().
 *                  Afterwards, you may either clear the context with
 *                  dpu_crypto_md_free(), or call dpu_crypto_md_starts() to reuse
 *                  the context for another digest operation with the same
 *                  algorithm.
 *
 * \param ctx       The generic message-digest context.
 * \param output    The buffer for the generic message-digest checksum result.
 *
 * \return          \c 0 on success.
 * \return          #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int
dpu_crypto_md_finish(dpu_crypto_md_context_t *ctx, unsigned char *output);

/**
 * \brief           This function sets the HMAC key and prepares to
 *                  authenticate a new message.
 *
 *                  Call this function after dpu_crypto_md_setup(), to use
 *                  the MD context for an HMAC calculation, then call
 *                  dpu_crypto_md_hmac_update() to provide the input data, and
 *                  dpu_crypto_md_hmac_finish() to get the HMAC value.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param key       The HMAC secret key.
 * \param keylen    The length of the HMAC key in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int
dpu_crypto_md_hmac_starts(dpu_crypto_md_context_t *ctx, const unsigned char *key, size_t keylen);

/**
 * \brief           This function feeds an input buffer into an ongoing HMAC
 *                  computation.
 *
 *                  Call dpu_crypto_md_hmac_starts() or dpu_crypto_md_hmac_reset()
 *                  before calling this function.
 *                  You may call this function multiple times to pass the
 *                  input piecewise.
 *                  Afterwards, call dpu_crypto_md_hmac_finish().
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int
dpu_crypto_md_hmac_update(dpu_crypto_md_context_t *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief           This function finishes the HMAC operation, and writes
 *                  the result to the output buffer.
 *
 *                  Call this function after dpu_crypto_md_hmac_starts() and
 *                  dpu_crypto_md_hmac_update() to get the HMAC value. Afterwards
 *                  you may either call dpu_crypto_md_free() to clear the context,
 *                  or call dpu_crypto_md_hmac_reset() to reuse the context with
 *                  the same HMAC key.
 *
 * \param ctx       The message digest context containing an embedded HMAC
 *                  context.
 * \param output    The generic HMAC checksum result.
 *
 * \return          \c 0 on success.
 * \return          #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 */
int
dpu_crypto_md_hmac_finish(dpu_crypto_md_context_t *ctx, unsigned char *output);

/**
 * \brief          This function calculates the full generic HMAC
 *                 on the input buffer with the provided key.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The HMAC result is calculated as
 *                 output = generic HMAC(hmac key, input buffer).
 *
 * \param key      The HMAC secret key.
 * \param keylen   The length of the HMAC secret key in Bytes.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The generic HMAC result.
 *
 * \return         \c 0 on success.
 * \return         #DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                 failure.
 */
int
dpu_crypto_md_hmac(const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif /* DPU_CRYPTO_MD_H */
