/**
 * \file dpu_crypto_md.c
 *
 * \brief Generic message digest wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *
 */

#include "config.h"

#if defined(DPU_CRYPTO_MD_C)

#include "md.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "platform_util.h"
#include "sha256.h"

void
dpu_crypto_md_init(dpu_crypto_md_context_t *ctx)
{
    memset(ctx, 0, sizeof(dpu_crypto_md_context_t));
}

void
dpu_crypto_md_free(dpu_crypto_md_context_t *ctx)
{
    if (ctx == NULL)
        return;

    dpu_crypto_platform_zeroize(ctx, sizeof(dpu_crypto_md_context_t));
}

int
dpu_crypto_md_setup(dpu_crypto_md_context_t *ctx)
{
    if (ctx == NULL)
        return (DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA);

    dpu_crypto_sha256_init(&ctx->md_ctx);

    return (0);
}

int
dpu_crypto_md_starts(dpu_crypto_md_context_t *ctx)
{
    if (ctx == NULL)
        return (DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA);

    return (dpu_crypto_sha256_starts(&ctx->md_ctx, 0));
}

int
dpu_crypto_md_update(dpu_crypto_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
    if (ctx == NULL)
        return (DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA);

    return (dpu_crypto_sha256_update(&ctx->md_ctx, input, ilen));
}

int
dpu_crypto_md_finish(dpu_crypto_md_context_t *ctx, unsigned char *output)
{
    if (ctx == NULL)
        return (DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA);

    return (dpu_crypto_sha256_finish(&ctx->md_ctx, output));
}

int
dpu_crypto_md_hmac_starts(dpu_crypto_md_context_t *ctx, const unsigned char *key, size_t keylen)
{
    int ret = DPU_CRYPTO_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char sum[SHA256_DIGEST_SIZE];
    unsigned char *ipad, *opad;
    size_t i;

    if (ctx == NULL)
        return (DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA);

    if (keylen > (size_t)SHA256_HASH_BLOCK_SIZE) {
        if ((ret = dpu_crypto_md_starts(ctx)) != 0)
            goto cleanup;
        if ((ret = dpu_crypto_md_update(ctx, key, keylen)) != 0)
            goto cleanup;
        if ((ret = dpu_crypto_md_finish(ctx, sum)) != 0)
            goto cleanup;

        keylen = (size_t)SHA256_DIGEST_SIZE;
        key = sum;
    }

    ipad = (unsigned char *)ctx->hmac_ctx;
    opad = (unsigned char *)ctx->hmac_ctx + SHA256_HASH_BLOCK_SIZE;

    memset(ipad, 0x36, SHA256_HASH_BLOCK_SIZE);
    memset(opad, 0x5C, SHA256_HASH_BLOCK_SIZE);

    for (i = 0; i < keylen; i++) {
        ipad[i] = (unsigned char)(ipad[i] ^ key[i]);
        opad[i] = (unsigned char)(opad[i] ^ key[i]);
    }

    if ((ret = dpu_crypto_md_starts(ctx)) != 0)
        goto cleanup;
    if ((ret = dpu_crypto_md_update(ctx, ipad, SHA256_HASH_BLOCK_SIZE)) != 0)
        goto cleanup;

cleanup:
    dpu_crypto_platform_zeroize(sum, sizeof(sum));

    return (ret);
}

int
dpu_crypto_md_hmac_update(dpu_crypto_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
    if (ctx == NULL)
        return (DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA);

    return (dpu_crypto_md_update(ctx, input, ilen));
}

int
dpu_crypto_md_hmac_finish(dpu_crypto_md_context_t *ctx, unsigned char *output)
{
    int ret = DPU_CRYPTO_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tmp[SHA256_DIGEST_SIZE];
    unsigned char *opad;

    if (ctx == NULL)
        return (DPU_CRYPTO_ERR_MD_BAD_INPUT_DATA);

    opad = (unsigned char *)ctx->hmac_ctx + SHA256_HASH_BLOCK_SIZE;

    if ((ret = dpu_crypto_md_finish(ctx, tmp)) != 0)
        return (ret);
    if ((ret = dpu_crypto_md_starts(ctx)) != 0)
        return (ret);
    if ((ret = dpu_crypto_md_update(ctx, opad, (size_t)SHA256_HASH_BLOCK_SIZE)) != 0)
        return (ret);
    if ((ret = dpu_crypto_md_update(ctx, tmp, (size_t)SHA256_DIGEST_SIZE)) != 0)
        return (ret);
    return (dpu_crypto_md_finish(ctx, output));
}

int
dpu_crypto_md_hmac(const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char *output)
{
    dpu_crypto_md_context_t ctx;
    int ret = DPU_CRYPTO_ERR_ERROR_CORRUPTION_DETECTED;

    dpu_crypto_md_init(&ctx);

    if ((ret = dpu_crypto_md_setup(&ctx)) != 0)
        goto cleanup;

    if ((ret = dpu_crypto_md_hmac_starts(&ctx, key, keylen)) != 0)
        goto cleanup;
    if ((ret = dpu_crypto_md_hmac_update(&ctx, input, ilen)) != 0)
        goto cleanup;
    if ((ret = dpu_crypto_md_hmac_finish(&ctx, output)) != 0)
        goto cleanup;

cleanup:
    dpu_crypto_md_free(&ctx);

    return (ret);
}

#endif /* DPU_CRYPTO_MD_C */
