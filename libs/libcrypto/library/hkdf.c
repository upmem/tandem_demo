/*
 *  HKDF implementation -- RFC 5869
 *
 *  Copyright (C) 2016-2018, ARM Limited, All Rights Reserved
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

#include "config.h"

#if defined(DPU_CRYPTO_HKDF_C)

#include "hkdf.h"

#include <string.h>

#include "error.h"
#include "platform_util.h"

int
dpu_crypto_hkdf(const unsigned char *salt,
    size_t salt_len,
    const unsigned char *ikm,
    size_t ikm_len,
    const unsigned char *info,
    size_t info_len,
    unsigned char *okm,
    size_t okm_len)
{
    int ret = DPU_CRYPTO_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char prk[SHA256_DIGEST_SIZE];

    ret = dpu_crypto_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);

    if (ret == 0) {
        ret = dpu_crypto_hkdf_expand(prk, info, info_len, okm, okm_len);
    }

    dpu_crypto_platform_zeroize(prk, sizeof(prk));

    return (ret);
}

int
dpu_crypto_hkdf_extract(const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len, unsigned char *prk)
{
    unsigned char null_salt[SHA256_DIGEST_SIZE] = { '\0' };

    if (salt == NULL) {
        if (salt_len != 0) {
            return DPU_CRYPTO_ERR_HKDF_BAD_INPUT_DATA;
        }

        salt = null_salt;
        salt_len = (size_t)SHA256_DIGEST_SIZE;
    }

    return (dpu_crypto_md_hmac(salt, salt_len, ikm, ikm_len, prk));
}

int
dpu_crypto_hkdf_expand(const unsigned char *prk, const unsigned char *info, size_t info_len, unsigned char *okm, size_t okm_len)
{
    size_t hash_len = (size_t)SHA256_DIGEST_SIZE;
    size_t prk_len = (size_t)SHA256_DIGEST_SIZE;
    size_t where = 0;
    size_t n;
    size_t t_len = 0;
    size_t i;
    int ret = 0;
    dpu_crypto_md_context_t ctx;
    unsigned char t[SHA256_DIGEST_SIZE];

    if (okm == NULL) {
        return (DPU_CRYPTO_ERR_HKDF_BAD_INPUT_DATA);
    }

    if (info == NULL) {
        info = (const unsigned char *)"";
        info_len = 0;
    }

    n = okm_len / hash_len;

    if ((okm_len % hash_len) != 0) {
        n++;
    }

    /*
     * Per RFC 5869 Section 2.3, okm_len must not exceed
     * 255 times the hash length
     */
    if (n > 255) {
        return (DPU_CRYPTO_ERR_HKDF_BAD_INPUT_DATA);
    }

    dpu_crypto_md_init(&ctx);

    if ((ret = dpu_crypto_md_setup(&ctx)) != 0) {
        goto exit;
    }

    /*
     * Compute T = T(1) | T(2) | T(3) | ... | T(N)
     * Where T(N) is defined in RFC 5869 Section 2.3
     */
    for (i = 1; i <= n; i++) {
        size_t num_to_copy;
        unsigned char c = i & 0xff;

        ret = dpu_crypto_md_hmac_starts(&ctx, prk, prk_len);
        if (ret != 0) {
            goto exit;
        }

        ret = dpu_crypto_md_hmac_update(&ctx, t, t_len);
        if (ret != 0) {
            goto exit;
        }

        ret = dpu_crypto_md_hmac_update(&ctx, info, info_len);
        if (ret != 0) {
            goto exit;
        }

        /* The constant concatenated to the end of each T(n) is a single octet.
         * */
        ret = dpu_crypto_md_hmac_update(&ctx, &c, 1);
        if (ret != 0) {
            goto exit;
        }

        ret = dpu_crypto_md_hmac_finish(&ctx, t);
        if (ret != 0) {
            goto exit;
        }

        num_to_copy = i != n ? hash_len : okm_len - where;
        memcpy(okm + where, t, num_to_copy);
        where += hash_len;
        t_len = hash_len;
    }

exit:
    dpu_crypto_md_free(&ctx);
    dpu_crypto_platform_zeroize(t, sizeof(t));

    return (ret);
}

#endif /* DPU_CRYPTO_HKDF_C */
