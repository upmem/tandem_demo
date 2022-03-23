/**
 * \file platform_util.h
 *
 * \brief Common and shared functions used by multiple modules in the DPU crypto
 *        library.
 */
/*
 *  Copyright (C) 2018, Arm Limited, All Rights Reserved
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
#ifndef DPU_CRYPTO_PLATFORM_UTIL_H
#define DPU_CRYPTO_PLATFORM_UTIL_H

/*
 * Bit operation macros.
 */
#define BIT(nr) (1U << (nr))

#define DPU_CRYPTO_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072 /**< The requested feature is not supported by the platform */

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>

#define DPU_CRYPTO_PARAM_FAILED(cond) assert(cond)

/* Internal macro meant to be called only from within the library. */
#define DPU_CRYPTO_INTERNAL_VALIDATE_RET(cond, ret)                                                                              \
    do {                                                                                                                         \
        if (!(cond)) {                                                                                                           \
            DPU_CRYPTO_PARAM_FAILED(cond);                                                                                       \
            return (ret);                                                                                                        \
        }                                                                                                                        \
    } while (0)

/* Internal macro meant to be called only from within the library. */
#define DPU_CRYPTO_INTERNAL_VALIDATE(cond)                                                                                       \
    do {                                                                                                                         \
        if (!(cond)) {                                                                                                           \
            DPU_CRYPTO_PARAM_FAILED(cond);                                                                                       \
            return;                                                                                                              \
        }                                                                                                                        \
    } while (0)

/**
 * \brief       Securely zeroize a buffer
 *
 *              The function is meant to wipe the data contained in a buffer so
 *              that it can no longer be recovered even if the program memory
 *              is later compromised. Call this function on sensitive data
 *              stored on the stack before returning from a function, and on
 *              sensitive data stored on the heap before freeing the heap
 *              object.
 *
 * \param buf   Buffer to be zeroized
 * \param len   Length of the buffer in bytes
 *
 */
void
dpu_crypto_platform_zeroize(void *buf, size_t len);

/**
 * \brief      Constant-time memory comparison
 *
 *             Standard memcpu must not be used to compre critical data,
 *             because the reuiqred CPU time depends on the number of equal bytes.
 *             cf. man memcmp
 *
 * \param buf  First buffer to compare
 * \param len  Second buffer to compare
 * \param size Size to compare
 *
 * \return     \0 if buffers are equals
 *
 */
int
safe_memcmp(const void *s1, const void *s2, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* DPU_CRYPTO_PLATFORM_UTIL_H */
