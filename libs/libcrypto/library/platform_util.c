/*
 * Common and shared functions used by multiple modules in the DPU crypto
 * library.
 *
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
#include "platform_util.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * This implementation should never be optimized out by the compiler
 *
 * This implementation for dpu_crypto_platform_zeroize() was inspired from Colin
 * Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * It uses a volatile function pointer to the standard memset(). Because the
 * pointer is volatile the compiler expects it to change at
 * any time and will not optimize out the call that could potentially perform
 * other operations on the input buffer instead of just setting it to 0.
 * Nevertheless, as pointed out by davidtgoldblatt on Hacker News
 * (refer to http://www.daemonology.net/blog/2014-09-05-erratum.html for
 * details), optimizations of the following form are still possible:
 *
 * if( memset_func != memset )
 *     memset_func( buf, 0, len );
 *
 */
static void *(*const volatile memset_func)(void *, int, size_t) = memset;

void
dpu_crypto_platform_zeroize(void *buf, size_t len)
{
    DPU_CRYPTO_INTERNAL_VALIDATE(len == 0 || buf != NULL);

    if (len > 0)
        memset_func(buf, 0, len);
}

int
safe_memcmp(const void *s1, const void *s2, size_t size)
{
    const uint8_t *us1 = s1;
    const uint8_t *us2 = s2;
    int result = 0;

    if (size == 0)
        return 0;

    /*
     * Code snippet without data-dependent branch due to Nate Lawson
     * (nate@root.org) of Root Labs.
     */
    while (size--)
        result |= *us1++ ^ *us2++;

    return result != 0;
}