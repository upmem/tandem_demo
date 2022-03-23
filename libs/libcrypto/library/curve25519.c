/* Copyright 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/* This code is mostly taken from the ref10 version of Ed25519 in SUPERCOP
 * 20141124 (http://bench.cr.yp.to/supercop.html). That code is released as
 * public domain but this file has the ISC license just to keep licencing
 * simple.
 *
 * The field functions are shared by Ed25519 and X25519 where possible. */
#include "config.h"

#if defined(DPU_CRYPTO_CURVE25519_C)

#include "curve25519.h"

#include <stddef.h>

#include "platform_util.h"

/* Parameter validation macros based on platform_util.h */
#define ECC_VALIDATE_RET(cond) DPU_CRYPTO_INTERNAL_VALIDATE_RET(cond, DPU_CRYPTO_ERR_ECC_BAD_INPUT_DATA)
#define ECC_VALIDATE(cond) DPU_CRYPTO_INTERNAL_VALIDATE(cond)

int
dpu_crypto_X25519_keypair(uint8_t out_public_value[32], uint8_t out_private_key[32], int (*f_rng)(void *, size_t))
{
    ECC_VALIDATE_RET(out_public_value != NULL);
    ECC_VALIDATE_RET(out_private_key != NULL);
    ECC_VALIDATE_RET(f_rng != NULL);

    f_rng(out_private_key, 32);

    /* All X25519 implementations should decode scalars correctly (see
     * https://tools.ietf.org/html/rfc7748#section-5). However, if an
     * implementation doesn't then it might interoperate with random keys a
     * fraction of the time because they'll, randomly, happen to be correctly
     * formed.
     *
     * Thus we do the opposite of the masking here to make sure that our private
     * keys are never correctly masked and so, hopefully, any incorrect
     * implementations are deterministically broken.
     *
     * This does not affect security because, although we're throwing away
     * entropy, a valid implementation of scalarmult should throw away the exact
     * same bits anyway. */
    out_private_key[0] |= 7;
    out_private_key[31] &= 63;
    out_private_key[31] |= 128;

    return dpu_crypto_X25519_public_from_private(out_private_key, out_public_value);
}

int
dpu_crypto_X25519(const uint8_t private_key[32], const uint8_t peer_public_value[32], uint8_t out_shared_key[32])
{
    ECC_VALIDATE_RET(private_key != NULL);
    ECC_VALIDATE_RET(peer_public_value != NULL);
    ECC_VALIDATE_RET(out_shared_key != NULL);

    static const uint8_t kZeros[32] = { 0 };
    dpu_crypto_x25519_scalar_mult(private_key, peer_public_value, out_shared_key);
    /* The all-zero output results when the input is a point of small order. */
    return (safe_memcmp(kZeros, out_shared_key, 32) == 0);
}

int
dpu_crypto_X25519_public_from_private(const uint8_t private_key[32], uint8_t out_public_value[32])
{
    ECC_VALIDATE_RET(private_key != NULL);
    ECC_VALIDATE_RET(out_public_value != NULL);

    static const uint8_t kMongomeryBasePoint[32] = { 9 };
    dpu_crypto_x25519_scalar_mult(private_key, kMongomeryBasePoint, out_public_value);

    return (0);
}

#endif /* DPU_CRYPTO_CURVE25519_C */
