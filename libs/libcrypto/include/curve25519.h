/* Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef DPU_CRYPTO_CURVE25519_H
#define DPU_CRYPTO_CURVE25519_H

#include <stddef.h>
#include <stdint.h>

/* Curve25519.
 *
 * Curve25519 is an elliptic curve. See https://tools.ietf.org/html/rfc7748.
 */

#define DPU_CRYPTO_ERR_ECC_BAD_INPUT_DATA -0x4F80 /**< Bad input parameters to function. */

/* X25519.
 *
 * X25519 is the Diffie-Hellman primitive built from curve25519. It is
 * sometimes referred to as “curve25519”, but “X25519” is a more precise
 * name.
 * See http://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748.
 */

#define X25519_PRIVATE_KEY_LEN 32
#define X25519_PUBLIC_VALUE_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief                   Generate a public/private key pair.
 *
 * \param out_public_value  Generated public key.
 * \param out_private_value Generated private key.
 * \param f_rng             The RNG function to use. This must not be \c NULL.
 *
 * \return                  \c 0 on success.
 * \return                  #DPU_CRYPTO_ERR_ECC_BAD_INPUT_DATA on failure.
 *
 */
int
dpu_crypto_X25519_keypair(uint8_t out_public_value[32], uint8_t out_private_key[32], int (*f_rng)(void *, size_t));

/**
 * \brief                    Diffie-Hellman function.
 *
 * \param private_key        Private key to use.
 * \param peers_public_value Public value to use.
 * \param out_shared_key     Generated shared key.
 *
 * \return                   \c 0 on success.
 * \return                   #DPU_CRYPTO_ERR_ECC_BAD_INPUT_DATA or 1 on failure.
 *
 * X25519() writes a shared key to @out_shared_key that is calculated from the
 * given private key and the peer's public value.
 *
 * Don't use the shared key directly, rather use a KDF and also include the two
 * public values as inputs.
 */
int
dpu_crypto_X25519(const uint8_t private_key[32], const uint8_t peers_public_value[32], uint8_t out_shared_key[32]);

/**
 * \brief                  Compute the matching public key.
 *
 * \param private_key      Private key to use.
 * \param out_public_value Computed public key.
 *
 * \return                 \c 0 on success.
 * \return                 #DPU_CRYPTO_ERR_ECC_BAD_INPUT_DATA on failure.
 *
 * X25519_public_from_private() calculates a Diffie-Hellman public value from
 * the given private key and writes it to @out_public_value.
 */
int
dpu_crypto_X25519_public_from_private(const uint8_t private_key[32], uint8_t out_public_value[32]);

/*
 * Low-level x25519 function, defined by either the generic or cortex-m0
 * implementation. Must not be called directly.
 */
void
dpu_crypto_x25519_scalar_mult(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* DPU_CRYPTO_CURVE25519_H */
