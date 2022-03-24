/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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

#ifndef DPU_CRYPTO_CONFIG_H
#define DPU_CRYPTO_CONFIG_H

/**
 * \def DPU_CRYPTO_SHA256_C
 *
 * Enable the SHA-224 and SHA-256 cryptographic hash algorithms.
 *
 * Module:  library/sha256.c
 *
 * This module adds support for SHA-224 and SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define DPU_CRYPTO_SHA256_C

/**
 * \def DPU_CRYPTO_SHA256_SMALLER
 *
 * Enable an implementation of SHA-256 that has lower IRAM footprint but also
 * lower performance.
 *
 * Uncomment to enable the smaller implementation of SHA256.
 */
//#define DPU_CRYPTO_SHA256_SMALLER

/**
 * \def DPU_CRYPTO_AES_C
 *
 * Enable the AES block cipher.
 *
 * Module:  library/aes.c
 */
#define DPU_CRYPTO_AES_C

/**
 * \def DPU_CRYPTO_CIPHER_MODE_CBC
 *
 * Enable Cipher Block Chaining mode (CBC) for symmetric ciphers.
 */
//#define DPU_CRYPTO_CIPHER_MODE_CBC

/**
 * \def DPU_CRYPTO_CIPHER_MODE_CFB
 *
 * Enable Cipher Feedback mode (CFB) for symmetric ciphers.
 */
//#define DPU_CRYPTO_CIPHER_MODE_CFB

/**
 * \def DPU_CRYPTO_CIPHER_MODE_CTR
 *
 * Enable Counter Block Cipher mode (CTR) for symmetric ciphers.
 */
//#define DPU_CRYPTO_CIPHER_MODE_CTR

/**
 * \def DPU_CRYPTO_CIPHER_MODE_OFB
 *
 * Enable Output Feedback mode (OFB) for symmetric ciphers.
 */
//#define DPU_CRYPTO_CIPHER_MODE_OFB

/**
 * \def DPU_CRYPTO_CIPHER_MODE_XTS
 *
 * Enable Xor-encrypt-xor with ciphertext stealing mode (XTS) for AES.
 */
//#define DPU_CRYPTO_CIPHER_MODE_XTS

/**
 * \def DPU_CRYPTO_AES_FEWER_TABLES
 *
 * Use less WRAM for AES tables.
 *
 * Uncommenting this macro omits 75% of the AES tables from
 * WRAM by computing their values on the fly during operations
 * (the tables are entry-wise rotations of one another).
 *
 * Tradeoff: Uncommenting this reduces the WRAM footprint
 * by ~6kb but at the cost of more arithmetic operations during
 * runtime. Specifically, one has to compare 4 accesses within
 * different tables to 4 accesses with additional arithmetic
 * operations within the same table. The performance gain/loss
 * depends on the system and memory details.
 */
//#define DPU_CRYPTO_AES_FEWER_TABLES

/**
 * \def DPU_CRYPTO_CURVE25519_C
 *
 * Enable the curve25519 elliptic curve.
 *
 * Module:  library/curve25519.c
 */
#define DPU_CRYPTO_CURVE25519_C

/**
 * \def DPU_CRYPTO_MD_C
 *
 * Enable the generic message digest layer.
 *
 * Module:  library/md.c
 *
 * Requires: DPU_CRYPTO_SHA256_C
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define DPU_CRYPTO_MD_C

/**
 * \def DPU_CRYPTO_HKDF_C
 *
 * Enable the HKDF algorithm (RFC 5869).
 *
 * Module:  library/hkdf.c
 *
 * Requires: DPU_CRYPTO_MD_C
 *
 * This module adds support for the Hashed Message Authentication Code
 * (HMAC)-based key derivation function (HKDF).
 */
#define DPU_CRYPTO_HKDF_C

#endif /* DPU_CRYPTO_CONFIG_H */
