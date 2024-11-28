/**
 * \file aeszkn.h
 *
 * \brief AES-ZKN for hardware AES acceleration on some RISC-V processors
 *
 * \warning These functions are only for internal use by other library
 *          functions; you must not call them directly.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_AESZKN_H
#define MBEDTLS_AESZKN_H

#include "mbedtls/build_info.h"
#include "mbedtls/aes.h"

#if (defined(MBEDTLS_AESZKN_C) && defined(MBEDTLS_HAVE_ASM) && \
    defined(__GNUC__) &&  \
    (defined(__riscv_zkne) &&  defined(__riscv_zknd)))

#define MBEDTLS_AESZKN_HAVE_CODE

/**
 * \brief          Internal function to detect the crypto extension in CPUs.
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
int mbedtls_aeszkn_has_support(void);
#else
#define mbedtls_aeszkn_has_support() 1
#endif

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
/**
 * \brief           Internal round key inversion. This function computes
 *                  decryption round keys from the encryption round keys.
 *
 * \note            This function is only for internal use by other library
 *                  functions; you must not call it directly.
 *
 * \param invkey    Round keys for the equivalent inverse cipher
 * \param fwdkey    Original round keys (for encryption)
 * \param bits      Key size in bits (must be 128, 192 or 256)
 */
void mbedtls_aeszkn_inverse_key(unsigned int *invkey,
                             const unsigned char *fwdkey,
                             size_t bits);
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

/**
 * \brief           Internal key expansion for encryption
 *
 * \note            This function is only for internal use by other library
 *                  functions; you must not call it directly.
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 * \param rc         Round constant
 * \param bits      Key size in bits (must be 128, 192 or 256)
 *
 * \return          0 if successful, or MBEDTLS_ERR_AES_INVALID_KEY_LENGTH
 */
int mbedtls_aeszkn_setkey_enc(unsigned int *rk,
                              const unsigned char *key,
                              const unsigned int *rc,
                              size_t bits);

/**
 * \brief          Internal AES-ZKN AES-ECB block encryption and decryption
 *
 * \note           This function is only for internal use by other library
 *                 functions; you must not call it directly.
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
int mbedtls_aeszkn_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16]);
#endif /* MBEDTLS_AESZKN_C && MBEDTLS_HAVE_ASM &&
               __GUN__ && __riscv_zkne && __riscv_zknd */
#endif /* MBEDTLS_AESZKN_H */
