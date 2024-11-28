/*
 *  AES-ZKN support functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * https://github.com/riscv/riscv-crypto/releases/download/v1.0.1-scalar/riscv-crypto-spec-scalar-v1.0.1.pdf
 */

#include "common.h"
#include <string.h>

#if defined(__linux__)
#include <sys/auxv.h>
#endif

#if defined(MBEDTLS_AESZKN_C)

#include "aeszkn.h"

#if defined(MBEDTLS_AESZKN_HAVE_CODE)
#if defined(MBEDTLS_ARCH_IS_RISCV32)

#define STR(S)        #S
#define XSTR(S)      STR(S)

#define CSR_MISA        0x301
#define RISCV_ISA_K    0x00000400

#define csr_read(csr)                \
({                                            \
    unsigned long __v;                \
    asm ("csrr %0, " XSTR(csr)     \
        : "=r" (__v) :                    \
        : "memory");                     \
        __v;	                           \
})

#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
/*
 * AES-ZKN support detection routine
 */
int mbedtls_aeszkn_has_support(void)
{
    unsigned long support = 0;

#if defined(__linux__)
    support  = getauxval(AT_HWCAP);
#else
    support = csr_read(CSR_MISA);
#endif

    return (support & RISCV_ISA_K) ? 1 : 0;
}
#endif /* MBEDTLS_AES_USE_HARDWARE_ONLY */

/*
 * Key expansion for encryption, 128-bit case
 */
static void aes_128_enc_ks(unsigned int *rk,
                             const unsigned char *ck,
                             const unsigned int *rc)
{
    (void) rk;
    (void) ck;
    (void) rc;

    asm ("mv t1, a2    \n\t" // round constant
         "lw a2, 0(a1)    \n\t" // load cipher key
         "lw a3, 4(a1)    \n\t"
         "lw a4, 8(a1)    \n\t"
         "lw a5, 12(a1)  \n\t"
         "mv a6, a0        \n\t"
         "addi t0, a0, 160    \n\t" // expand for 10 round
         ".aes_128_enc_ks_l0:\n\t"
         "sw a2, 0(a6)        \n\t" // save round key in rk
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)   \n\t"
         "beq t0, a6, aes_128_enc_ks_finish    \n\t"
         "addi a6, a6, 16    \n\t" // next round key
         "lbu t2, 0(t1)    \n\t" // load round constant
         "addi t1, t1, 4    \n\t"
         "xor a2, a2, t2    \n\t"
         "srli t4, a5, 8      \n\t"
         "slli t3 , a5, (32-8)    \n\t"
         "or t3 , t3 , t4    \n\t"
         "aes32esi a2, a2, t3, 0    \n\t"
         "aes32esi a2, a2, t3, 1    \n\t"
         "aes32esi a2, a2, t3, 2    \n\t"
         "aes32esi a2, a2, t3, 3    \n\t"
         "xor a3, a3, a2    \n\t"
         "xor a4, a4, a3    \n\t"
         "xor a5, a5, a4    \n\t"
         "j .aes_128_enc_ks_l0    \n\t"
         "aes_128_enc_ks_finish:    \n\t"
         "li 	a0, 0    \n\t");
}

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
/*
 * Key expansion for encryption, 192-bit case
 */
static void aes_192_enc_ks(unsigned int *rk,
                             const unsigned char *ck,
                             const unsigned int *rc)
{
    (void) rk;
    (void) ck;
    (void) rc;

    asm ("mv t1, a2    \n\t" // round constant
         "lw a2, 0(a1)    \n\t"
         "lw a3, 4(a1)    \n\t"
         "lw a4, 8(a1)    \n\t"
         "lw a5, 12(a1)    \n\t"
         "lw a7, 16(a1)    \n\t"
         "lw t5, 20(a1)    \n\t"
         "mv a6, a0    \n\t"
         "addi t0, a0, 48*4    \n\t" // expand for 12 round
         ".aes_192_enc_ks_l0:    \n\t"
         "sw a2, 0(a6)    \n\t"
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)    \n\t"
         "beq t0, a6, aes_192_enc_ks_finish    \n\t"
         "sw a7, 16(a6)    \n\t"
         "sw t5, 20(a6)    \n\t"
         "addi a6, a6, 24    \n\t" // next round key
         "lbu     t4, 0(t1)    \n\t" // load round constant
         "addi    t1, t1, 4    \n\t"
         "xor     a2, a2, t4    \n\t"
         "srli    t4, t5, 8    \n\t"
         "slli    t3 , t5, (32-8)    \n\t"
         "or      t3 , t3 , t4    \n\t"
         "aes32esi a2, a2, t3, 0    \n\t"
         "aes32esi a2, a2, t3, 1    \n\t"
         "aes32esi a2, a2, t3, 2    \n\t"
         "aes32esi a2, a2, t3, 3    \n\t"
         "xor     a3, a3, a2    \n\t"
         "xor     a4, a4, a3    \n\t"
         "xor     a5, a5, a4    \n\t"
         "xor     a7, a7, a5    \n\t"
         "xor     t5, t5, a7    \n\t"
         "j .aes_192_enc_ks_l0    \n\t"
         "aes_192_enc_ks_finish:    \n\t"
         "li 	a0, 0    \n\t");
}

/*
 * Key expansion for encryption, 256-bit case
 */
static void aes_256_enc_ks (unsigned int *rk,
                             const unsigned char *ck,
                             const unsigned int *rc)
{
    (void) rk;
    (void) ck;
    (void) rc;

    asm ("mv t1, a2    \n\t"
         "lw a2, 0(a1)    \n\t"
         "lw a3, 4(a1)    \n\t"
         "lw a4, 8(a1)    \n\t"
         "lw a5, 12(a1)    \n\t"
         "lw a7, 16(a1)    \n\t"
         "lw t5, 20(a1)    \n\t"
         "lw t6, 24(a1)    \n\t"
         "lw t2, 28(a1)    \n\t"
         "mv a6, a0    \n\t"
         "addi t0, a0, 56*4    \n\t" // expand for 14 round
         "sw a2, 0(a6)    \n\t"
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)    \n\t"
         ".aes_256_enc_ks_l0:    \n\t"
         "sw a7, 16(a6)    \n\t"
         "sw t5, 20(a6)    \n\t"
         "sw t6, 24(a6)    \n\t"
         "sw t2, 28(a6)    \n\t"
         "addi a6, a6, 32    \n\t"
         "lbu t4, 0(t1)    \n\t"
         "addi t1, t1, 4    \n\t"
         "xor a2, a2, t4    \n\t"
         "srli t4, t2, 8    \n\t"
         "slli t3 , t2, (32-8)    \n\t"
         "or t3 , t3 , t4    \n\t"
         "aes32esi a2, a2, t3, 0    \n\t"
         "aes32esi a2, a2, t3, 1    \n\t"
         "aes32esi a2, a2, t3, 2    \n\t"
         "aes32esi a2, a2, t3, 3    \n\t"
         "xor a3, a3, a2    \n\t"
         "xor a4, a4, a3    \n\t"
         "xor a5, a5, a4    \n\t"
         "sw a2, 0(a6)    \n\t"
         "sw a3, 4(a6)    \n\t"
         "sw a4, 8(a6)    \n\t"
         "sw a5, 12(a6)    \n\t"
         "beq t0, a6, aes_256_enc_ks_finish    \n\t"
         "aes32esi a7, a7, a5, 0    \n\t"
         "aes32esi a7, a7, a5, 1    \n\t"
         "aes32esi a7, a7, a5, 2    \n\t"
         "aes32esi a7, a7, a5, 3    \n\t"
         "xor t5, t5, a7    \n\t"
         "xor t6, t6, t5    \n\t"
         "xor t2, t2, t6    \n\t"
         "j .aes_256_enc_ks_l0    \n\t"
         "aes_256_enc_ks_finish:    \n\t"
         "li 	a0, 0\n\t");
}
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
/*
 * Key expansion of Inverse transformation for decryption
 */
void aes_dec_ks_inv(unsigned int *rk,
                             const unsigned char *ck)
{
    (void) rk;
    (void) ck;

    asm (".des_inv_ks_loop:    \n\t"
         "lw	 t0, 0(a2)    \n\t"
         "li t1, 0    \n\t"
         "aes32esi	t1, t1, t0, 0    \n\t"
         "aes32esi	t1, t1, t0, 1    \n\t"
         "aes32esi	t1, t1, t0, 2    \n\t"
         "aes32esi	t1, t1, t0, 3    \n\t"
         "li t0, 0    \n\t"
         "aes32dsmi	t0, t0, t1, 0    \n\t"
         "aes32dsmi	t0, t0, t1, 1    \n\t"
         "aes32dsmi	t0, t0, t1, 2    \n\t"
         "aes32dsmi	t0, t0, t1, 3    \n\t"
         "sw t0, 0(a0)    \n\t"
         "addi a0, a0, 4    \n\t"
         "sw t0, 0(a2)    \n\t"
         "addi a2, a2, 4    \n\t"
         "bne a2, a3, .des_inv_ks_loop    \n\t"
         "lw	 t0, 0(a2)    \n\t"
         "sw t0, 0(a0)    \n\t"
         "lw t0, 4(a2)    \n\t"
         "sw t0, 4(a0)    \n\t"
         "lw t0, 8(a2)    \n\t"
         "sw t0, 8(a0)    \n\t"
         "lw	 t0, 12(a2)    \n\t"
         "sw t0, 12(a0)    \n\t");
}

/*
 * Key expansion for decryption, 128-bit case
 */
static void aes_128_dec_ks(unsigned int *rk,
                             const unsigned char *ck)
{
    (void) rk;
    (void) ck;

    asm ("addi    sp, sp, -16    \n\t"
         "sw ra, 0(sp)    \n\t"
         "addi a2, a1, 16    \n\t" // original  round key
         "addi a3, a1, 160    \n\t" // 10 round key schdule
         "addi a0, a0, 16    \n\t"
         "call aes_dec_ks_inv    \n\t"
         "lw	 ra, 0(sp)    \n\t"
         "addi sp, sp, 16    \n\t");
}

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
/*
 * Key expansion for decryption, 192-bit case
 */
static void aes_192_dec_ks(unsigned int *rk,
                             const unsigned char *ck)
{
    (void) rk;
    (void) ck;

    asm ("addi    sp, sp, -16\n\t"
         "sw      ra, 0(sp)\n\t"
         "addi	a2, a1, 16\n\t"
         "addi	a3, a1, 48*4\n\t"
         "addi	a0, a0, 16\n\t"
         "call    aes_dec_ks_inv\n\t"
         "lw		ra, 0(sp)\n\t"
         "addi	sp, sp, 16\n\t");
}

/*
 * Key expansion for decryption, 256-bit case
 */
static void aes_256_dec_ks(unsigned int *rk,
                             const unsigned char *ck)
{
    (void) rk;
    (void) ck;

    asm ("addi sp, sp, -16    \n\t"
         "sw ra, 0(sp)    \n\t"
         "addi a2, a1, 16    \n\t"
         "addi a3, a1, 56*4    \n\t"
         "addi a0, a0, 16    \n\t"
         "call aes_dec_ks_inv    \n\t"
         "lw	 ra, 0(sp)    \n\t"
         "addi sp, sp, 16    \n\t");
}
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

static void aes_ecb_encrypt(unsigned char ct[16],
                             const unsigned char pt[16],
                             unsigned int *rk,
                             unsigned int *ptr)
{
    (void) ct;
    (void) pt;
    (void) rk;
    (void) ptr;

    asm ("lw a4, 0(a1)    \n\t"
         "lw	 a5, 4(a1)    \n\t"
         "lw	 a6, 8(a1)    \n\t"
         "lw	 a7,12(a1)    \n\t"
         "lw	 t0, 0(a2)    \n\t"
         "lw	 t1, 4(a2)    \n\t"
         "lw	 t2, 8(a2)    \n\t"
         "lw	 t3, 12(a2)    \n\t"
         "xor a4, a4, t0    \n\t"
         "xor a5, a5, t1    \n\t"
         "xor a6, a6, t2    \n\t"
         "xor a7, a7, t3    \n\t"
         ".aes_enc:    \n\t"
         "lw	 t0, 16(a2)    \n\t"
         "lw	 t1, 20(a2)    \n\t"
         "lw	 t2, 24(a2)    \n\t"
         "lw	 t3, 28(a2)    \n\t"
         "aes32esmi	t0, t0, a4, 0    \n\t"
         "aes32esmi	t0, t0, a5, 1    \n\t"
         "aes32esmi	t0, t0, a6, 2    \n\t"
         "aes32esmi	t0, t0, a7, 3    \n\t"
         "aes32esmi	t1, t1, a5, 0    \n\t"
         "aes32esmi	t1, t1, a6, 1    \n\t"
         "aes32esmi	t1, t1, a7, 2    \n\t"
         "aes32esmi	t1, t1, a4, 3    \n\t"
         "aes32esmi	t2, t2, a6, 0    \n\t"
         "aes32esmi	t2, t2, a7, 1    \n\t"
         "aes32esmi	t2, t2, a4, 2    \n\t"
         "aes32esmi	t2, t2, a5, 3    \n\t"
         "aes32esmi	t3, t3, a7, 0    \n\t"
         "aes32esmi	t3, t3, a4, 1    \n\t"
         "aes32esmi	t3, t3, a5, 2    \n\t"
         "aes32esmi	t3, t3, a6, 3    \n\t"
         "lw	 a4, 32(a2)    \n\t"
         "lw	 a5, 36(a2)    \n\t"
         "lw	 a6, 40(a2)    \n\t"
         "lw	 a7, 44(a2)    \n\t"
         "addi a2, a2, 32    \n\t"
         "beq a2, a3, .aes_enc_finish    \n\t"
         "aes32esmi a4, a4, t0, 0    \n\t"
         "aes32esmi a4, a4, t1, 1    \n\t"
         "aes32esmi a4, a4, t2, 2    \n\t"
         "aes32esmi a4, a4, t3, 3    \n\t"
         "aes32esmi a5, a5, t1, 0    \n\t"
         "aes32esmi a5, a5, t2, 1    \n\t"
         "aes32esmi a5, a5, t3, 2    \n\t"
         "aes32esmi a5, a5, t0, 3    \n\t"
         "aes32esmi a6, a6, t2, 0    \n\t"
         "aes32esmi a6, a6, t3, 1    \n\t"
         "aes32esmi a6, a6, t0, 2    \n\t"
         "aes32esmi a6, a6, t1, 3    \n\t"
         "aes32esmi a7, a7, t3, 0    \n\t"
         "aes32esmi a7, a7, t0, 1    \n\t"
         "aes32esmi a7, a7, t1, 2    \n\t"
         "aes32esmi a7, a7, t2, 3    \n\t"
         "j .aes_enc    \n\t"
         ".aes_enc_finish:    \n\t"
         "aes32esi a4, a4, t0, 0    \n\t"
         "aes32esi a4, a4, t1, 1    \n\t"
         "aes32esi a4, a4, t2, 2    \n\t"
         "aes32esi a4, a4, t3, 3    \n\t"
         "aes32esi a5, a5, t1, 0    \n\t"
         "aes32esi a5, a5, t2, 1    \n\t"
         "aes32esi a5, a5, t3, 2    \n\t"
         "aes32esi a5, a5, t0, 3    \n\t"
         "aes32esi a6, a6, t2, 0    \n\t"
         "aes32esi a6, a6, t3, 1    \n\t"
         "aes32esi a6, a6, t0, 2    \n\t"
         "aes32esi a6, a6, t1, 3    \n\t"
         "aes32esi a7, a7, t3, 0    \n\t"
         "aes32esi a7, a7, t0, 1    \n\t"
         "aes32esi a7, a7, t1, 2    \n\t"
         "aes32esi a7, a7, t2, 3    \n\t"
         "sw a4, 0(a0)    \n\t"
         "sw a5, 4(a0)    \n\t"
         "sw a6, 8(a0)    \n\t"
         "sw a7, 12(a0)    \n\t");
}

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
static void aes_ecb_decrypt(unsigned char pt[16],
                             const unsigned char ct[16],
                             unsigned int *rk,
                             unsigned int *ptr)
{
    (void) pt;
    (void) ct;
    (void) rk;
    (void) ptr;

    asm ("lw a4, 0(a1)    \n\t"
         "lw	 a5, 4(a1)    \n\t"
         "lw	 a6, 8(a1)    \n\t"
         "lw	 a7, 12(a1)    \n\t"
         "lw	 t0, 0(a3)    \n\t"
         "lw	 t1, 4(a3)    \n\t"
         "lw	 t2, 8(a3)    \n\t"
         "lw	 t3, 12(a3)    \n\t"
         "xor a4, a4, t0    \n\t"
         "xor a5, a5, t1    \n\t"
         "xor a6, a6, t2    \n\t"
         "xor a7, a7, t3    \n\t"
         "addi a3, a3, -32    \n\t"
         ".aes_dec:    \n\t"
         "lw	 t0, 16(a3)    \n\t"
         "lw	 t1, 20(a3)    \n\t"
         "lw	 t2, 24(a3)    \n\t"
         "lw  t3, 28(a3)    \n\t"
         "aes32dsmi	t0, t0, a4, 0    \n\t"
         "aes32dsmi	t0, t0, a7, 1    \n\t"
         "aes32dsmi	t0, t0, a6, 2    \n\t"
         "aes32dsmi	t0, t0, a5, 3    \n\t"
         "aes32dsmi	t1, t1, a5, 0    \n\t"
         "aes32dsmi	t1, t1, a4, 1    \n\t"
         "aes32dsmi	t1, t1, a7, 2    \n\t"
         "aes32dsmi	t1, t1, a6, 3    \n\t"
         "aes32dsmi	t2, t2, a6, 0    \n\t"
         "aes32dsmi	t2, t2, a5, 1    \n\t"
         "aes32dsmi	t2, t2, a4, 2    \n\t"
         "aes32dsmi	t2, t2, a7, 3    \n\t"
         "aes32dsmi	t3, t3, a7, 0    \n\t"
         "aes32dsmi	t3, t3, a6, 1    \n\t"
         "aes32dsmi	t3, t3, a5, 2    \n\t"
         "aes32dsmi	t3, t3, a4, 3    \n\t"
         "lw	 a4, 0(a3)    \n\t"
         "lw	 a5, 4(a3)    \n\t"
         "lw	 a6, 8(a3)    \n\t"
         "lw	 a7, 12(a3)    \n\t"
         "beq a2, a3, .aes_dec_finish    \n\t"
         "addi a3, a3, -32    \n\t"
         "aes32dsmi   a4, a4, t0, 0    \n\t"
         "aes32dsmi   a4, a4, t3, 1    \n\t"
         "aes32dsmi   a4, a4, t2, 2    \n\t"
         "aes32dsmi   a4, a4, t1, 3    \n\t"
         "aes32dsmi   a5, a5, t1, 0    \n\t"
         "aes32dsmi   a5, a5, t0, 1    \n\t"
         "aes32dsmi   a5, a5, t3, 2    \n\t"
         "aes32dsmi   a5, a5, t2, 3    \n\t"
         "aes32dsmi   a6, a6, t2, 0    \n\t"
         "aes32dsmi   a6, a6, t1, 1    \n\t"
         "aes32dsmi   a6, a6, t0, 2    \n\t"
         "aes32dsmi   a6, a6, t3, 3    \n\t"
         "aes32dsmi   a7, a7, t3, 0    \n\t"
         "aes32dsmi   a7, a7, t2, 1    \n\t"
         "aes32dsmi   a7, a7, t1, 2    \n\t"
         "aes32dsmi   a7, a7, t0, 3    \n\t"
         "j .aes_dec    \n\t"
         ".aes_dec_finish:    \n\t"
         "aes32dsi a4, a4, t0, 0    \n\t"
         "aes32dsi a4, a4, t3, 1    \n\t"
         "aes32dsi a4, a4, t2, 2    \n\t"
         "aes32dsi a4, a4, t1, 3    \n\t"
         "aes32dsi a5, a5, t1, 0    \n\t"
         "aes32dsi a5, a5, t0, 1    \n\t"
         "aes32dsi a5, a5, t3, 2    \n\t"
         "aes32dsi a5, a5, t2, 3    \n\t"
         "aes32dsi a6, a6, t2, 0    \n\t"
         "aes32dsi a6, a6, t1, 1    \n\t"
         "aes32dsi a6, a6, t0, 2    \n\t"
         "aes32dsi a6, a6, t3, 3    \n\t"
         "aes32dsi a7, a7, t3, 0    \n\t"
         "aes32dsi a7, a7, t2, 1    \n\t"
         "aes32dsi a7, a7, t1, 2    \n\t"
         "aes32dsi a7, a7, t0, 3    \n\t"
         "sw a4, 0(a0)    \n\t"
         "sw a5, 4(a0)    \n\t"
         "sw a6, 8(a0)    \n\t"
         "sw a7, 12(a0)    \n\t");
}
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

static void aes_encrypt(unsigned char ct[16],
                             const unsigned char pt[16],
                             unsigned int *rk,
                             int nr)
{
    unsigned int *ptr = rk;

    ptr += 4*nr;
    aes_ecb_encrypt(ct, pt, rk, ptr);
}

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
static void aes_decrypt(unsigned char pt[16],
                             const unsigned char ct[16],
                             unsigned int *rk,
                             int nr)
{
    unsigned int *ptr = rk;

    ptr += 4*nr;
    aes_ecb_decrypt(pt, ct, rk, ptr);
}

/*
 * Compute decryption round keys from encryption round keys
 */
void mbedtls_aeszkn_inverse_key(unsigned int *invkey,
                             const unsigned char *fwdkey,
                             size_t bits)
{
    memcpy(invkey, fwdkey, 16);
    switch (bits) {
        case 128: aes_128_dec_ks(invkey, fwdkey); break;
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 192: aes_192_dec_ks(invkey, fwdkey); break;
        case 256: aes_256_dec_ks(invkey, fwdkey); break;
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
        default:;
    }
}
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

int mbedtls_aeszkn_setkey_enc(unsigned int *rk,
                             const unsigned char *key,
                             const unsigned int *rc,
                             size_t bits)
{
    switch (bits) {
        case 128: aes_128_enc_ks(rk, key, rc); break;
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 192: aes_192_enc_ks(rk, key, rc); break;
        case 256: aes_256_enc_ks(rk, key, rc); break;
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    return 0;
}

/*
 * AES-ECB block en(de)cryption
 */
int mbedtls_aeszkn_crypt_ecb(mbedtls_aes_context *ctx,
                             int mode,
                             const unsigned char input[16],
                             unsigned char output[16])
{
    unsigned int *keys = (unsigned int *) (ctx->buf + ctx->rk_offset);

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (mode == MBEDTLS_AES_DECRYPT) {
        aes_decrypt(output, input, keys, ctx->nr);
    } else
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */
    {
        aes_encrypt(output, input, keys, ctx->nr);
    }

    return 0;
}
#elif defined(MBEDTLS_ARCH_IS_RISCV64)
#error "MBEDTLS_AESZKN_C defined, but 64 not support yet"
#endif /* MBEDTLS_ARCH_IS_RISCV32 */
#endif /* MBEDTLS_AESZKN_HAVE_CODE */
#endif /* MBEDTLS_AESZKN_C */
