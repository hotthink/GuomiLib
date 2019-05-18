#include "sm2.h"
#include "../sm3/sm3.h"

#include <string.h>
#include <stdlib.h>

#define GUOMI
#define FAST_MODE 1
#define DEBUG 0
#define NUM_ECC_DIGITS (ECC_BYTES/8)
#define MAX_TRIES 16

typedef unsigned int uint;

#if defined(__SIZEOF_INT128__) || ((__clang_major__ * 100 + __clang_minor__) >= 302)
#define SUPPORTS_INT128 1
#else
#define SUPPORTS_INT128 0
#endif

#if SUPPORTS_INT128
typedef unsigned __int128 uint128_t;
#else
typedef struct
{
    uint64_t m_low;
    uint64_t m_high;
} uint128_t;
#endif

typedef struct EccPoint
{
    uint64_t x[NUM_ECC_DIGITS];
    uint64_t y[NUM_ECC_DIGITS];
} EccPoint;

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

//BN_hex2bn(&p, "");
////BN_hex2bn(&a, "");
////BN_hex2bn(&b, "");
////xck(EC_GROUP_set_curve_GFp(ecg, p, a, b, ctx));
////BIGNUM *Gx = NULL, *Gy = NULL, *N = NULL;
////BN_hex2bn(&Gx, ""
////               "");
////BN_hex2bn(&Gy, "");
////BN_hex2bn(&N , "");

#define Curve_P_16 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFDFFFFFFFF}
#define Curve_P_24 {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull}
#ifndef GUOMI
#define Curve_P_32 {0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull}
#else
#define Curve_P_32 {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull}
//#define Curve_P_32 {0x722EDB8B08F1DFC3ull, 0x457283915C45517Dull,0xE8B92435BF6FF7DEull, 0x8542D69E4C044F18ull}
#endif
#define Curve_P_48 {0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}


#ifndef GUOMI
#define Curve_A_32 {0xFFFFFFFFFFFFFFFCull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull}
#else
#define Curve_A_32 {0xFFFFFFFFFFFFFFFCull, 0xFFFFFFFF00000000ull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull}
#endif

#define Curve_B_16 {0xD824993C2CEE5ED3, 0xE87579C11079F43D}
#define Curve_B_24 {0xFEB8DEECC146B9B1ull, 0x0FA7E9AB72243049ull, 0x64210519E59C80E7ull}

#ifndef GUOMI
#define Curve_B_32 {0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull, 0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull}
#else
#define Curve_B_32 {0xDDBCBD414D940E93ull, 0xF39789F515AB8F92ull, 0x4D5A9E4BCF6509A7ull, 0x28E9FA9E9D9F5E34ull}
#endif

#define Curve_B_48 {0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A, 0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4}

#define Curve_G_16 { \
    {0x0C28607CA52C5B86, 0x161FF7528B899B2D}, \
    {0xC02DA292DDED7A83, 0xCF5AC8395BAFEB13}}

#define Curve_G_24 { \
    {0xF4FF0AFD82FF1012ull, 0x7CBF20EB43A18800ull, 0x188DA80EB03090F6ull}, \
    {0x73F977A11E794811ull, 0x631011ED6B24CDD5ull, 0x07192B95FFC8DA78ull}}

#ifndef GUOMI
#define Curve_G_32 { \
    {0xF4A13945D898C296ull, 0x77037D812DEB33A0ull, 0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull}, \
    {0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull, 0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull}}
#else
#define Curve_G_32 { \
    {0x715A4589334C74C7ull, 0x8FE30BBFF2660BE1ull, 0x5F9904466A39C994ull, 0x32C4AE2C1F198119ull}, \
        {0x02DF32E52139F0A0ull, 0xD0A9877CC62A4740ull, 0x59BDCEE36B692153ull, 0xBC3736A2F4F6779Cull}}
#endif

#define Curve_G_48 { \
    {0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38, 0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537}, \
    {0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0, 0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F}}

#define Curve_N_16 {0x75A30D1B9038A115, 0xFFFFFFFE00000000}
#define Curve_N_24 {0x146BC9B1B4D22831ull, 0xFFFFFFFF99DEF836ull, 0xFFFFFFFFFFFFFFFFull}

#ifndef GUOMI
#define Curve_N_32 {0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull}
#else
#define Curve_N_32 {0x53BBF40939D54123ull,0x7203DF6B21C6052Bull,0xFFFFFFFFFFFFFFFFull,0xFFFFFFFEFFFFFFFFull}
#endif

#define Curve_N_48 {0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

//#define SK {0x0C23661D15897263ull, 0x2A519A55171B1B65ull, 0x068C8D803DFF7979ull, 0x128B2FA8BD433C6Cull}
//#define PK { \
//{0xE97C04FF4DF2548Aull, 0x02BB79E2A5844495ull, 0x471BEE11825BE462ull, 0x0AE4C7798AA0F119ull}, \
//{0xA9FE0C6BB798E857ull, 0x07353E53A176D684ull, 0x6352A73C17B7F16Full, 0x7C0240F88F1CD4E1ull}}

#define SK {0x0C23661D15897263ull, 0x2A519A55171B1B65ull, 0x068C8D803DFF7979ull, 0x128B2FA8BD433C6Cull}
#define PK { \
{0xE97C04FF4DF2548Aull, 0x02BB79E2A5844495ull, 0x471BEE11825BE462ull, 0x0AE4C7798AA0F119ull}, \
{0xA9FE0C6BB798E857ull, 0x07353E53A176D684ull, 0x6352A73C17B7F16Full, 0x7C0240F88F1CD4E1ull}}

#define HASH {0x5D42E3D9B9EFFE76ull, 0x9A87E6FC682D48BBull, 0x28476E005C377FB1ull, 0xB524F552CD82B8B0ull}
#define RAND_K {0x260DBAAE1FB2F96Full, 0xC176D925DD72B727ull, 0x94F94E934817663Full, 0x6CB28D99385C175Cull}

static void vli_modMult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod);
static uint64_t curve_p[NUM_ECC_DIGITS] = CONCAT(Curve_P_, ECC_CURVE);
static uint64_t curve_b[NUM_ECC_DIGITS] = CONCAT(Curve_B_, ECC_CURVE);
static uint64_t curve_a[NUM_ECC_DIGITS] = CONCAT(Curve_A_, ECC_CURVE);
static EccPoint curve_G = CONCAT(Curve_G_, ECC_CURVE);
static uint64_t curve_n[NUM_ECC_DIGITS] = CONCAT(Curve_N_, ECC_CURVE);

#if (defined(_WIN32) || defined(_WIN64))
/* Windows */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static int getRandomNumber(uint64_t *p_vli)
{
    HCRYPTPROV l_prov;
    if(!CryptAcquireContext(&l_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return 0;
    }

    CryptGenRandom(l_prov, ECC_BYTES, (BYTE *)p_vli);
    CryptReleaseContext(l_prov, 0);

    return 1;
}

#else /* _WIN32 */

/* Assume that we are using a POSIX-like system with /dev/urandom or /dev/random. */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int getRandomNumber(uint64_t *p_vli)
{
    int l_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(l_fd == -1)
    {
        l_fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if(l_fd == -1)
        {
            return 0;
        }
    }

    char *l_ptr = (char *)p_vli;
    size_t l_left = ECC_BYTES;
    while(l_left > 0)
    {
        int l_read = read(l_fd, l_ptr, l_left);
        if(l_read <= 0)
        { // read failed
            close(l_fd);
            return 0;
        }
        l_left -= l_read;
        l_ptr += l_read;
    }

    close(l_fd);
    return 1;
}

#endif /* _WIN32 */

static void vli_clear(uint64_t *p_vli)
{
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_vli[i] = 0;
    }
}

/* Returns 1 if p_vli == 0, 0 otherwise. */
static int vli_isZero(uint64_t *p_vli)
{
    uint i;
    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        if(p_vli[i])
        {
            return 0;
        }
    }
    return 1;
}

/* Returns nonzero if bit p_bit of p_vli is set. */
static uint64_t vli_testBit(uint64_t *p_vli, uint p_bit)
{
    return (p_vli[p_bit/64] & ((uint64_t)1 << (p_bit % 64)));
}

/* Counts the number of 64-bit "digits" in p_vli. */
static uint vli_numDigits(uint64_t *p_vli)
{
    int i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for(i = NUM_ECC_DIGITS - 1; i >= 0 && p_vli[i] == 0; --i)
    {
    }

    return (i + 1);
}

/* Counts the number of bits required for p_vli. */
static uint vli_numBits(uint64_t *p_vli)
{
    uint i;
    uint64_t l_digit;

    uint l_numDigits = vli_numDigits(p_vli);
    if(l_numDigits == 0)
    {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for(i=0; l_digit; ++i)
    {
        l_digit >>= 1;
    }

    return ((l_numDigits - 1) * 64 + i);
}

/* Sets p_dest = p_src. */
static void vli_set(uint64_t *p_dest, uint64_t *p_src)
{
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_dest[i] = p_src[i];
    }
}

/* Returns sign of p_left - p_right. */
static int vli_cmp(uint64_t *p_left, uint64_t *p_right)
{
    int i;
    for(i = NUM_ECC_DIGITS-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

/* Computes p_result = p_in << c, returning carry. Can modify in place (if p_result == p_in). 0 < p_shift < 64. */
static uint64_t vli_lshift(uint64_t *p_result, uint64_t *p_in, uint p_shift)
{
    uint64_t l_carry = 0;
    uint i;
    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        uint64_t l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (64 - p_shift);
    }

    return l_carry;
}

/* Computes p_vli = p_vli >> 1. */
static void vli_rshift1(uint64_t *p_vli)
{
    uint64_t *l_end = p_vli;
    uint64_t l_carry = 0;

    p_vli += NUM_ECC_DIGITS;
    while(p_vli-- > l_end)
    {
        uint64_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << 63;
    }
}

/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
static uint64_t vli_add(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_carry = 0;
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint64_t l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}

/* Computes p_result = p_left - p_right, returning borrow. Can modify in place. */
static uint64_t vli_sub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_borrow = 0;
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint64_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

#if SUPPORTS_INT128

/* Computes p_result = p_left * p_right. */
static void vli_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;

    uint i, k;

    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<NUM_ECC_DIGITS; ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_right[k-i];
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }

    p_result[NUM_ECC_DIGITS*2 - 1] = (uint64_t)r01;
}

static void asm_mult_256(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right){
//    uint64_t res_addr = p_result;
//    uint64_t left_addr = p_left;
//    uint64_t right_addr = p_right;
    __asm__ __volatile__(
    "movdqa	(%%rsi), %%xmm4\n\t"
    "movdqa	16(%%rsi), %%xmm5\n\t"
    "movdqa	(%%rdx), %%xmm6\n\t"
    "movdqa	16(%%rdx), %%xmm7\n\t"
    "movq	%%r12, %%xmm14\n\t"
    "movq	%%r14, %%xmm15\n\t"
    "pinsrq	$1, %%r13, %%xmm14\n\t"
    "pinsrq	$1, %%r15, %%xmm15\n\t"
    "pextrq	$1, %%xmm4, %%r12\n\t"
    "pextrq	$1, %%xmm5, %%r13\n\t"
    "pextrq	$1, %%xmm6, %%r14\n\t"
    "pextrq	$1, %%xmm7, %%r15\n\t"
    "xorq	%%r9, %%r9\n\t"
    "xorq	%%r10, %%r10\n\t"
    "movq	%%xmm6, %%r11\n\t"
    "movq	%%xmm4, %%rax\n\t"
    "mulq	%%r11\n\t"
    "movq	%%rax, %%xmm0\n\t"
    "movq	%%rdx, %%r8\n\t"
    "movq	%%xmm4, %%rax\n\t"
    "mulq	%%r14\n\t"
    "addq	%%rax, %%r8\n\t"
    "adcq	%%rdx, %%r9\n\t"
    "movq	%%xmm6, %%rax\n\t"
    "mulq	%%r12\n\t"
    "addq	%%rax, %%r8\n\t"
    "adcq	%%rdx, %%r9\n\t"
    "adcq	$0, %%r10\n\t"
    "pinsrq	$1, %%r8, %%xmm0\n\t"
    "xorq	%%r8, %%r8\n\t"
    "movq	%%xmm7, %%r11\n\t"
    "movq	%%xmm4, %%rax\n\t"
    "mulq	%%r11\n\t"
    "addq	%%rax, %%r9\n\t"
    "adcq	%%rdx, %%r10\n\t"
    "adcq	$0, %%r8\n\t"
    "movq	%%r12, %%rax\n\t"
    "mulq	%%r14\n\t"
    "addq	%%rax, %%r9\n\t"
    "adcq	%%rdx, %%r10\n\t"
    "adcq	$0, %%r8\n\t"
    "movq	%%xmm6, %%r11\n\t"
    "movq	%%xmm5, %%rax\n\t"
    "mulq	%%r11\n\t"
    "addq	%%rax, %%r9\n\t"
    "adcq	%%rdx, %%r10\n\t"
    "adcq	$0, %%r8\n\t"
    "movq	%%r9, %%xmm1\n\t"
    "xorq	%%r9, %%r9\n\t"
    "movq	%%xmm4, %%rax\n\t"
    "mulq	%%r15\n\t"
    "addq	%%rax, %%r10\n\t"
    "adcq	%%rdx, %%r8\n\t"
    "adcq	$0, %%r9\n\t"
    "movq	%%xmm7, %%rax\n\t"
    "mulq	%%r12\n\t"
    "addq	%%rax, %%r10\n\t"
    "adcq	%%rdx, %%r8\n\t"
    "adcq	$0, %%r9\n\t"
    "movq	%%xmm5, %%rax\n\t"
    "mulq	%%r14\n\t"
    "addq	%%rax, %%r10\n\t"
    "adcq	%%rdx, %%r8\n\t"
    "adcq	$0, %%r9\n\t"
    "movq	%%xmm6, %%rax\n\t"
    "mulq	%%r13\n\t"
    "addq	%%rax, %%r10\n\t"
    "adcq	%%rdx, %%r8\n\t"
    "adcq	$0, %%r9\n\t"
    "pinsrq	$1, %%r10, %%xmm1\n\t"
    "xorq	%%r10, %%r10\n\t"
    "movq	%%r12, %%rax\n\t"
    "mulq	%%r15\n\t"
    "addq	%%rax, %%r8\n\t"
    "adcq	%%rdx, %%r9\n\t"
    "adcq	$0, %%r10\n\t"
    "movq	%%xmm7, %%r11\n\t"
    "movq	%%xmm5, %%rax\n\t"
    "mulq	%%r11\n\t"
    "addq	%%rax, %%r8\n\t"
    "adcq	%%rdx, %%r9\n\t"
    "adcq	$0, %%r10\n\t"
    "movq	%%r13, %%rax\n\t"
    "mulq	%%r14\n\t"
    "addq	%%rax, %%r8\n\t"
    "adcq	%%rdx, %%r9\n\t"
    "adcq	$0, %%r10\n\t"
    "movq	%%r8, %%xmm2\n\t"
    "xorq	%%r8, %%r8\n\t"
    "movq	%%xmm5, %%rax\n\t"
    "mulq	%%r15\n\t"
    "addq	%%rax, %%r9\n\t"
    "adcq	%%rdx, %%r10\n\t"
    "adcq	$0, %%r8\n\t"
    "movq	%%xmm7, %%rax\n\t"
    "mulq	%%r13\n\t"
    "addq	%%rax, %%r9\n\t"
    "adcq	%%rdx, %%r10\n\t"
    "adcq	$0, %%r8\n\t"
    "pinsrq	$1, %%r9, %%xmm2\n\t"
    "movq	%%r13, %%rax\n\t"
    "mulq	%%r15\n\t"
    "addq	%%rax, %%r10\n\t"
    "adcq	%%rdx, %%r8\n\t"
    "movq	%%r10, %%xmm3\n\t"
    "pinsrq	$1, %%r8, %%xmm3\n\t"
    "movq	%%xmm14, %%r12\n\t"
    "movq	%%xmm15, %%r14\n\t"
    "pextrq	$1, %%xmm14, %%r13\n\t"
    "pextrq	$1, %%xmm15, %%r15\n\t"
    "movdqa	%%xmm0, (%%rdi)\n\t"
    "movdqa	%%xmm1, 16(%%rdi)\n\t"
    "movdqa	%%xmm2, 32(%%rdi)\n\t"
    "movdqa	%%xmm3, 48(%%rdi)\n\t"
    "emms\n\t"
    "xorq	%%rax, %%rax\n\t"
    "xorq	%%rdx, %%rdx\n\t"
	        :"=D"(p_result)
            :"S"(p_left),"d"(p_right)
            );


}

/* Computes p_result = p_left^2. */
static void vli_square(uint64_t *p_result, uint64_t *p_left)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;

    uint i, k;
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_left[k-i];
            if(i < k-i)
            {
                r2 += l_product >> 127;
                l_product *= 2;
            }
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }

    p_result[NUM_ECC_DIGITS*2 - 1] = (uint64_t)r01;
}

#else /* #if SUPPORTS_INT128 */

static uint128_t mul_64_64(uint64_t p_left, uint64_t p_right)
{
    uint128_t l_result;

    uint64_t a0 = p_left & 0xffffffffull;
    uint64_t a1 = p_left >> 32;
    uint64_t b0 = p_right & 0xffffffffull;
    uint64_t b1 = p_right >> 32;

    uint64_t m0 = a0 * b0;
    uint64_t m1 = a0 * b1;
    uint64_t m2 = a1 * b0;
    uint64_t m3 = a1 * b1;

    m2 += (m0 >> 32);
    m2 += m1;
    if(m2 < m1)
    { // overflow
        m3 += 0x100000000ull;
    }

    l_result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
    l_result.m_high = m3 + (m2 >> 32);

    return l_result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
    uint128_t l_result;
    l_result.m_low = a.m_low + b.m_low;
    l_result.m_high = a.m_high + b.m_high + (l_result.m_low < a.m_low);
    return l_result;
}

static void vli_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;

    uint i, k;

    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<NUM_ECC_DIGITS; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_right[k-i]);
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }

    p_result[NUM_ECC_DIGITS*2 - 1] = r01.m_low;
}

static void vli_square(uint64_t *p_result, uint64_t *p_left)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;

    uint i, k;
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_left[k-i]);
            if(i < k-i)
            {
                r2 += l_product.m_high >> 63;
                l_product.m_high = (l_product.m_high << 1) | (l_product.m_low >> 63);
                l_product.m_low <<= 1;
            }
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }

    p_result[NUM_ECC_DIGITS*2 - 1] = r01.m_low;
}

#endif /* SUPPORTS_INT128 */


/* Computes p_result = (p_left + p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modAdd(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_carry = vli_add(p_result, p_left, p_right);
    if(l_carry || vli_cmp(p_result, p_mod) >= 0)
    { /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        vli_sub(p_result, p_result, p_mod);
    }
}

/* Computes p_result = (p_left - p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modSub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_borrow = vli_sub(p_result, p_left, p_right);
    if(l_borrow)
    { /* In this case, p_result == -diff == (max int) - diff.
         Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
        vli_add(p_result, p_result, p_mod);
    }
}

#if ECC_CURVE == secp128r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    int l_carry;

    vli_set(p_result, p_product);

    l_tmp[0] = p_product[2];
    l_tmp[1] = (p_product[3] & 0x1FFFFFFFFull) | (p_product[2] << 33);
    l_carry = vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[2] >> 31) | (p_product[3] << 33);
    l_tmp[1] = (p_product[3] >> 31) | ((p_product[2] & 0xFFFFFFFF80000000ull) << 2);
    l_carry += vli_add(p_result, p_result, l_tmp);

    l_tmp[0] = (p_product[2] >> 62) | (p_product[3] << 2);
    l_tmp[1] = (p_product[3] >> 62) | ((p_product[2] & 0xC000000000000000ull) >> 29) | (p_product[3] << 35);
    l_carry += vli_add(p_result, p_result, l_tmp);

    l_tmp[0] = (p_product[3] >> 29);
    l_tmp[1] = ((p_product[3] & 0xFFFFFFFFE0000000ull) << 4);
    l_carry += vli_add(p_result, p_result, l_tmp);

    l_tmp[0] = (p_product[3] >> 60);
    l_tmp[1] = (p_product[3] & 0xFFFFFFFE00000000ull);
    l_carry += vli_add(p_result, p_result, l_tmp);

    l_tmp[0] = 0;
    l_tmp[1] = ((p_product[3] & 0xF000000000000000ull) >> 27);
    l_carry += vli_add(p_result, p_result, l_tmp);

    while(l_carry || vli_cmp(curve_p, p_result) != 1)
    {
        l_carry -= vli_sub(p_result, p_result, curve_p);
    }
}

#elif ECC_CURVE == secp192r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    int l_carry;

    vli_set(p_result, p_product);

    vli_set(l_tmp, &p_product[3]);
    l_carry = vli_add(p_result, p_result, l_tmp);

    l_tmp[0] = 0;
    l_tmp[1] = p_product[3];
    l_tmp[2] = p_product[4];
    l_carry += vli_add(p_result, p_result, l_tmp);

    l_tmp[0] = l_tmp[1] = p_product[5];
    l_tmp[2] = 0;
    l_carry += vli_add(p_result, p_result, l_tmp);

    while(l_carry || vli_cmp(curve_p, p_result) != 1)
    {
        l_carry -= vli_sub(p_result, p_result, curve_p);
    }
}

#elif ECC_CURVE == secp256r1

static void asm_mmod_fast(uint64_t *p_result, uint64_t *p_product){
//    uint64_t res_addr = p_result;
//    uint64_t prod_addr = p_product;
    __asm__ __volatile__(
    "movdqa	(%%rsi), %%xmm0\n\t"
    "movdqa	16(%%rsi), %%xmm1\n\t"
    "movdqa	32(%%rsi), %%xmm2\n\t"
    "movdqa	48(%%rsi), %%xmm3\n\t"
    "movq	%%r12, %%xmm14\n\t"
    "movq	%%r14, %%xmm15\n\t"
    "pinsrq	$1, %%r13, %%xmm14\n\t"
    "pinsrq	$1, %%r15, %%xmm15\n\t"
    "movd	%%xmm2, %%r8d\n\t"
    "movd	%%xmm3, %%r12d\n\t"
    "pextrd	$1, %%xmm2, %%r9d\n\t"
    "pextrd	$2, %%xmm2, %%r10d\n\t"
    "pextrd	$3, %%xmm2, %%r11d\n\t"
    "pextrd	$1, %%xmm3, %%r13d\n\t"
    "pextrd	$2, %%xmm3, %%r14d\n\t"
    "pextrd	$3, %%xmm3, %%r15d\n\t"
    "addq	%%r9, %%r8\n\t"
    "addq	%%r10, %%r9\n\t"
    "addq	%%r11, %%r10\n\t"
    "addq	%%r12, %%r11\n\t"
    "addq	%%r13, %%r11\n\t"
    "addq	%%r13, %%r12\n\t"
    "addq	%%r14, %%r12\n\t"
    "addq	%%r14, %%r13\n\t"
    "addq	%%r15, %%r13\n\t"
    "movq	$8, %%rsi\n\t"
    "shlq	$32, %%rsi\n\t"
    "subq	$8, %%rsi\n\t"
    "movd	%%xmm0, %%eax\n\t"
    "addq	%%r8, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "subq	%%r11, %%rax\n\t"
    "subq	%%r14, %%rax\n\t"
    "movd	%%eax, %%xmm4\n\t"
    "shrq	$32, %%rax\n\t"
    "pextrd	$1, %%xmm0, %%edx\n\t"
    "addq	%%rdx, %%rax\n\t"
    "addq	%%r9, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "subq	%%r12, %%rax\n\t"
    "subq	%%r15, %%rax\n\t"
    "pinsrd	$1, %%eax, %%xmm4\n\t"
    "shrq	$32, %%rax\n\t"
    "pextrd	$2, %%xmm0, %%edx\n\t"
    "addq	%%rdx, %%rax\n\t"
    "addq	%%r10, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "subq	%%r13, %%rax\n\t"
    "pinsrd	$2, %%eax, %%xmm4\n\t"
    "shrq	$32, %%rax\n\t"
    "pextrd	$3, %%xmm0, %%edx\n\t"
    "addq	%%rdx, %%rax\n\t"
    "addq	%%r11, %%rax\n\t"
    "addq	%%r11, %%rax\n\t"
    "addq	%%r14, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "addq	$8, %%rax\n\t"
    "subq	%%r13, %%rax\n\t"
    "subq	%%r8, %%rax\n\t"
    "pinsrd	$3, %%eax, %%xmm4\n\t"
    "shrq	$32, %%rax\n\t"
    "movd	%%xmm1, %%edx\n\t"
    "addq	%%rdx, %%rax\n\t"
    "addq	%%r12, %%rax\n\t"
    "addq	%%r12, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "subq	%%r14, %%rax\n\t"
    "subq	%%r9, %%rax\n\t"
    "movd	%%eax, %%xmm5\n\t"
    "shrq	$32, %%rax\n\t"
    "pextrd	$1, %%xmm1, %%edx\n\t"
    "addq	%%rdx, %%rax\n\t"
    "addq	%%r13, %%rax\n\t"
    "addq	%%r13, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "subq	%%r15, %%rax\n\t"
    "subq	%%r10, %%rax\n\t"
    "pinsrd	$1, %%eax, %%xmm5\n\t"
    "shrq	$32, %%rax\n\t"
    "pextrd	$2, %%xmm1, %%edx\n\t"
    "addq	%%rdx, %%rax\n\t"
    "addq	%%r14, %%rax\n\t"
    "addq	%%r14, %%rax\n\t"
    "addq	%%r15, %%rax\n\t"
    "addq	%%r13, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "addq	$8, %%rax\n\t"
    "subq	%%r8, %%rax\n\t"
    "pinsrd	$2, %%eax, %%xmm5\n\t"
    "shrq	$32, %%rax\n\t"
    "pextrd	$3, %%xmm1, %%edx\n\t"
    "addq	%%rdx, %%rax\n\t"
    "addq	%%r15, %%rax\n\t"
    "addq	%%r15, %%rax\n\t"
    "addq	%%r15, %%rax\n\t"
    "addq	%%r8, %%rax\n\t"
    "addq	%%rsi, %%rax\n\t"
    "subq	$8, %%rax\n\t"
    "subq	%%r9, %%rax\n\t"
    "subq	%%r11, %%rax\n\t"
    "pinsrd	$3, %%eax, %%xmm5\n\t"
    "shrq	$32, %%rax\n\t"
    "movq	%%xmm4, %%r8\n\t"
    "movq	%%xmm5, %%r10\n\t"
    "pextrq	$1, %%xmm4, %%r9\n\t"
    "pextrq	$1, %%xmm5, %%r11\n\t"
    "subq	%%r12, %%r8\n\t"
    "sbbq	%%r13, %%r9\n\t"
    "sbbq	%%r14, %%r10\n\t"
    "sbbq	%%r15, %%r11\n\t"
    "sbbq	%%rdx, %%rax\n\t"
    "jnc	.L1\n\t"
    "xorq	%%r12, %%r12\n\t"
    "xorq	%%r14, %%r14\n\t"
    "notq	%%r12\n\t"
    "mov	%%r12d, %%r13d\n\t"
    "movq	%%r13, %%r15\n\t"
    "notq	%%r15\n\t"
    "incq	%%r15\n\t"
    "addq	%%r12, %%r8\n\t"
    "adcq	%%r13, %%r9\n\t"
    "adcq	%%r14, %%r10\n\t"
    "adcq	%%r15, %%r11\n\t"
    ".L1:\n\t"
    "movq	%%r8, %%xmm4\n\t"
    "movq	%%r10, %%xmm5\n\t"
    "pinsrq	$1, %%r9, %%xmm4\n\t"
    "pinsrq	$1, %%r11, %%xmm5\n\t"
    "movq	%%xmm14, %%r12\n\t"
    "movq	%%xmm15, %%r14\n\t"
    "pextrq	$1, %%xmm14, %%r13\n\t"
    "pextrq	$1, %%xmm15, %%r15\n\t"
    "movdqa	%%xmm4, (%%rdi)\n\t"
    "movdqa	%%xmm5, 16(%%rdi)\n\t"
    "emms\n\t"
    "xorq	%%rax, %%rax\n\t"
    "xorq	%%rdx, %%rd\n\t"
    :"=D"(p_result)
    :"S"(p_product)
    );

}
/* Computes p_result = p_product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    int l_carry;

    /* s1 */
    vli_set(p_result, p_product);

    /* s2 */
    l_tmp[0] = p_product[6];
    l_tmp[1] = p_product[4] << 32;
    l_tmp[2] = p_product[4] >> 32 | p_product[5] << 32;
    l_tmp[3] = p_product[5] >> 32 | p_product[4] << 32;
    l_carry = vli_add(p_result, p_result, l_tmp);

    /* s3 */
    l_tmp[0] = p_product[4];
    l_tmp[1] = p_product[7] & 0xffffffff00000000ull;
    l_tmp[2] = 0;
    l_tmp[3] = p_product[4] & 0xffffffff00000000ull;
    l_carry += vli_add(p_result, p_result, l_tmp);

    /* s4 */
    l_tmp[0] = p_product[5] << 32 | p_product[4] >> 32;
    l_tmp[1] = p_product[7] << 32;
    l_tmp[2] = p_product[7] >> 32;
    l_tmp[3] = p_product[5] << 32;
    l_carry += vli_add(p_result, p_result, l_tmp);

    /* s5 */
    l_tmp[0] = (p_product[5] >> 32) | (p_product[6] << 32);
    l_tmp[1] = p_product[5] & 0xffffffff00000000ull;
    l_tmp[2] = p_product[6];
    l_tmp[3] = p_product[7];
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    /* s6 */
    l_tmp[0] = p_product[5];
    l_tmp[1] = p_product[6] << 32;
    l_tmp[2] = p_product[6] >> 32 | p_product[7] << 32;
    l_tmp[3] = p_product[7] >> 32 | (p_product[5] & 0xffffffff00000000ull);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    /* s7 */
    l_tmp[0] = 0;
    l_tmp[1] = 0;
    l_tmp[2] = 0;
    l_tmp[3] = p_product[6] << 32;
    l_carry += vli_lshift(l_tmp, l_tmp, 1);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    /* s8 */
    l_tmp[0] = p_product[6] >> 32;
    l_tmp[1] = 0;
    l_tmp[2] = 0;
    l_tmp[3] = p_product[6] & 0xffffffff00000000ull;
    l_carry += vli_lshift(l_tmp, l_tmp, 1);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    /* s9 */
    l_tmp[0] = p_product[7] << 32 | (p_product[7] & 0xffffffff);
    l_tmp[1] = 0;
    l_tmp[2] = 0;
    l_tmp[3] = p_product[7] << 32;
    l_carry += vli_lshift(l_tmp, l_tmp, 1);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    /* s10 */
    l_tmp[0] = p_product[7] >> 32 | (p_product[7] & 0xffffffff00000000ull);
    l_tmp[1] = p_product[6] & 0xffffffff00000000ull;
    l_tmp[2] = p_product[7];
    l_tmp[3] = p_product[7] & 0xffffffff00000000ull;
    l_carry += vli_lshift(l_tmp, l_tmp, 1);
    l_carry += vli_add(p_result, p_result, l_tmp);

    /* s11 */
    l_tmp[0] = 0;
    l_tmp[1] = (p_product[4] & 0xffffffff);
    l_tmp[2] = 0;
    l_tmp[3] = 0;
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    /* s12 */
    l_tmp[0] = 0;
    l_tmp[1] = p_product[4] >> 32;
    l_tmp[2] = 0;
    l_tmp[3] = 0;
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    /* s13 */
    l_tmp[0] = 0;
    l_tmp[1] = p_product[6] >> 32;
    l_tmp[2] = 0;
    l_tmp[3] = 0;
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    /* s14 */
    l_tmp[0] = 0;
    l_tmp[1] = p_product[7] & 0xffffffff;
    l_tmp[2] = 0;
    l_tmp[3] = 0;
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    if(l_carry < 0)
    {
        do
        {
            l_carry += vli_add(p_result, p_result, curve_p);
        } while(l_carry < 0);
    }
    else
    {
        while(l_carry || vli_cmp(curve_p, p_result) != 1)
        {
            l_carry -= vli_sub(p_result, p_result, curve_p);
        }
    }
}

#elif ECC_CURVE == secp384r1

static void omega_mult(uint64_t *p_result, uint64_t *p_right)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    uint64_t l_carry, l_diff;

    /* Multiply by (2^128 + 2^96 - 2^32 + 1). */
    vli_set(p_result, p_right); /* 1 */
    l_carry = vli_lshift(l_tmp, p_right, 32);
    p_result[1 + NUM_ECC_DIGITS] = l_carry + vli_add(p_result + 1, p_result + 1, l_tmp); /* 2^96 + 1 */
    p_result[2 + NUM_ECC_DIGITS] = vli_add(p_result + 2, p_result + 2, p_right); /* 2^128 + 2^96 + 1 */
    l_carry += vli_sub(p_result, p_result, l_tmp); /* 2^128 + 2^96 - 2^32 + 1 */
    l_diff = p_result[NUM_ECC_DIGITS] - l_carry;
    if(l_diff > p_result[NUM_ECC_DIGITS])
    { /* Propagate borrow if necessary. */
        uint i;
        for(i = 1 + NUM_ECC_DIGITS; ; ++i)
        {
            --p_result[i];
            if(p_result[i] != (uint64_t)-1)
            {
                break;
            }
        }
    }
    p_result[NUM_ECC_DIGITS] = l_diff;
}

/* Computes p_result = p_product % curve_p
    see PDF "Comparing Elliptic Curve Cryptography and RSA on 8-bit CPUs"
    section "Curve-Specific Optimizations" */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[2*NUM_ECC_DIGITS];

    while(!vli_isZero(p_product + NUM_ECC_DIGITS)) /* While c1 != 0 */
    {
        uint64_t l_carry = 0;
        uint i;

        vli_clear(l_tmp);
        vli_clear(l_tmp + NUM_ECC_DIGITS);
        omega_mult(l_tmp, p_product + NUM_ECC_DIGITS); /* tmp = w * c1 */
        vli_clear(p_product + NUM_ECC_DIGITS); /* p = c0 */

        /* (c1, c0) = c0 + w * c1 */
        for(i=0; i<NUM_ECC_DIGITS+3; ++i)
        {
            uint64_t l_sum = p_product[i] + l_tmp[i] + l_carry;
            if(l_sum != p_product[i])
            {
                l_carry = (l_sum < p_product[i]);
            }
            p_product[i] = l_sum;
        }
    }

    while(vli_cmp(p_product, curve_p) > 0)
    {
        vli_sub(p_product, p_product, curve_p);
    }
    vli_set(p_result, p_product);
}

#endif

/* Computes p_result = (p_left * p_right) % curve_p. */
static void vli_modMult_fast(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    if(FAST_MODE){

        uint64_t l_product[2 * NUM_ECC_DIGITS];
        vli_mult(l_product, p_left, p_right);
        vli_mmod_fast(p_result, l_product);
    }
    else {
        vli_modMult(p_result, p_left, p_right, curve_p);
    }
}

/* Computes p_result = p_left^2 % curve_p. */
static void vli_modSquare_fast(uint64_t *p_result, uint64_t *p_left)
{
    if(FAST_MODE) {
        uint64_t l_product[2 * NUM_ECC_DIGITS];
        vli_square(l_product, p_left);
        vli_mmod_fast(p_result, l_product);
    }
    else{
        vli_modMult(p_result,p_left,p_left,curve_p);
    }
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void vli_modInv(uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod)
{
    uint64_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS], u[NUM_ECC_DIGITS], v[NUM_ECC_DIGITS];
    uint64_t l_carry;
    int l_cmpResult;

    if(vli_isZero(p_input))
    {
        vli_clear(p_result);
        return;
    }

    vli_set(a, p_input);
    vli_set(b, p_mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);

    while((l_cmpResult = vli_cmp(a, b)) != 0)
    {
        l_carry = 0;
        if(EVEN(a))
        {
            vli_rshift1(a);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
        else if(EVEN(b))
        {
            vli_rshift1(b);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
        else if(l_cmpResult > 0)
        {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if(vli_cmp(u, v) < 0)
            {
                vli_add(u, u, p_mod);
            }
            vli_sub(u, u, v);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
        else
        {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if(vli_cmp(v, u) < 0)
            {
                vli_add(v, v, p_mod);
            }
            vli_sub(v, v, u);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
    }

    vli_set(p_result, u);
}

/* ------ Point operations ------ */

/* Returns 1 if p_point is the point at infinity, 0 otherwise. */
static int EccPoint_isZero(EccPoint *p_point)
{
    return (vli_isZero(p_point->x) && vli_isZero(p_point->y));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Double in place */
static void EccPoint_double_jacobian(uint64_t *X1, uint64_t *Y1, uint64_t *Z1)
{
    /* t1 = X, t2 = Y, t3 = Z */
    uint64_t t4[NUM_ECC_DIGITS];
    uint64_t t5[NUM_ECC_DIGITS];

    if(vli_isZero(Z1))
    {
        return;
    }

    
    vli_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
    vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(t4, t4);   /* t4 = y1^4 */
    vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */

    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
    vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
    vli_modSub(Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
    vli_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */

    vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
    if(vli_testBit(X1, 0))
    {
        uint64_t l_carry = vli_add(X1, X1, curve_p);
        vli_rshift1(X1);
        X1[NUM_ECC_DIGITS-1] |= l_carry << 63;
    }
    else
    {
        vli_rshift1(X1);
    }
    /* t1 = 3/2*(x1^2 - z1^4) = B */

    vli_modSquare_fast(Z1, X1);      /* t3 = B^2 */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
    vli_modSub(t5, t5, Z1, curve_p); /* t5 = A - x3 */
    vli_modMult_fast(X1, X1, t5);    /* t1 = B * (A - x3) */
    vli_modSub(t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */

    vli_set(X1, Z1);
    vli_set(Z1, Y1);
    vli_set(Y1, t4);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uint64_t *X1, uint64_t *Y1, uint64_t *Z)
{
    uint64_t t1[NUM_ECC_DIGITS];

    vli_modSquare_fast(t1, Z);    /* z^2 */
    vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
    vli_modMult_fast(t1, t1, Z);  /* z^3 */
    vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uint64_t *p_initialZ)
{
    uint64_t z[NUM_ECC_DIGITS];

    vli_set(X2, X1);
    vli_set(Y2, Y1);

    vli_clear(z);
    z[0] = 1;
    if(p_initialZ)
    {
        vli_set(z, p_initialZ);
    }

    apply_z(X1, Y1, z);

    EccPoint_double_jacobian(X1, Y1, z);

    apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint64_t t5[NUM_ECC_DIGITS];

    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */
    vli_modSquare_fast(t5, Y2);      /* t5 = (y2 - y1)^2 = D */

    vli_modSub(t5, t5, X1, curve_p); /* t5 = D - B */
    vli_modSub(t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */
    vli_modSub(X2, X2, X1, curve_p); /* t3 = C - B */
    vli_modMult_fast(Y1, Y1, X2);    /* t2 = y1*(C - B) */
    vli_modSub(X2, X1, t5, curve_p); /* t3 = B - x3 */
    vli_modMult_fast(Y2, Y2, X2);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

    vli_set(X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint64_t t5[NUM_ECC_DIGITS];
    uint64_t t6[NUM_ECC_DIGITS];
    uint64_t t7[NUM_ECC_DIGITS];

    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modAdd(t5, Y2, Y1, curve_p); /* t4 = y2 + y1 */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */

    vli_modSub(t6, X2, X1, curve_p); /* t6 = C - B */
    vli_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) */
    vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
    vli_modSquare_fast(X2, Y2);      /* t3 = (y2 - y1)^2 */
    vli_modSub(X2, X2, t6, curve_p); /* t3 = x3 */

    vli_modSub(t7, X1, X2, curve_p); /* t7 = B - x3 */
    vli_modMult_fast(Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

    vli_modSquare_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */
    vli_modSub(t7, t7, t6, curve_p); /* t7 = x3' */
    vli_modSub(t6, t7, X1, curve_p); /* t6 = x3' - B */
    vli_modMult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub(Y1, t6, Y1, curve_p); /* t2 = y3' */

    vli_set(X1, t7);
}

static void EccPoint_mult(EccPoint *p_result, EccPoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ)
{
    /* R0 and R1 */
    uint64_t Rx[2][NUM_ECC_DIGITS];
    uint64_t Ry[2][NUM_ECC_DIGITS];
    uint64_t z[NUM_ECC_DIGITS];
    int i, nb;

    vli_set(Rx[1], p_point->x);
    vli_set(Ry[1], p_point->y);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

    for(i = vli_numBits(p_scalar) - 2; i > 0; --i)
    {
        // printf("127\n");
        nb = !vli_testBit(p_scalar, i);
        XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    }

    nb = !vli_testBit(p_scalar, 0);
    XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);

    /* Find final 1/Z value. */

    vli_modSub(z, Rx[1], Rx[0], curve_p); /* X1 - X0 */
    vli_modMult_fast(z, z, Ry[1-nb]);     /* Yb * (X1 - X0) */
    //vli_modMult(z,z,Ry[1-nb],curve_p);
    vli_modMult_fast(z, z, p_point->x);   /* xP * Yb * (X1 - X0) */
    //vli_modMult(z, z, p_point->x,curve_p);   /* xP * Yb * (X1 - X0) */

    vli_modInv(z, z, curve_p);            /* 1 / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, p_point->y);   /* yP / (xP * Yb * (X1 - X0)) */
    //vli_modMult(z, z, p_point->y,curve_p);
    vli_modMult_fast(z, z, Rx[1-nb]);     /* Xb * yP / (xP * Yb * (X1 - X0)) */
    //vli_modMult(z, z, Rx[1-nb],curve_p);
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);

    apply_z(Rx[0], Ry[0], z);

    vli_set(p_result->x, Rx[0]);
    vli_set(p_result->y, Ry[0]);
}

static void ecc_bytes2native(uint64_t p_native[NUM_ECC_DIGITS], const uint8_t p_bytes[ECC_BYTES])
{
    unsigned i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        const uint8_t *p_digit = p_bytes + 8 * (NUM_ECC_DIGITS - 1 - i);
        p_native[i] = ((uint64_t)p_digit[0] << 56) | ((uint64_t)p_digit[1] << 48) | ((uint64_t)p_digit[2] << 40) | ((uint64_t)p_digit[3] << 32) |
                      ((uint64_t)p_digit[4] << 24) | ((uint64_t)p_digit[5] << 16) | ((uint64_t)p_digit[6] << 8) | (uint64_t)p_digit[7];
    }
}

static void ecc_native2bytes(uint8_t p_bytes[ECC_BYTES], const uint64_t p_native[NUM_ECC_DIGITS])
{
    unsigned i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint8_t *p_digit = p_bytes + 8 * (NUM_ECC_DIGITS - 1 - i);
        p_digit[0] = p_native[i] >> 56;
        p_digit[1] = p_native[i] >> 48;
        p_digit[2] = p_native[i] >> 40;
        p_digit[3] = p_native[i] >> 32;
        p_digit[4] = p_native[i] >> 24;
        p_digit[5] = p_native[i] >> 16;
        p_digit[6] = p_native[i] >> 8;
        p_digit[7] = p_native[i];
    }
}

/* Compute a = sqrt(a) (mod curve_p). */
static void mod_sqrt(uint64_t a[NUM_ECC_DIGITS])
{
    unsigned i;
    uint64_t p1[NUM_ECC_DIGITS] = {1};
    uint64_t l_result[NUM_ECC_DIGITS] = {1};

    /* Since curve_p == 3 (mod 4) for all supported curves, we can
       compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
    vli_add(p1, curve_p, p1); /* p1 = curve_p + 1 */
    for(i = vli_numBits(p1) - 1; i > 1; --i)
    {
        vli_modSquare_fast(l_result, l_result);
        if(vli_testBit(p1, i))
        {
            vli_modMult_fast(l_result, l_result, a);
        }
    }
    vli_set(a, l_result);
}

static void ecc_point_decompress(EccPoint *p_point, const uint8_t p_compressed[ECC_BYTES+1])
{
    ecc_bytes2native(p_point->x, p_compressed+1);

    vli_modSquare_fast(p_point->y, p_point->x); /* y = x^2 */
    vli_modAdd(p_point->y, p_point->y, curve_a, curve_p); /* y = x^2 + a */
    vli_modMult_fast(p_point->y, p_point->y, p_point->x); /* y = x^3 + ax */
    vli_modAdd(p_point->y, p_point->y, curve_b, curve_p); /* y = x^3 + ax + b */

    mod_sqrt(p_point->y);

    if((p_point->y[0] & 0x01) != (p_compressed[0] & 0x01))
    {
        vli_sub(p_point->y, curve_p, p_point->y);
    }
}

int sm2_make_key(uint8_t p_privateKey[ECC_BYTES], uint8_t p_publicKey_X[ECC_BYTES], uint8_t p_publicKey_Y[ECC_BYTES])
{
    uint64_t l_private[NUM_ECC_DIGITS];
    EccPoint l_public;
    unsigned l_tries = 0;

    do
    {
        if(!getRandomNumber(l_private) || (l_tries++ >= MAX_TRIES))
        {
            return 0;
        }
        if(vli_isZero(l_private))
        {
            continue;
        }

        /* Make sure the private key is in the range [1, n-1].
           For the supported curves, n is always large enough that we only need to subtract once at most. */
        if(vli_cmp(curve_n, l_private) != 1)
        {
            vli_sub(l_private, l_private, curve_n);
        }

        EccPoint_mult(&l_public, &curve_G, l_private, NULL);
    } while(EccPoint_isZero(&l_public));

    
    ecc_native2bytes(p_privateKey, l_private);
//    ecc_native2bytes(p_publicKey + 1, l_public.x);
//    p_publicKey[0] = 2 + (l_public.y[0] & 0x01);
    if(p_publicKey_X != NULL)
        ecc_native2bytes(p_publicKey_X, l_public.x);
    if(p_publicKey_Y != NULL)
        ecc_native2bytes(p_publicKey_Y, l_public.y);
    return 1;
}

int sm2_shared_secret(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_privateKey[ECC_BYTES], uint8_t p_secret[ECC_BYTES])
{
    EccPoint l_public;
    uint64_t l_private[NUM_ECC_DIGITS];
    uint64_t l_random[NUM_ECC_DIGITS];

    if(!getRandomNumber(l_random))
    {
        return 0;
    }

    ecc_point_decompress(&l_public, p_publicKey);
    ecc_bytes2native(l_private, p_privateKey);

    EccPoint l_product;
    EccPoint_mult(&l_product, &l_public, l_private, l_random);

    ecc_native2bytes(p_secret, l_product.x);

    return !EccPoint_isZero(&l_product);
}

/* -------- sm2 code -------- */

/* Computes p_result = (p_left * p_right) % p_mod. */
static void vli_modMult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_product[2 * NUM_ECC_DIGITS];
    uint64_t l_modMultiple[2 * NUM_ECC_DIGITS];
    uint l_digitShift, l_bitShift;
    uint l_productBits;
    uint l_modBits = vli_numBits(p_mod);

    vli_mult(l_product, p_left, p_right);
    l_productBits = vli_numBits(l_product + NUM_ECC_DIGITS);
    if(l_productBits)
    {
        l_productBits += NUM_ECC_DIGITS * 64;
    }
    else
    {
        l_productBits = vli_numBits(l_product);
    }

    if(l_productBits < l_modBits)
    { /* l_product < p_mod. */
        vli_set(p_result, l_product);
        return;
    }

    /* Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
       power of two possible while still resulting in a number less than p_left. */
    vli_clear(l_modMultiple);
    vli_clear(l_modMultiple + NUM_ECC_DIGITS);
    l_digitShift = (l_productBits - l_modBits) / 64;
    l_bitShift = (l_productBits - l_modBits) % 64;
    if(l_bitShift)
    {
        l_modMultiple[l_digitShift + NUM_ECC_DIGITS] = vli_lshift(l_modMultiple + l_digitShift, p_mod, l_bitShift);
    }
    else
    {
        vli_set(l_modMultiple + l_digitShift, p_mod);
    }

    /* Subtract all multiples of p_mod to get the remainder. */
    vli_clear(p_result);
    p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
    while(l_productBits > NUM_ECC_DIGITS * 64 || vli_cmp(l_modMultiple, p_mod) >= 0)
    {
        int l_cmp = vli_cmp(l_modMultiple + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS);
        if(l_cmp < 0 || (l_cmp == 0 && vli_cmp(l_modMultiple, l_product) <= 0))
        {
            if(vli_sub(l_product, l_product, l_modMultiple))
            { /* borrow */
                vli_sub(l_product + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS, p_result);
            }
            vli_sub(l_product + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS, l_modMultiple + NUM_ECC_DIGITS);
        }
        uint64_t l_carry = (l_modMultiple[NUM_ECC_DIGITS] & 0x01) << 63;
        vli_rshift1(l_modMultiple + NUM_ECC_DIGITS);
        vli_rshift1(l_modMultiple);
        l_modMultiple[NUM_ECC_DIGITS-1] |= l_carry;

        --l_productBits;
    }
    vli_set(p_result, l_product);
}

static uint umax(uint a, uint b)
{
    return (a > b ? a : b);
}

int ECC_check_point(EccPoint *p_point)
{
    uint64_t temp[NUM_ECC_DIGITS];
    uint64_t y_square[NUM_ECC_DIGITS];
    
    vli_modSquare_fast(temp, p_point->x); /* temp = x^2 */
    vli_modAdd(temp, temp, curve_a, curve_p); /* temp = x^2 + a */
    vli_modMult_fast(temp, temp, p_point->x); /* temp = x^3 + ax */
    vli_modAdd(temp, temp, curve_b, curve_p); /* temp = x^3 + ax + b */
    vli_modSquare_fast(y_square, p_point->y);                       /*temp = sqrt(x^3 + ax + b) */
    
    if(vli_cmp(temp, y_square) == 0)    /* check if temp = y^2 */
        return 1;
    else
        return 0;
}

int bytes_is_zero(const uint8_t *input, int len)
{
    int i = 0;
    
    for(i = 0; i < len; i++)
    {
        if(input[i] != 0)
            return 0;
    }
    
    return 1;
}

unsigned char* sm2_kdf(unsigned char Z[ECC_BYTES * 2], int klen)
{
    int ct = 1;
    int ret;
    int i = 0;
    unsigned char* K = (unsigned char*)malloc(klen*(sizeof(unsigned char)));
    unsigned char H[SM3_DIGEST_LENGTH];
    unsigned char* temp = (unsigned char*)malloc((ECC_BYTES*2+4)*(sizeof(unsigned char)));
    
    memcpy(temp, Z, ECC_BYTES*2);
    for(i = 0; i < klen/SM3_DIGEST_LENGTH; i++)
    {
        memcpy(temp + ECC_BYTES*2, &ct, 4);
        ct++;
        ret = sm3_hash(temp, H, ECC_BYTES*2+4);
        if(ret == 0)
        {
            free(K);
            free(temp);
            return NULL;
        }
        memcpy(K+i*SM3_DIGEST_LENGTH, H, SM3_DIGEST_LENGTH);
    }
    if(klen % SM3_DIGEST_LENGTH != 0)
    {
        memcpy(temp + ECC_BYTES*2, &ct, 4);
        ret = sm3_hash(temp, H, ECC_BYTES*2+4);
        if(ret == 0)
        {
            free(K);
            free(temp);
            return NULL;
        }
        memcpy(K+i*SM3_DIGEST_LENGTH, H, klen % SM3_DIGEST_LENGTH);
    }
    
    free(temp);
    return K;
}


int sm2_sign(const uint8_t p_privateKey[ECC_BYTES], const uint8_t p_hash[ECC_BYTES], uint8_t p_signature[ECC_BYTES*2])
{
    byte tmpx[ECC_BYTES];
    byte tmpy[ECC_BYTES];
    byte tmp1[ECC_BYTES];
    byte K[ECC_BYTES];
    byte N[ECC_BYTES];
    uint64_t k[NUM_ECC_DIGITS];
    uint64_t n[NUM_ECC_DIGITS] = Curve_N_32;
    uint64_t l_tmp[NUM_ECC_DIGITS];
    uint64_t l_s[NUM_ECC_DIGITS];
    uint64_t _1[NUM_ECC_DIGITS] = {0x1};
    EccPoint p;
    EccPoint test;
    int i = 0;
    unsigned l_tries = 0;


    do
    {
        if(!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
        {
            return 0;
        }
        if(vli_isZero(k))
        {
            continue;
        }

        while(vli_cmp(curve_n, k) != 1)
        {
            vli_sub(k, k, curve_n);
        }

        /* tmp = k * G */
        ecc_native2bytes(tmpx,curve_G.x);
        ecc_native2bytes(tmpy,curve_G.y);
        ecc_native2bytes(tmp1, _1);
        ecc_native2bytes(K,k);
        if(DEBUG) {
            printf("随机数k的值：\n");
            for (i = 0; i < ECC_BYTES; i++) {
                printf("%2x ", K[i]);
            }
            printf("\n");
            printf("原来点的信息：\n");
            for (i = 0; i < ECC_BYTES; i++) {
                printf("%2x ", tmpx[i]);
            }
            printf("\n");
            for (i = 0; i < ECC_BYTES; i++) {
                printf("%2x ", tmpy[i]);
            }
            printf("\n");
        }
        EccPoint_mult(&test, &curve_G, n, NULL);
        EccPoint_mult(&p, &curve_G, k, NULL);
        ecc_native2bytes(tmpx,test.x);
        ecc_native2bytes(tmpy,test.y);

        if(DEBUG) {
            printf("倍乘过的点的信息：\n");
            for (i = 0; i < ECC_BYTES; i++) {
                printf("%2x ", tmpx[i]);
            }
            printf("\n");
            for (i = 0; i < ECC_BYTES; i++) {
                printf("%2x ", tmpy[i]);
            }
            printf("\n");
        }
        if(vli_isZero(p.x))
            continue;
        if(vli_cmp(curve_n, p.x) != 1)
        {
            vli_sub(p.x, p.x, curve_n);
        }

        /* r = (x1 + e)(mod n) */
        ecc_bytes2native(l_tmp, p_hash);
        vli_modAdd(p.x, p.x, l_tmp, curve_n);
        vli_add(l_tmp, p.x, k);
        if(vli_isZero(p.x) || vli_cmp(l_tmp, curve_n) == 0)
            continue;

        /* signature = r */
        ecc_native2bytes(p_signature, p.x);

        /* s = 1 / (1 + d)*/
        ecc_bytes2native(l_tmp, p_privateKey);
        vli_modAdd(l_s, _1, l_tmp, curve_n);
        vli_modInv(l_s, l_s, curve_n);

        /* k = k - r * d */
        vli_modMult(l_tmp, p.x, l_tmp, curve_n);
        vli_modSub(k, k, l_tmp, curve_n);

        /* s = s * k */
        vli_modMult(l_s, l_s, k, curve_n);
    } while(vli_isZero(l_s));

    /* signature = (r, s) */
    ecc_native2bytes(p_signature + ECC_BYTES, l_s);

    return 1;
}

int sm2_verify(const uint8_t p_publicKey_X[ECC_BYTES], const uint8_t p_publicKey_Y[ECC_BYTES], const uint8_t p_hash[ECC_BYTES], const uint8_t p_signature[ECC_BYTES*2])
{
//    uint64_t u1[NUM_ECC_DIGITS], u2[NUM_ECC_DIGITS];
    uint64_t e[NUM_ECC_DIGITS];
    uint64_t z[NUM_ECC_DIGITS];
    uint64_t R[NUM_ECC_DIGITS];
    EccPoint l_public, l_sum;
    uint64_t rx[NUM_ECC_DIGITS];
    uint64_t ry[NUM_ECC_DIGITS];
    uint64_t tx[NUM_ECC_DIGITS];
    uint64_t ty[NUM_ECC_DIGITS];
    uint64_t tz[NUM_ECC_DIGITS];

    uint64_t l_r[NUM_ECC_DIGITS], l_s[NUM_ECC_DIGITS], l_t[NUM_ECC_DIGITS];

//    ecc_point_decompress(&l_public, p_publicKey);
    ecc_bytes2native(l_public.x, p_publicKey_X);
    ecc_bytes2native(l_public.y, p_publicKey_Y);
    ecc_bytes2native(l_r, p_signature);
    ecc_bytes2native(l_s, p_signature + ECC_BYTES);

    if(vli_isZero(l_r) || vli_isZero(l_s))
    { /* r, s must not be 0. */
        return 0;
    }

    if(vli_cmp(curve_n, l_r) != 1 || vli_cmp(curve_n, l_s) != 1)
    { /* r, s must be < n. */
        return 0;
    }

    /* t = (r + s) mod n */
    vli_modAdd(l_t, l_r, l_s, curve_n);
    if(vli_isZero(l_t))
        return 0;

//    /* Calculate u1 and u2. */
//    vli_modInv(z, l_s, curve_n); /* Z = s^-1 */
//    ecc_bytes2native(u1, p_hash);
//    vli_modMult(u1, u1, z, curve_n); /* u1 = e/s */
//    vli_modMult(u2, l_r, z, curve_n); /* u2 = r/s */

    /* Calculate l_sum = G + Q. */
    vli_set(l_sum.x, l_public.x);
    vli_set(l_sum.y, l_public.y);
    vli_set(tx, curve_G.x);
    vli_set(ty, curve_G.y);
    vli_modSub(z, l_sum.x, tx, curve_p); /* Z = x2 - x1 */
    XYcZ_add(tx, ty, l_sum.x, l_sum.y);
    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(l_sum.x, l_sum.y, z);

    /* Use Shamir's trick to calculate s*G + t*Q */
    EccPoint *l_points[4] = {NULL, &curve_G, &l_public, &l_sum};
    uint l_numBits = umax(vli_numBits(l_s), vli_numBits(l_t));

    EccPoint *l_point = l_points[(!!vli_testBit(l_s, l_numBits-1)) | ((!!vli_testBit(l_t, l_numBits-1)) << 1)];
    vli_set(rx, l_point->x);
    vli_set(ry, l_point->y);
    vli_clear(z);
    z[0] = 1;

    int i;
    for(i = l_numBits - 2; i >= 0; --i)
    {
        EccPoint_double_jacobian(rx, ry, z);

        int l_index = (!!vli_testBit(l_s, i)) | ((!!vli_testBit(l_t, i)) << 1);
        EccPoint *l_point = l_points[l_index];
        if(l_point)
        {
            vli_set(tx, l_point->x);
            vli_set(ty, l_point->y);
            apply_z(tx, ty, z);
            vli_modSub(tz, rx, tx, curve_p); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry);
            vli_modMult_fast(z, z, tz);
        }
    }

    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(rx, ry, z);

    /* x1 = x1 (mod n) */
    while(vli_cmp(curve_n, rx) != 1)
    {
        vli_sub(rx, rx, curve_n);
    }

    /* R = (e + x1) mod n */
    ecc_bytes2native(e, p_hash);
    vli_modAdd(R, e, rx, curve_n);

    /* Accept only if R == r. */
    return (vli_cmp(R, l_r) == 0);
}

int sm2_encrypt(const uint8_t p_publicKey_X[ECC_BYTES], const uint8_t p_publicKey_Y[ECC_BYTES], const uint8_t *M, int klen, uint8_t *cypher)
{
    uint64_t k[NUM_ECC_DIGITS], pk_x[NUM_ECC_DIGITS], pk_y[NUM_ECC_DIGITS];
    uint8_t x1[ECC_BYTES], y1[ECC_BYTES], x2[ECC_BYTES], y2[ECC_BYTES], Z[ECC_BYTES*2], C3[SM3_DIGEST_LENGTH];
    EccPoint C1;
    EccPoint S;
    unsigned l_tries = 0;
    uint8_t *t;
    int i = 0;
    
    if(cypher == NULL)
        return 0;
    do
    {
        if(!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
        {
            return 0;
        }
        if(vli_isZero(k))
        {
            continue;
        }
        while(vli_cmp(curve_n, k) != 1)
        {
            vli_sub(k, k, curve_n);
        }
        
        EccPoint_mult(&C1, &curve_G, k, NULL);   //C1
        ecc_native2bytes(x1, C1.x);
        ecc_native2bytes(y1, C1.y);

        ecc_bytes2native(pk_x, p_publicKey_X);
        ecc_bytes2native(pk_y, p_publicKey_Y);
        vli_set(S.x, pk_x);
        vli_set(S.y, pk_y);
        if(EccPoint_isZero(&S) == 1)
        {
            return 0;
        }
        EccPoint_mult(&S, &S, k, NULL);     //[k]Pb
        ecc_native2bytes(x2, S.x);
        ecc_native2bytes(y2, S.y);
        memcpy(Z, x2, ECC_BYTES);
        memcpy(Z+ECC_BYTES, y2, ECC_BYTES);
        t = sm2_kdf(Z, klen);               //t = KDF(x2||y2, klen)
        if(t == NULL)
            return 0;
        }
    while(bytes_is_zero(t, klen) == 1);

    uint8_t *C2 = (uint8_t*)malloc(sizeof(uint8_t) * klen);
    uint8_t *H = (uint8_t*)malloc(sizeof(uint8_t) * (ECC_BYTES*2+klen));

    for(i = 0; i < klen; i++)
    {
        C2[i] = t[i] ^ M[i];
    }
    memcpy(H, x2, ECC_BYTES);
    memcpy(H+ECC_BYTES, M, klen);
    memcpy(H+ECC_BYTES+klen, y2, ECC_BYTES);
    sm3_hash(H, C3, ECC_BYTES*2+klen);
    
    memcpy(cypher, x1, ECC_BYTES);
    memcpy(cypher+ECC_BYTES, y1, ECC_BYTES);
    memcpy(cypher+ECC_BYTES*2, C2, klen);
    memcpy(cypher+ECC_BYTES*2+klen, C3, SM3_DIGEST_LENGTH);
    
    free(C2);
    free(H);
    free(t);
    return 1;
}
int sm2_decrypt(const uint8_t p_privateKey[ECC_BYTES], const uint8_t *cypher, int klen, uint8_t *plain)
{
    EccPoint C1;
    EccPoint S;
    uint64_t d[NUM_ECC_DIGITS];
    uint8_t x2[ECC_BYTES], y2[ECC_BYTES], u[SM3_DIGEST_LENGTH], C3[SM3_DIGEST_LENGTH], Z[ECC_BYTES*2];
    uint8_t *t = NULL, *H = NULL, *C2 = cypher + ECC_BYTES*2;
    int i = 0;
    
    if(plain == NULL)
        return 0;
    ecc_bytes2native(C1.x, cypher);
    ecc_bytes2native(C1.y, cypher+ECC_BYTES);
    if(ECC_check_point(&C1) == 0 || EccPoint_isZero(&C1) == 1)
        return 0;
    ecc_bytes2native(d, p_privateKey);
    EccPoint_mult(&S, &C1, d, NULL);
    ecc_native2bytes(x2, S.x);
    ecc_native2bytes(y2, S.y);
    memcpy(Z, x2, ECC_BYTES);
    memcpy(Z+ECC_BYTES, y2, ECC_BYTES);
    t = sm2_kdf(Z, klen);
    if(t == NULL)
        return 0;
    if(bytes_is_zero(t, klen))
    {
        free(t);
        return 0;
    }
    
    for(i = 0; i < klen; i++)
    {
        plain[i] = C2[i]^t[i];
    }
    
    H = (uint8_t*)malloc(sizeof(ECC_BYTES*2+klen));
    memcpy(H, x2, ECC_BYTES);
    memcpy(H+ECC_BYTES, plain, klen);
    memcpy(H+ECC_BYTES+klen, y2, ECC_BYTES);
    sm3_hash(H, u, ECC_BYTES*2+klen);
    
    memcpy(C3, cypher+ECC_BYTES*2+klen, SM3_DIGEST_LENGTH);
    for(i = 0; i < SM3_DIGEST_LENGTH; i++)
    {
        if(u[i] != C3[i])
        {
            free(t);
            free(H);
            return 0;
        }
    }
    free(t);
    free(H);
    return 1;
}

void test1(){
    byte p_privateKey[ECC_BYTES];
    byte p_hash[ECC_BYTES];
    byte p_publicKey_X[ECC_BYTES], p_publicKey_Y[ECC_BYTES];
    byte p_signature[ECC_BYTES * 2];
    byte *cypher = (byte*)malloc(sizeof(byte)*(ECC_BYTES*2+10+SM3_DIGEST_LENGTH));
    byte plain[10];

    int i = 0;
    for(i=0;i<ECC_BYTES;i++){
        p_hash[i] = 1;
    }

    sm2_make_key(p_privateKey, p_publicKey_X, p_publicKey_Y);
    
    

    if(sm2_encrypt(p_publicKey_X, p_publicKey_Y, (byte*)"1234567890", 10, cypher) == 1);
    printf("cypher:%s\n", cypher);
    if(sm2_decrypt(p_privateKey, cypher, 10, plain) == 1) {

        for (i = 0; i < 10; i++) {
            printf("%d ", plain[i]);
        }
    }
    else
        printf("解密错误！");
    printf("\n");
    
//    sm2_sign(p_privateKey, p_hash, p_signature);
//    printf("%d\n", sm2_verify(p_publicKey,p_hash,p_signature));
}
