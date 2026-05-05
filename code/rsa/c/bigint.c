#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Simple fixed-size unsigned big integers.
 *
 * Representation:
 * - BIGINT_BITS is configurable at compile time: -DBIGINT_BITS=512, for example.
 * - Each integer is stored as 32-bit words.
 * - The words are little-endian: word[0] contains the least significant bits.
 * - uint32_t limbs are used so a limb multiplication fits cleanly in uint64_t.
 */
#ifndef BIGINT_BITS
#define BIGINT_BITS 256
#endif

#define LIMB_BITS 32u
#define BIGINT_WORDS (BIGINT_BITS / LIMB_BITS)

#if BIGINT_BITS < 64 || (BIGINT_BITS % LIMB_BITS) != 0
#error "BIGINT_BITS must be a multiple of 32 and at least 64"
#endif

typedef struct {
    uint32_t word[BIGINT_WORDS];
} BigInt;

typedef struct {
    uint32_t word[2 * BIGINT_WORDS];
} BigIntWide;

static void bigint_zero(BigInt *x)
{
    memset(x, 0, sizeof(*x));
}

static int bigint_is_zero(const BigInt *x)
{
    size_t i;
    for (i = 0; i < BIGINT_WORDS; ++i) {
        if (x->word[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void bigint_from_u64(BigInt *x, uint64_t value)
{
    bigint_zero(x);
    x->word[0] = (uint32_t)value;
    if (BIGINT_WORDS > 1) {
        x->word[1] = (uint32_t)(value >> 32);
    }
}

static int bigint_cmp(const BigInt *a, const BigInt *b)
{
    size_t i;
    for (i = BIGINT_WORDS; i-- > 0;) {
        if (a->word[i] < b->word[i]) {
            return -1;
        }
        if (a->word[i] > b->word[i]) {
            return 1;
        }
    }
    return 0;
}

static int bigint_add(BigInt *result, const BigInt *a, const BigInt *b)
{
    uint64_t carry = 0;
    size_t i;

    for (i = 0; i < BIGINT_WORDS; ++i) {
        uint64_t sum = (uint64_t)a->word[i] + b->word[i] + carry;
        result->word[i] = (uint32_t)sum;
        carry = sum >> LIMB_BITS;
    }

    return carry != 0;
}

static uint32_t bigint_sub_assign(BigInt *a, const BigInt *b)
{
    uint64_t borrow = 0;
    size_t i;

    for (i = 0; i < BIGINT_WORDS; ++i) {
        uint64_t sub = (uint64_t)b->word[i] + borrow;
        borrow = (a->word[i] < sub);
        a->word[i] = (uint32_t)((uint64_t)a->word[i] - sub);
    }

    return (uint32_t)borrow;
}

static uint32_t bigint_shift_left1(BigInt *x)
{
    uint32_t carry = 0;
    size_t i;

    for (i = 0; i < BIGINT_WORDS; ++i) {
        uint32_t next_carry = x->word[i] >> 31;
        x->word[i] = (x->word[i] << 1) | carry;
        carry = next_carry;
    }

    return carry;
}

static int bigint_get_bit(const BigInt *x, size_t bit)
{
    return (int)((x->word[bit / LIMB_BITS] >> (bit % LIMB_BITS)) & 1u);
}

static int bigint_wide_get_bit(const BigIntWide *x, size_t bit)
{
    return (int)((x->word[bit / LIMB_BITS] >> (bit % LIMB_BITS)) & 1u);
}

static int bigint_mul_small(BigInt *x, uint32_t factor)
{
    uint64_t carry = 0;
    size_t i;

    for (i = 0; i < BIGINT_WORDS; ++i) {
        uint64_t product = (uint64_t)x->word[i] * factor + carry;
        x->word[i] = (uint32_t)product;
        carry = product >> LIMB_BITS;
    }

    return carry != 0;
}

static int bigint_add_small(BigInt *x, uint32_t value)
{
    uint64_t carry = value;
    size_t i;

    for (i = 0; i < BIGINT_WORDS && carry != 0; ++i) {
        uint64_t sum = (uint64_t)x->word[i] + carry;
        x->word[i] = (uint32_t)sum;
        carry = sum >> LIMB_BITS;
    }

    return carry != 0;
}

/* Returns 0 on success, -1 on invalid input, -2 on overflow. */
static int bigint_from_string(BigInt *x, const char *text)
{
    int overflow = 0;
    int saw_digit = 0;

    bigint_zero(x);
    while (isspace((unsigned char)*text)) {
        ++text;
    }
    if (*text == '+') {
        ++text;
    }

    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text += 2;
        while (isxdigit((unsigned char)*text)) {
            int value;
            if (*text >= '0' && *text <= '9') {
                value = *text - '0';
            } else if (*text >= 'a' && *text <= 'f') {
                value = *text - 'a' + 10;
            } else {
                value = *text - 'A' + 10;
            }
            overflow |= bigint_mul_small(x, 16);
            overflow |= bigint_add_small(x, (uint32_t)value);
            saw_digit = 1;
            ++text;
        }
    } else {
        while (isdigit((unsigned char)*text)) {
            overflow |= bigint_mul_small(x, 10);
            overflow |= bigint_add_small(x, (uint32_t)(*text - '0'));
            saw_digit = 1;
            ++text;
        }
    }

    while (isspace((unsigned char)*text)) {
        ++text;
    }
    if (!saw_digit || *text != '\0') {
        return -1;
    }
    return overflow ? -2 : 0;
}

static uint32_t bigint_div_small(BigInt *x, uint32_t divisor)
{
    uint64_t remainder = 0;
    size_t i;

    for (i = BIGINT_WORDS; i-- > 0;) {
        uint64_t current = (remainder << LIMB_BITS) | x->word[i];
        x->word[i] = (uint32_t)(current / divisor);
        remainder = current % divisor;
    }

    return (uint32_t)remainder;
}

static void bigint_print_dec(const BigInt *x)
{
    BigInt tmp = *x;
    char digits[BIGINT_BITS / 3 + 4];
    size_t count = 0;

    if (bigint_is_zero(&tmp)) {
        putchar('0');
        return;
    }

    while (!bigint_is_zero(&tmp)) {
        digits[count++] = (char)('0' + bigint_div_small(&tmp, 10));
    }
    while (count > 0) {
        putchar(digits[--count]);
    }
}

static void bigint_mul_wide(BigIntWide *result, const BigInt *a, const BigInt *b)
{
    size_t i, j;
    memset(result, 0, sizeof(*result));

    for (i = 0; i < BIGINT_WORDS; ++i) {
        uint64_t carry = 0;
        for (j = 0; j < BIGINT_WORDS; ++j) {
            uint64_t sum = (uint64_t)a->word[i] * b->word[j]
                         + result->word[i + j]
                         + carry;
            result->word[i + j] = (uint32_t)sum;
            carry = sum >> LIMB_BITS;
        }
        j = i + BIGINT_WORDS;
        while (carry != 0 && j < 2 * BIGINT_WORDS) {
            uint64_t sum = (uint64_t)result->word[j] + carry;
            result->word[j] = (uint32_t)sum;
            carry = sum >> LIMB_BITS;
            ++j;
        }
    }
}

static int bigint_mul(BigInt *result, const BigInt *a, const BigInt *b)
{
    BigIntWide wide;
    size_t i;
    int overflow = 0;

    bigint_mul_wide(&wide, a, b);
    for (i = 0; i < BIGINT_WORDS; ++i) {
        result->word[i] = wide.word[i];
    }
    for (i = BIGINT_WORDS; i < 2 * BIGINT_WORDS; ++i) {
        overflow |= (wide.word[i] != 0);
    }

    return overflow;
}

static int bigint_mod(BigInt *result, const BigInt *a, const BigInt *modulus)
{
    BigInt remainder;
    size_t bit;

    if (bigint_is_zero(modulus)) {
        return -1;
    }

    bigint_zero(&remainder);
    for (bit = BIGINT_BITS; bit-- > 0;) {
        uint32_t carry = bigint_shift_left1(&remainder);
        remainder.word[0] |= (uint32_t)bigint_get_bit(a, bit);
        if (carry || bigint_cmp(&remainder, modulus) >= 0) {
            bigint_sub_assign(&remainder, modulus);
        }
    }

    *result = remainder;
    return 0;
}

static int bigint_mod_wide(BigInt *result, const BigIntWide *a, const BigInt *modulus)
{
    BigInt remainder;
    size_t bit;

    if (bigint_is_zero(modulus)) {
        return -1;
    }

    bigint_zero(&remainder);
    for (bit = 2 * BIGINT_BITS; bit-- > 0;) {
        uint32_t carry = bigint_shift_left1(&remainder);
        remainder.word[0] |= (uint32_t)bigint_wide_get_bit(a, bit);
        if (carry || bigint_cmp(&remainder, modulus) >= 0) {
            bigint_sub_assign(&remainder, modulus);
        }
    }

    *result = remainder;
    return 0;
}

static int bigint_mul_mod(BigInt *result, const BigInt *a, const BigInt *b,
                          const BigInt *modulus)
{
    BigIntWide product;

    bigint_mul_wide(&product, a, b);
    return bigint_mod_wide(result, &product, modulus);
}

int main(void)
{
    BigInt a, b, m, sum, product, reduced, mod_product;
    int add_overflow, mul_overflow;

    if (bigint_from_string(&a, "340282366920938463463374607431768211455") != 0 ||
        bigint_from_string(&b, "12345678901234567890") != 0 ||
        bigint_from_string(&m, "100000000000000000000000000000000000003") != 0) {
        fprintf(stderr, "Invalid test value for BIGINT_BITS=%d\n", BIGINT_BITS);
        return 1;
    }

    add_overflow = bigint_add(&sum, &a, &b);
    mul_overflow = bigint_mul(&product, &a, &b);

    if (bigint_mod(&reduced, &a, &m) != 0 ||
        bigint_mul_mod(&mod_product, &a, &b, &m) != 0) {
        fprintf(stderr, "Modulo by zero\n");
        return 1;
    }

    printf("BIGINT_BITS = %d\n", BIGINT_BITS);

    printf("a        = ");
    bigint_print_dec(&a);
    printf("\n");

    printf("b        = ");
    bigint_print_dec(&b);
    printf("\n");

    printf("m        = ");
    bigint_print_dec(&m);
    printf("\n");

    printf("a + b    = ");
    bigint_print_dec(&sum);
    printf("%s\n", add_overflow ? "  (overflow)" : "");

    printf("a * b    = ");
    bigint_print_dec(&product);
    printf("%s\n", mul_overflow ? "  (low bits, overflow)" : "");

    printf("a %% m    = ");
    bigint_print_dec(&reduced);
    printf("\n");

    printf("(a*b)%%m  = ");
    bigint_print_dec(&mod_product);
    printf("\n");

    bigint_from_u64(&a, UINT64_C(123456789));
    printf("from u64 = ");
    bigint_print_dec(&a);
    printf("\n");

    return 0;
}
