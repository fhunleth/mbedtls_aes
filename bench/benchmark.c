/*
 * SPDX-FileCopyrightText: Frank Hunleth
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * AES benchmark
 *
 * Verify that the amalgamated mbedtls_aes works and compare its performance
 * to tiny-AES-c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "tiny-AES-c/aes.h"
#include "mbedtls_aes.h"

#define BUFFER_SIZE   (100 * 1024 * 1024)
#define AES_KEYBITS   256
#define AES_KEYBYTES  (AES_KEYBITS / 8)  /* tiny-AES-c's aes.h already defines AES_KEYLEN */
#define AES_BLOCK     16

static double benchmark_runtime_seconds = 3.0;

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---------- Benchmark framework ---------- */

typedef struct {
    const char *name;
    void *(*setup)(const uint8_t key[AES_KEYBYTES]);
    void  (*encrypt)(void *ctx, const uint8_t iv[AES_BLOCK], uint8_t *buf, size_t len);
    void  (*decrypt)(void *ctx, const uint8_t iv[AES_BLOCK], uint8_t *buf, size_t len);
    void  (*teardown)(void *ctx);
} backend_t;

static void run_benchmark(const backend_t *be, const uint8_t key[AES_KEYBYTES],
                          const uint8_t iv[AES_BLOCK], uint8_t *buf)
{
    printf("--- %s ---\n", be->name);

    void *ctx = be->setup(key);
    if (!ctx) {
        printf("  setup failed\n\n");
        return;
    }

    size_t iters = 0;
    double t0 = now_seconds();
    double t;
    do {
        be->encrypt(ctx, iv, buf, BUFFER_SIZE);
        iters++;
        t = now_seconds();
    } while (t - t0 < benchmark_runtime_seconds);
    double enc_elapsed = t - t0;
    double enc_bytes = (double)iters * (double)BUFFER_SIZE;
    printf("  encrypt: %zu x %d MB in %.3f s -> %7.2f MB/s\n",
           iters, BUFFER_SIZE / (1024 * 1024), enc_elapsed,
           enc_bytes / (1024.0 * 1024.0) / enc_elapsed);

    iters = 0;
    t0 = now_seconds();
    do {
        be->decrypt(ctx, iv, buf, BUFFER_SIZE);
        iters++;
        t = now_seconds();
    } while (t - t0 < benchmark_runtime_seconds);
    double dec_elapsed = t - t0;
    double dec_bytes = (double)iters * (double)BUFFER_SIZE;
    printf("  decrypt: %zu x %d MB in %.3f s -> %7.2f MB/s\n\n",
           iters, BUFFER_SIZE / (1024 * 1024), dec_elapsed,
           dec_bytes / (1024.0 * 1024.0) / dec_elapsed);

    be->teardown(ctx);
}

/* ---------- tiny-AES-c backend ---------- */

static void *tiny_setup(const uint8_t key[AES_KEYBYTES])
{
    struct AES_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx) return NULL;
    AES_init_ctx(ctx, key);
    return ctx;
}

static void tiny_encrypt(void *ctx_, const uint8_t iv[AES_BLOCK], uint8_t *buf, size_t len)
{
    struct AES_ctx *ctx = ctx_;
    AES_ctx_set_iv(ctx, iv);
    AES_CBC_encrypt_buffer(ctx, buf, (uint32_t)len);
}

static void tiny_decrypt(void *ctx_, const uint8_t iv[AES_BLOCK], uint8_t *buf, size_t len)
{
    struct AES_ctx *ctx = ctx_;
    AES_ctx_set_iv(ctx, iv);
    AES_CBC_decrypt_buffer(ctx, buf, (uint32_t)len);
}

static void tiny_teardown(void *ctx) { free(ctx); }

/* ---------- mbedtls_aes default backend ---------- */

typedef struct {
    mbedtls_aes_context enc;
    mbedtls_aes_context dec;
} mbed_ctx_t;

static void *mbed_setup(const uint8_t key[AES_KEYBYTES])
{
    mbed_ctx_t *c = malloc(sizeof(*c));
    if (!c) return NULL;
    mbedtls_aes_init(&c->enc);
    mbedtls_aes_init(&c->dec);
    if (mbedtls_aes_setkey_enc(&c->enc, key, AES_KEYBITS) != 0 ||
        mbedtls_aes_setkey_dec(&c->dec, key, AES_KEYBITS) != 0) {
        free(c);
        return NULL;
    }
    return c;
}

static void mbed_encrypt(void *ctx_, const uint8_t iv_in[AES_BLOCK], uint8_t *buf, size_t len)
{
    mbed_ctx_t *c = ctx_;
    uint8_t iv[AES_BLOCK];
    memcpy(iv, iv_in, AES_BLOCK);
    mbedtls_aes_crypt_cbc(&c->enc, MBEDTLS_AES_ENCRYPT, len, iv, buf, buf);
}

static void mbed_decrypt(void *ctx_, const uint8_t iv_in[AES_BLOCK], uint8_t *buf, size_t len)
{
    mbed_ctx_t *c = ctx_;
    uint8_t iv[AES_BLOCK];
    memcpy(iv, iv_in, AES_BLOCK);
    mbedtls_aes_crypt_cbc(&c->dec, MBEDTLS_AES_DECRYPT, len, iv, buf, buf);
}

static void mbed_teardown(void *ctx_)
{
    mbed_ctx_t *c = ctx_;
    mbedtls_aes_free(&c->enc);
    mbedtls_aes_free(&c->dec);
    free(c);
}

/* ---------- Correctness checks ---------- */

/* NIST SP 800-38A Appendix F.2 — shared IV and plaintext across F.2.1/2/5/6. */
static const uint8_t nist_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t nist_plain[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/* F.2.1 / F.2.2 — AES-128-CBC. */
static const uint8_t nist128_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
static const uint8_t nist128_cbc_cipher[64] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
    0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
    0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
};

/* F.2.3 / F.2.4 — AES-192-CBC. */
static const uint8_t nist192_key[24] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};
static const uint8_t nist192_cbc_cipher[64] = {
    0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
    0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
    0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
    0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
    0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
    0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
    0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
    0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd,
};

/* F.2.5 / F.2.6 — AES-256-CBC. */
static const uint8_t nist256_key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static const uint8_t nist256_cbc_cipher[64] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
    0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
    0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
    0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
};

/* F.1.5 / F.1.6 — AES-256-ECB (no IV). */
static const uint8_t nist256_ecb_cipher[64] = {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
    0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
    0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
    0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
    0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
    0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
    0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7,
};

/* F.3.13 / F.3.14 — AES-256-CFB128. */
static const uint8_t nist256_cfb_cipher[64] = {
    0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
    0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
    0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8,
    0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
    0xdf, 0x10, 0x13, 0x24, 0x15, 0xe5, 0x4b, 0x92,
    0xa1, 0x3e, 0xd0, 0xa8, 0x26, 0x7a, 0xe2, 0xf9,
    0x75, 0xa3, 0x85, 0x74, 0x1a, 0xb9, 0xce, 0xf8,
    0x20, 0x31, 0x62, 0x3d, 0x55, 0xb1, 0xe4, 0x71,
};

/* F.4.5 / F.4.6 — AES-256-OFB. */
static const uint8_t nist256_ofb_cipher[64] = {
    0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
    0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
    0x4f, 0xeb, 0xdc, 0x67, 0x40, 0xd2, 0x0b, 0x3a,
    0xc8, 0x8f, 0x6a, 0xd8, 0x2a, 0x4f, 0xb0, 0x8d,
    0x71, 0xab, 0x47, 0xa0, 0x86, 0xe8, 0x6e, 0xed,
    0xf3, 0x9d, 0x1c, 0x5b, 0xba, 0x97, 0xc4, 0x08,
    0x01, 0x26, 0x14, 0x1d, 0x67, 0xf3, 0x7b, 0xe8,
    0x53, 0x8f, 0x5a, 0x8b, 0xe7, 0x40, 0xe4, 0x84,
};

/* F.5.5 / F.5.6 — AES-256-CTR. Initial counter block differs from nist_iv. */
static const uint8_t nist_ctr_iv[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const uint8_t nist256_ctr_cipher[64] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
    0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
    0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
    0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
    0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
    0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
    0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
    0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
};

/* IEEE 1619 (XTS-AES) test vectors, taken verbatim from upstream
 * TF-PSA-Crypto/tests/suites/test_suite_aes.xts.data. Stored as hex so the
 * strings can be pasted back if they ever need reverification. */

/* Vector 1 — AES-128-XTS, 32-byte data unit, all zero. */
static const char xts_v1_key[] =
    "00000000000000000000000000000000"
    "00000000000000000000000000000000";
static const char xts_v1_du[]  = "00000000000000000000000000000000";
static const char xts_v1_pt[]  =
    "00000000000000000000000000000000"
    "00000000000000000000000000000000";
static const char xts_v1_ct[]  =
    "917cf69ebd68b2ec9b9fe9a3eadda692"
    "cd43d2f59598ed858c02c2652fbf922e";

/* Vector 2 — AES-128-XTS, 32-byte data unit, non-trivial key and tweak. */
static const char xts_v2_key[] =
    "11111111111111111111111111111111"
    "22222222222222222222222222222222";
static const char xts_v2_du[]  = "33333333330000000000000000000000";
static const char xts_v2_pt[]  =
    "44444444444444444444444444444444"
    "44444444444444444444444444444444";
static const char xts_v2_ct[]  =
    "c454185e6a16936e39334038acef838b"
    "fb186fff7480adc4289382ecd6d394f0";

/* Vector 10 — AES-256-XTS, 512-byte data unit. The only AES-256-XTS vector
 * size upstream supplies; large but that is what IEEE 1619 specifies. */
static const char xts_v10_key[] =
    "27182818284590452353602874713526"
    "62497757247093699959574966967627"
    "31415926535897932384626433832795"
    "02884197169399375105820974944592";
static const char xts_v10_du[] = "ff000000000000000000000000000000";
static const char xts_v10_pt[] =
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f"
    "707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f"
    "707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
static const char xts_v10_ct[] =
    "1c3b3a102f770386e4836c99e370cf9b"
    "ea00803f5e482357a4ae12d414a3e63b"
    "5d31e276f8fe4a8d66b317f9ac683f44"
    "680a86ac35adfc3345befecb4bb188fd"
    "5776926c49a3095eb108fd1098baec70"
    "aaa66999a72a82f27d848b21d4a741b0"
    "c5cd4d5fff9dac89aeba122961d03a75"
    "7123e9870f8acf1000020887891429ca"
    "2a3e7a7d7df7b10355165c8b9a6d0a7d"
    "e8b062c4500dc4cd120c0f7418dae3d0"
    "b5781c34803fa75421c790dfe1de1834"
    "f280d7667b327f6c8cd7557e12ac3a0f"
    "93ec05c52e0493ef31a12d3d9260f79a"
    "289d6a379bc70c50841473d1a8cc81ec"
    "583e9645e07b8d9670655ba5bbcfecc6"
    "dc3966380ad8fecb17b6ba02469a020a"
    "84e18e8f84252070c13e9f1f289be54f"
    "bc481457778f616015e1327a02b140f1"
    "505eb309326d68378f8374595c849d84"
    "f4c333ec4423885143cb47bd71c5edae"
    "9be69a2ffeceb1bec9de244fbe15992b"
    "11b77c040f12bd8f6a975a44a0f90c29"
    "a9abc3d4d893927284c58754cce29452"
    "9f8614dcd2aba991925fedc4ae74ffac"
    "6e333b93eb4aff0479da9a410e4450e0"
    "dd7ae4c6e2910900575da401fc07059f"
    "645e8b7e9bfdef33943054ff84011493"
    "c27b3429eaedb4ed5376441a77ed4385"
    "1ad77f16f541dfd269d50d6a5f14fb0a"
    "ab1cbb4c1550be97f7ab4066193c4caa"
    "773dad38014bd2092fa755c824bb5e54"
    "c4f36ffda9fcea70b9c6e693e148c151";

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        char c1 = hex[2 * i], c2 = hex[2 * i + 1];
        int n1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' :
                 (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 :
                 (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
        int n2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' :
                 (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 :
                 (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
        if (n1 < 0 || n2 < 0) return -1;
        out[i] = (uint8_t)((n1 << 4) | n2);
    }
    return 0;
}

/* keybits is the combined XTS key length: 256 for AES-128-XTS, 512 for AES-256-XTS. */
static int check_mbed_xts(const char *label, unsigned int keybits,
                          const char *key_hex, const char *du_hex,
                          const char *pt_hex, const char *ct_hex, size_t n)
{
    uint8_t key[64], du[AES_BLOCK];
    uint8_t pt[512], ct[512], buf[512];
    mbedtls_aes_xts_context enc, dec;
    int rv = -1;

    if (n > sizeof(pt)) return -1;
    if (hex_to_bytes(key_hex, key, keybits / 8) != 0 ||
        hex_to_bytes(du_hex,  du,  AES_BLOCK)   != 0 ||
        hex_to_bytes(pt_hex,  pt,  n)           != 0 ||
        hex_to_bytes(ct_hex,  ct,  n)           != 0) {
        printf("%s: hex decode failed\n", label);
        return -1;
    }

    mbedtls_aes_xts_init(&enc);
    mbedtls_aes_xts_init(&dec);
    if (mbedtls_aes_xts_setkey_enc(&enc, key, keybits) != 0 ||
        mbedtls_aes_xts_setkey_dec(&dec, key, keybits) != 0) {
        printf("%s: setkey failed\n", label);
        goto done;
    }

    mbedtls_aes_crypt_xts(&enc, MBEDTLS_AES_ENCRYPT, n, du, pt, buf);
    if (memcmp(buf, ct, n) != 0) {
        printf("%s: encrypt does not match IEEE 1619 vector\n", label);
        goto done;
    }

    mbedtls_aes_crypt_xts(&dec, MBEDTLS_AES_DECRYPT, n, du, ct, buf);
    if (memcmp(buf, pt, n) != 0) {
        printf("%s: decrypt does not match IEEE 1619 vector\n", label);
        goto done;
    }
    rv = 0;
done:
    mbedtls_aes_xts_free(&enc);
    mbedtls_aes_xts_free(&dec);
    return rv;
}

static int check_mbed_cbc(const char *label, unsigned int keybits,
                          const uint8_t *key, const uint8_t *iv,
                          const uint8_t *pt, const uint8_t *ct, size_t n)
{
    mbedtls_aes_context enc, dec;
    uint8_t buf[64];
    uint8_t iv_copy[AES_BLOCK];
    int rv = -1;

    mbedtls_aes_init(&enc);
    mbedtls_aes_init(&dec);
    if (mbedtls_aes_setkey_enc(&enc, key, keybits) != 0 ||
        mbedtls_aes_setkey_dec(&dec, key, keybits) != 0) {
        printf("%s: setkey failed\n", label);
        goto done;
    }

    memcpy(buf, pt, n);
    memcpy(iv_copy, iv, AES_BLOCK);
    mbedtls_aes_crypt_cbc(&enc, MBEDTLS_AES_ENCRYPT, n, iv_copy, buf, buf);
    if (memcmp(buf, ct, n) != 0) {
        printf("%s: encrypt does not match NIST vector\n", label);
        goto done;
    }

    memcpy(buf, ct, n);
    memcpy(iv_copy, iv, AES_BLOCK);
    mbedtls_aes_crypt_cbc(&dec, MBEDTLS_AES_DECRYPT, n, iv_copy, buf, buf);
    if (memcmp(buf, pt, n) != 0) {
        printf("%s: decrypt does not match NIST vector\n", label);
        goto done;
    }
    rv = 0;
done:
    mbedtls_aes_free(&enc);
    mbedtls_aes_free(&dec);
    return rv;
}

static int check_mbed_ecb(const char *label, unsigned int keybits,
                          const uint8_t *key, const uint8_t *pt,
                          const uint8_t *ct, size_t n)
{
    mbedtls_aes_context enc, dec;
    uint8_t buf[64];
    int rv = -1;

    mbedtls_aes_init(&enc);
    mbedtls_aes_init(&dec);
    if (mbedtls_aes_setkey_enc(&enc, key, keybits) != 0 ||
        mbedtls_aes_setkey_dec(&dec, key, keybits) != 0) {
        printf("%s: setkey failed\n", label);
        goto done;
    }

    for (size_t i = 0; i < n; i += AES_BLOCK) {
        mbedtls_aes_crypt_ecb(&enc, MBEDTLS_AES_ENCRYPT, pt + i, buf + i);
    }
    if (memcmp(buf, ct, n) != 0) {
        printf("%s: encrypt does not match NIST vector\n", label);
        goto done;
    }

    for (size_t i = 0; i < n; i += AES_BLOCK) {
        mbedtls_aes_crypt_ecb(&dec, MBEDTLS_AES_DECRYPT, ct + i, buf + i);
    }
    if (memcmp(buf, pt, n) != 0) {
        printf("%s: decrypt does not match NIST vector\n", label);
        goto done;
    }
    rv = 0;
done:
    mbedtls_aes_free(&enc);
    mbedtls_aes_free(&dec);
    return rv;
}

static int check_mbed_cfb128(const char *label, unsigned int keybits,
                             const uint8_t *key, const uint8_t *iv,
                             const uint8_t *pt, const uint8_t *ct, size_t n)
{
    /* CFB uses the encrypt key for both directions. */
    mbedtls_aes_context ctx;
    uint8_t buf[64];
    uint8_t iv_copy[AES_BLOCK];
    size_t iv_off;
    int rv = -1;

    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, keybits) != 0) {
        printf("%s: setkey failed\n", label);
        goto done;
    }

    iv_off = 0;
    memcpy(iv_copy, iv, AES_BLOCK);
    mbedtls_aes_crypt_cfb128(&ctx, MBEDTLS_AES_ENCRYPT, n, &iv_off,
                             iv_copy, pt, buf);
    if (memcmp(buf, ct, n) != 0) {
        printf("%s: encrypt does not match NIST vector\n", label);
        goto done;
    }

    iv_off = 0;
    memcpy(iv_copy, iv, AES_BLOCK);
    mbedtls_aes_crypt_cfb128(&ctx, MBEDTLS_AES_DECRYPT, n, &iv_off,
                             iv_copy, ct, buf);
    if (memcmp(buf, pt, n) != 0) {
        printf("%s: decrypt does not match NIST vector\n", label);
        goto done;
    }
    rv = 0;
done:
    mbedtls_aes_free(&ctx);
    return rv;
}

static int check_mbed_ofb(const char *label, unsigned int keybits,
                          const uint8_t *key, const uint8_t *iv,
                          const uint8_t *pt, const uint8_t *ct, size_t n)
{
    /* OFB is symmetric: the same call encrypts and decrypts. */
    mbedtls_aes_context ctx;
    uint8_t buf[64];
    uint8_t iv_copy[AES_BLOCK];
    size_t iv_off;
    int rv = -1;

    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, keybits) != 0) {
        printf("%s: setkey failed\n", label);
        goto done;
    }

    iv_off = 0;
    memcpy(iv_copy, iv, AES_BLOCK);
    mbedtls_aes_crypt_ofb(&ctx, n, &iv_off, iv_copy, pt, buf);
    if (memcmp(buf, ct, n) != 0) {
        printf("%s: encrypt does not match NIST vector\n", label);
        goto done;
    }

    iv_off = 0;
    memcpy(iv_copy, iv, AES_BLOCK);
    mbedtls_aes_crypt_ofb(&ctx, n, &iv_off, iv_copy, ct, buf);
    if (memcmp(buf, pt, n) != 0) {
        printf("%s: decrypt does not match NIST vector\n", label);
        goto done;
    }
    rv = 0;
done:
    mbedtls_aes_free(&ctx);
    return rv;
}

static int check_mbed_ctr(const char *label, unsigned int keybits,
                          const uint8_t *key, const uint8_t *counter0,
                          const uint8_t *pt, const uint8_t *ct, size_t n)
{
    /* CTR is symmetric. */
    mbedtls_aes_context ctx;
    uint8_t buf[64];
    uint8_t nonce_counter[AES_BLOCK];
    uint8_t stream_block[AES_BLOCK];
    size_t nc_off;
    int rv = -1;

    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, keybits) != 0) {
        printf("%s: setkey failed\n", label);
        goto done;
    }

    nc_off = 0;
    memcpy(nonce_counter, counter0, AES_BLOCK);
    mbedtls_aes_crypt_ctr(&ctx, n, &nc_off, nonce_counter, stream_block, pt, buf);
    if (memcmp(buf, ct, n) != 0) {
        printf("%s: encrypt does not match NIST vector\n", label);
        goto done;
    }

    nc_off = 0;
    memcpy(nonce_counter, counter0, AES_BLOCK);
    mbedtls_aes_crypt_ctr(&ctx, n, &nc_off, nonce_counter, stream_block, ct, buf);
    if (memcmp(buf, pt, n) != 0) {
        printf("%s: decrypt does not match NIST vector\n", label);
        goto done;
    }
    rv = 0;
done:
    mbedtls_aes_free(&ctx);
    return rv;
}

static int check_tiny_vector(const char *label,
                             const uint8_t *key, const uint8_t *iv,
                             const uint8_t *pt, const uint8_t *ct, size_t n)
{
    struct AES_ctx ctx;
    uint8_t buf[64];

    AES_init_ctx_iv(&ctx, key, iv);
    memcpy(buf, pt, n);
    AES_CBC_encrypt_buffer(&ctx, buf, (uint32_t)n);
    if (memcmp(buf, ct, n) != 0) {
        printf("%s: encrypt does not match NIST vector\n", label);
        return -1;
    }

    AES_init_ctx_iv(&ctx, key, iv);
    memcpy(buf, ct, n);
    AES_CBC_decrypt_buffer(&ctx, buf, (uint32_t)n);
    if (memcmp(buf, pt, n) != 0) {
        printf("%s: decrypt does not match NIST vector\n", label);
        return -1;
    }
    return 0;
}

static int verify_backends(const uint8_t key[AES_KEYBYTES], const uint8_t iv[AES_BLOCK])
{
    /* NIST SP 800-38A vectors: absolute correctness. 1-block cases catch
     * off-by-one / tail-handling issues; 4-block cases catch loop errors.
     * CBC is exercised for all three key sizes; the other modes get one
     * representative AES-256 spot check each. */
    if (check_mbed_cbc("mbedtls AES-128-CBC 1 block",  128,
                       nist128_key, nist_iv, nist_plain, nist128_cbc_cipher, 16) != 0) return -1;
    if (check_mbed_cbc("mbedtls AES-128-CBC 4 blocks", 128,
                       nist128_key, nist_iv, nist_plain, nist128_cbc_cipher, 64) != 0) return -1;
    if (check_mbed_cbc("mbedtls AES-192-CBC 4 blocks", 192,
                       nist192_key, nist_iv, nist_plain, nist192_cbc_cipher, 64) != 0) return -1;
    if (check_mbed_cbc("mbedtls AES-256-CBC 1 block",  256,
                       nist256_key, nist_iv, nist_plain, nist256_cbc_cipher, 16) != 0) return -1;
    if (check_mbed_cbc("mbedtls AES-256-CBC 4 blocks", 256,
                       nist256_key, nist_iv, nist_plain, nist256_cbc_cipher, 64) != 0) return -1;

    if (check_mbed_ecb   ("mbedtls AES-256-ECB 4 blocks", 256,
                          nist256_key, nist_plain, nist256_ecb_cipher, 64) != 0) return -1;
    if (check_mbed_cfb128("mbedtls AES-256-CFB128 4 blocks", 256,
                          nist256_key, nist_iv, nist_plain, nist256_cfb_cipher, 64) != 0) return -1;
    if (check_mbed_ofb   ("mbedtls AES-256-OFB 4 blocks", 256,
                          nist256_key, nist_iv, nist_plain, nist256_ofb_cipher, 64) != 0) return -1;
    if (check_mbed_ctr   ("mbedtls AES-256-CTR 4 blocks", 256,
                          nist256_key, nist_ctr_iv, nist_plain, nist256_ctr_cipher, 64) != 0) return -1;

    /* XTS (IEEE 1619) — keybits is the combined key length. */
    if (check_mbed_xts("mbedtls AES-128-XTS Vector 1",  256,
                       xts_v1_key,  xts_v1_du,  xts_v1_pt,  xts_v1_ct,  32)  != 0) return -1;
    if (check_mbed_xts("mbedtls AES-128-XTS Vector 2",  256,
                       xts_v2_key,  xts_v2_du,  xts_v2_pt,  xts_v2_ct,  32)  != 0) return -1;
    if (check_mbed_xts("mbedtls AES-256-XTS Vector 10", 512,
                       xts_v10_key, xts_v10_du, xts_v10_pt, xts_v10_ct, 512) != 0) return -1;

    /* tiny-AES-c in this tree is compiled for AES-256 CBC only. */
    if (check_tiny_vector("tiny AES-256-CBC 1 block",
                          nist256_key, nist_iv, nist_plain, nist256_cbc_cipher, 16) != 0) return -1;
    if (check_tiny_vector("tiny AES-256-CBC 4 blocks",
                          nist256_key, nist_iv, nist_plain, nist256_cbc_cipher, 64) != 0) return -1;

    /* Random cross-library round-trip: catches bugs the fixed vectors miss. */
    const size_t n = 4096;
    uint8_t *plain = malloc(n);
    uint8_t *ref   = malloc(n);
    uint8_t *work  = malloc(n);
    if (!plain || !ref || !work) { free(plain); free(ref); free(work); return -1; }

    for (size_t i = 0; i < n; i++) plain[i] = (uint8_t)(i * 31 + 7);

    memcpy(work, plain, n);
    void *c = mbed_setup(key);
    mbed_encrypt(c, iv, work, n);
    memcpy(ref, work, n);
    mbed_decrypt(c, iv, work, n);
    mbed_teardown(c);
    if (memcmp(work, plain, n) != 0) {
        printf("mbedtls_aes CBC round-trip failed\n");
        goto fail;
    }

    memcpy(work, plain, n);
    c = tiny_setup(key);
    tiny_encrypt(c, iv, work, n);
    if (memcmp(work, ref, n) != 0) {
        printf("tiny-AES-c vs mbedtls_aes ciphertext mismatch\n");
        tiny_teardown(c); goto fail;
    }
    tiny_decrypt(c, iv, work, n);
    tiny_teardown(c);
    if (memcmp(work, plain, n) != 0) {
        printf("tiny-AES-c CBC round-trip failed\n");
        goto fail;
    }

    free(plain); free(ref); free(work);
    return 0;
fail:
    free(plain); free(ref); free(work);
    return -1;
}

/* ---------- main ---------- */

static void print_active_path(void)
{
    const char *name = "unknown";
    switch (mbedtls_aes_get_implementation()) {
        case MBEDTLS_AES_IMP_AESNI_ASM:        name = "AES-NI (asm)";        break;
        case MBEDTLS_AES_IMP_AESNI_INTRINSICS: name = "AES-NI (intrinsics)"; break;
        case MBEDTLS_AES_IMP_AESCE:            name = "AES-CE";              break;
        case MBEDTLS_AES_IMP_SOFTWARE:         name = "software";            break;
        case MBEDTLS_AES_IMP_UNKNOWN:          name = "unknown";             break;
    }
    printf("mbedtls_aes_get_implementation: %s\n\n", name);
}

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
            "usage: %s [--min-seconds=<float>] [--check-only]\n"
            "  --min-seconds=<float>  benchmark each backend for at least this long (default 3.0)\n"
            "  --check-only           run the cross-check only; skip the benchmark loop\n",
            prog);
}

int main(int argc, char **argv)
{
    int check_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--min-seconds=", 14) == 0) {
            double v = atof(argv[i] + 14);
            if (v > 0) benchmark_runtime_seconds = v;
        } else if (strcmp(argv[i], "--check-only") == 0) {
            check_only = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "%s: unknown argument: %s\n", argv[0], argv[i]);
            usage(stderr, argv[0]);
            return 2;
        }
    }

    print_active_path();

    uint8_t key[AES_KEYBYTES];
    uint8_t iv[AES_BLOCK];
    for (int i = 0; i < AES_KEYBYTES; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < AES_BLOCK; i++)  iv[i]  = (uint8_t)(i * 13 + 3);

    if (verify_backends(key, iv) != 0) {
        fprintf(stderr, "Cross-check FAILED; aborting benchmark.\n");
        return 1;
    }
    printf("Cross-check OK.\n\n");

    if (check_only) return 0;

    uint8_t *buf = malloc(BUFFER_SIZE);
    if (!buf) {
        fprintf(stderr, "malloc(%d) failed\n", BUFFER_SIZE);
        return 1;
    }
    for (size_t i = 0; i < BUFFER_SIZE; i++) buf[i] = (uint8_t)i;

    printf("AES-256-CBC, buffer = %d MB, min run = %.2f s\n\n",
           BUFFER_SIZE / (1024 * 1024), benchmark_runtime_seconds);

    backend_t tiny_be = {
        .name = "tiny-AES-c (AES-256-CBC)",
        .setup = tiny_setup, .encrypt = tiny_encrypt,
        .decrypt = tiny_decrypt, .teardown = tiny_teardown,
    };
    run_benchmark(&tiny_be, key, iv, buf);

    backend_t mbed_be = {
        .name = "mbedtls_aes default (AES-256-CBC)",
        .setup = mbed_setup, .encrypt = mbed_encrypt,
        .decrypt = mbed_decrypt, .teardown = mbed_teardown,
    };
    run_benchmark(&mbed_be, key, iv, buf);

    free(buf);
    return 0;
}
