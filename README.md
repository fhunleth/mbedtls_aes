<!--
SPDX-FileCopyrightText: Frank Hunleth
SPDX-License-Identifier: CC0-1.0
-->

# mbedtls_aes — single-file AES drop-in

This project provides the [Mbed TLS AES implementation](https://github.com/Mbed-TLS/TF-PSA-Crypto)
in one `.c` and one `.h` file for easy embedding in other applications.

It is similar to [`tiny-AES-c`](https://github.com/kokke/tiny-AES-c). Mbed TLS
provides a significantly faster AES implementation including support for AES-NI
on x86/x64 and the Armv8-A Cryptographic Extension on AArch64. Hardware
acceleration is auto-enabled at compile-time based on target architecture;
runtime dispatch then picks the fastest available path based on CPU features.

Every platform I try has different performance. Roughly, I'm seeing Mbed TLS's
AES implementation come in 5x-10x better than tiny-AES-c without hardware
acceleration and 20x-100x better with hardware acceleration on 64-bit ARM
embedded and desktop processors. Here's an example run on my laptop from the
included `aes_bench` program:

```
--- tiny-AES-c (AES-256-CBC) ---
  encrypt: 5 x 100 MB in 3.081 s ->  162.26 MB/s
  decrypt: 2 x 100 MB in 3.891 s ->   51.40 MB/s

--- mbedtls_aes default (AES-256-CBC) ---
  encrypt: 32 x 100 MB in 3.060 s -> 1045.85 MB/s
  decrypt: 226 x 100 MB in 3.009 s -> 7510.42 MB/s

--- mbedtls_aes XTS (AES-256-XTS, 4096 B sectors) ---
  encrypt: 233 x 100 MB in 3.001 s -> 7763.03 MB/s
  decrypt: 230 x 100 MB in 3.002 s -> 7662.29 MB/s
```

## Getting the library

Grab the two files from the repository:

```
mbedtls_aes.c
mbedtls_aes.h
```

Copy them into your project, compile `mbedtls_aes.c` with the rest of your code,
and `#include "mbedtls_aes.h"` wherever you use it. No build flags are required.

To build yourself in this repository, run the following:

```sh
git submodule update --init --recursive
make
make check
```

Always run `make check`. While this project shouldn't break the Mbed TLS AES
implementation, this spot-checks the AES implementation against NIST test
vectors just in case.

## Minimal example

```c
#include "mbedtls_aes.h"

void encrypt_aes256_cbc(const uint8_t key[32], const uint8_t iv_in[16],
                        uint8_t *buf, size_t len)
{
    mbedtls_aes_context ctx;
    uint8_t iv[16];

    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);

    memcpy(iv, iv_in, sizeof(iv));                 /* mbedtls mutates the IV */
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, buf, buf);

    mbedtls_aes_free(&ctx);
}
```

Supported modes: ECB, CBC, CFB, CTR, OFB, XTS. Supported key sizes: 128, 192, 256.

## Checking the implementation

If you're not getting the performance you expect, check that you're running
the right implementation:

```c
switch (mbedtls_aes_get_implementation()) {
    case MBEDTLS_AES_IMP_AESNI_ASM:
    case MBEDTLS_AES_IMP_AESNI_INTRINSICS: /* x86/x64 AES-NI */ break;
    case MBEDTLS_AES_IMP_AESCE:            /* Armv8-A CE     */ break;
    case MBEDTLS_AES_IMP_SOFTWARE:         /* software       */ break;
}
```

## Build configuration

All configuration is through C `#define`s as summarized below.

| define | effect |
|---|---|
| `MBEDTLS_NO_AES_HARDWARE` | force software-only path (disables both AES-NI and AES-CE detection) |
| `MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH` | restrict to AES-128 for smaller code size |
| `MBEDTLS_BLOCK_CIPHER_NO_DECRYPT` | encrypt-only builds (drops the decrypt tables) |
| `MBEDTLS_AES_ROM_TABLES` | put the S-box tables in `const` (ROM) memory |
| `MBEDTLS_AES_FEWER_TABLES` | trade a bit of speed for ~6 KB smaller binary |

## License

Apache-2.0 OR GPL-2.0-or-later, matching upstream Mbed TLS. License texts live
in `LICENSES/`. The repository is [REUSE](https://reuse.software)-compliant.
