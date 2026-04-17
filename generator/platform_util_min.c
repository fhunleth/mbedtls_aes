/*
 *  SPDX-FileCopyrightText: The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 *  Minimal platform_util replacement to provide zeroize functions
 */

/* Secure zeroize that resists compiler optimization. Prefer platform
 * primitives where available; otherwise a volatile memset pointer plus
 * an empty asm barrier (matching the original Mbed TLS approach). */

#if defined(__GLIBC__) && \
    ((__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25) || __GLIBC__ > 2)
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#  endif
#  include <string.h>
#  define MBEDTLS_HAVE_EXPLICIT_BZERO
#elif (defined(__FreeBSD__) && (__FreeBSD_version >= 1100037)) || \
      defined(__OpenBSD__)
#  include <string.h>
#  define MBEDTLS_HAVE_EXPLICIT_BZERO
#elif defined(_WIN32)
#  include <windows.h>
#endif

#ifndef MBEDTLS_HAVE_EXPLICIT_BZERO
static void *(*const volatile mbedtls_memset_func)(void *, int, size_t) = memset;
#endif

void mbedtls_platform_zeroize(void *buf, size_t len)
{
    if (len == 0) {
        return;
    }
#if defined(MBEDTLS_HAVE_EXPLICIT_BZERO)
    explicit_bzero(buf, len);
#elif defined(_WIN32)
    SecureZeroMemory(buf, len);
#else
    mbedtls_memset_func(buf, 0, len);
#endif
#if defined(__GNUC__) || defined(__clang__)
    /* Barrier: pretend the memory is read so the zeroing can't be elided. */
    __asm__ __volatile__ ("" : : "r" (buf) : "memory");
#endif
}

void mbedtls_zeroize_and_free(void *buf, size_t len)
{
    if (buf != NULL) {
        mbedtls_platform_zeroize(buf, len);
        mbedtls_free(buf);
    }
}
