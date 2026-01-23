/* BSD 3-Clause License
 *
 * Copyright (c) 2018, Thomas Gamper
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * asprintf
 *
 * An implementation of
 * [vasprintf](http://man7.org/linux/man-pages/man3/asprintf.3.html) and
 * [asprintf](http://man7.org/linux/man-pages/man3/asprintf.3.html) for the
 * Microsoft Windows platform. This implementation takes advantage of the
 * security enhancements provided by the [Microsoft CRT]
 * (https://docs.microsoft.com/de-de/cpp/c-runtime-library/security-features-in-the-crt).
 * Works with all Visual C++ versions starting from Visual C++ 2008.
 */

#include "compat/asprintf.h"

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if _MSC_VER < 1800
#undef va_copy
#define va_copy(dst, src) (dst = src)
#endif

#ifdef __cplusplus
extern "C"
#endif
    int
    vasprintf(char **strp, const char *fmt, va_list ap)
{
    va_list ap_copy;
    int     formattedLength, actualLength;
    size_t  requiredSize;

    // be paranoid
    *strp = NULL;

    // copy va_list, as it is used twice
    va_copy(ap_copy, ap);

    // compute length of formatted string, without NULL terminator
    formattedLength = _vscprintf(fmt, ap_copy);
    va_end(ap_copy);

    // bail out on error
    if (formattedLength < 0) {
        return -1;
    }

    // allocate buffer, with NULL terminator
    requiredSize = ((size_t) formattedLength) + 1;
    *strp        = (char *) malloc(requiredSize);

    // bail out on failed memory allocation
    if (*strp == NULL) {
        errno = ENOMEM;
        return -1;
    }

    // write formatted string to buffer, use security hardened _s function
    actualLength = vsnprintf_s(*strp, requiredSize, requiredSize - 1, fmt, ap);

    // again, be paranoid
    if (actualLength != formattedLength) {
        free(*strp);
        *strp = NULL;
        errno = EOTHER;
        return -1;
    }

    return formattedLength;
}

#ifdef __cplusplus
extern "C"
#endif
    int
    asprintf(char **strp, const char *fmt, ...)
{
    int     result;

    va_list ap;
    va_start(ap, fmt);
    result = vasprintf(strp, fmt, ap);
    va_end(ap);

    return result;
}
#endif

#ifdef USE_MY_ASPRINTF
int asprintf(char **pp, char *fmt, ...)
{
    char   *p;
    int     size;
    va_list args, args_safe;

    va_start(args, fmt);
    va_copy(args_safe, args);

    // Just get the string size.
    if ((size = vsnprintf(NULL, 0, fmt, args_safe)) < 0) {
        va_end(args_safe);
        va_end(args);
        return -1;
    }

    if (! (p = malloc(size + 1))) {
        va_end(args_safe);
        va_end(args);
        return -1;
    }

    vsprintf(*pp = p, fmt, args);

    va_end(args_safe);
    va_end(args);

    return size;
}
#endif

