/*
    libpe - the PE library

    Copyright (C) 2010 - 2017 libpe authors
    
    This file is part of libpe.

    libpe is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libpe is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libpe.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "libpe/error.h"
#include "libpe/macros.h"
#include <errno.h>
#include <string.h>

const char *pe_error_msg(pe_err_e error) {
	static const char * const errors[] = {
		"no error", // LIBPE_E_OK,
		"allocation failure", // LIBPE_E_ALLOCATION_FAILURE,
		"open() failed", // LIBPE_E_OPEN_FAILED,
		"fdopen() failed", // LIBPE_E_FDOPEN_FAILED,
		"fstat() failed", // LIBPE_E_FSTAT_FAILED,
		"not a regular file", // LIBPE_E_NOT_A_FILE,
		"not a PE file", // LIBPE_E_NOT_A_PE_FILE,
		"invalid e_lfanew", // LIBPE_E_INVALID_LFANEW,
		"missing COFF header", // LIBPE_E_MISSING_COFF_HEADER,
		"missing OPTIONAL header", // LIBPE_E_MISSING_OPTIONAL_HEADER,
		"invalid signature", // LIBPE_E_INVALID_SIGNATURE,
		"unsupported image format", // LIBPE_E_UNSUPPORTED_IMAGE,
		"mmap() failed", // LIBPE_E_MMAP_FAILED,
		"munmap() failed", // LIBPE_E_MUNMAP_FAILED,
		"close() failed", // LIBPE_E_CLOSE_FAILED,
		"too many directories", // LIBPE_E_TOO_MANY_DIRECTORIES,
		"too many sections", // LIBPE_E_TOO_MANY_SECTIONS,
		"type punning failed", // LIBPE_E_TYPE_PUNNING_FAILED
		// Exports errors
		"cannot read relative virtual address", //LIBPE_E_EXPORTS_CANT_READ_RVA
		"cannot read exports directory", // LIBPE_E_EXPORTS_CANT_READ_DIR
		"number of functions not equal to number of names", //LIBPE_E_EXPORTS_FUNC_NEQ_NAMES
		// Hashes Errors
		"error calculating hash", // LIBPE_E_HASHING_FAILED
		// Misc
		"no callbacks found", //LIBPE_E_NO_CALLBACKS_FOUND
		"no functions found", //LIBPE_E_NO_FUNCIONS_FOUND
	};
	static const size_t index_max = LIBPE_SIZEOF_ARRAY(errors);
	size_t index = index_max + error;
	return (index < index_max)
		? errors[index]
		: (index == index_max)
			? errors[0] // LIBPE_E_OK
			: "invalid error code";
}

void pe_error_print(FILE *stream, pe_err_e error) {
	if (errno == 0) {
		fprintf(stream, "ERROR [%d]: %s\n", error, pe_error_msg(error));
	} else {
		char errmsg[255];
		memset(errmsg, 0, sizeof(errmsg));

		/*
		 * Quotes from https://linux.die.net/man/3/strerror_r
		 *
		 * The strerror_r() function is similar to strerror(), but is thread safe. This function
		 * is available in two versions: an XSI-compliant version specified in POSIX.1-2001
		 * (available since glibc 2.3.4, but not POSIX-compliant until glibc 2.13), and a
		 * GNU-specific version (available since glibc 2.0). The XSI-compliant version is provided
		 * with the feature test macros settings shown in the SYNOPSIS; otherwise the GNU-specific
		 * version is provided. If no feature test macros are explicitly defined, then (since
		 * glibc 2.4) _POSIX_SOURCE is defined by default with the value 200112L, so that the
		 * XSI-compliant version of strerror_r() is provided by default.
		 *
		 * The XSI-compliant strerror_r() is preferred for portable applications. It returns the
		 * error string in the user-supplied buffer buf of length buflen.
		 *
		 * The GNU-specific strerror_r() returns a pointer to a string containing the error
		 * message. This may be either a pointer to a string that the function stores in buf, or
		 * a pointer to some (immutable) static string (in which case buf is unused). If the
		 * function stores a string in buf, then at most buflen bytes are stored (the string may
		 * be truncated if buflen is too small and errnum is unknown). The string always includes
		 * a terminating null byte.
		 */

		// Since we define _GNU_SOURCE in our Makefile, strerror_r should be GNU-compliant.
		// However, looks like if you're on macOS, strerror_r is XSI-compliant.

#if defined(__DARWIN_C_LEVEL) // XSI-compliant
		/* int ret = */ strerror_r(errno, errmsg, sizeof(errmsg));
		const char *errmsg_ptr = errmsg;
#elif defined(_GNU_SOURCE) // GNU-specific
		const char *errmsg_ptr = strerror_r(errno, errmsg, sizeof(errmsg));
#else // Fallback to XSI-compliant
		/* int ret = */ strerror_r(errno, errmsg, sizeof(errmsg));
		const char *errmsg_ptr = errmsg;
#endif

		fprintf(stream, "ERROR [%d]: %s (%s)\n", error, pe_error_msg(error),
			errmsg_ptr);
	}
}
