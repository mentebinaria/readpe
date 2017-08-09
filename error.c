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
		"failed reading directory", // LIBPE_E_EXPORTS_DIR
		"failed reading virtual address", // LIBPE_E_EXPORTS_VA
		"cannot read relative virtual address", //LIBPE_E_EXPORTS_CANT_READ_RVA	
		"number of function not equal to no of names", //LIBPE_E_EXPORTS_FUNC_NEQ_NAMES
		// Hashes Errors
		"error getting md5 hash", // LIBPE_E_HASHES_MD5
		"error getting sha1 hash", // LIBPE_E_HASHES_SHA1
		"error getting sha256 hash", // LIBPE_E_HASHES_SHA256
		"error getting ssdeep hash", // LIBPE_E_HASHES_SSDEEP
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
		strerror_r(errno, errmsg, sizeof(errmsg));
		fprintf(stream, "ERROR [%d]: %s (%s)\n", error, pe_error_msg(error),
			errmsg);
	}
}
