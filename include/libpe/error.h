/*
    libpe - the PE library

    Copyright (C) 2010 - 2015 libpe authors
    
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

#ifndef LIBPE_ERROR_H
#define LIBPE_ERROR_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBPE_E_OK = 0,
	// Declaring negative values this way is EVIL because it
	// BREAKS compatiblity every time we add/remove an error code.
	LIBPE_E_ALLOCATION_FAILURE = -23,
	LIBPE_E_OPEN_FAILED,
	LIBPE_E_FDOPEN_FAILED,
	LIBPE_E_FSTAT_FAILED,
	LIBPE_E_NOT_A_FILE,
	LIBPE_E_NOT_A_PE_FILE,
	LIBPE_E_INVALID_LFANEW,
	LIBPE_E_MISSING_COFF_HEADER,
	LIBPE_E_MISSING_OPTIONAL_HEADER,
	LIBPE_E_INVALID_SIGNATURE,
	LIBPE_E_UNSUPPORTED_IMAGE,
	LIBPE_E_MMAP_FAILED,
	LIBPE_E_MUNMAP_FAILED,
	LIBPE_E_CLOSE_FAILED,
	LIBPE_E_TOO_MANY_DIRECTORIES,
	LIBPE_E_TOO_MANY_SECTIONS,
	LIBPE_E_INVALID_THUNK,
	// Exports
	LIBPE_E_EXPORTS_CANT_READ_RVA,
	LIBPE_E_EXPORTS_CANT_READ_DIR,
	LIBPE_E_EXPORTS_FUNC_NEQ_NAMES,
	// Hashes
	LIBPE_E_HASHING_FAILED,
	// Misc
	LIBPE_E_NO_CALLBACKS_FOUND,
	LIBPE_E_NO_FUNCTIONS_FOUND
} pe_err_e;

const char *pe_error_msg(pe_err_e error);
void pe_error_print(FILE *stream, pe_err_e error);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
