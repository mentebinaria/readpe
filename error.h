/*
	libpe - the PE library

	Copyright (C) 2010 - 2013 libpe authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef LIBPE_ERROR_H
#define LIBPE_ERROR_H

#include <stdio.h>

typedef enum {
	LIBPE_E_OK = 0,
	LIBPE_E_ALLOCATION_FAILURE = -15,
	LIBPE_E_OPEN_FAILED,
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
} pe_err_e;

const char *pe_error_msg(pe_err_e error);
void pe_error_print(FILE *stream, pe_err_e error);

#endif
