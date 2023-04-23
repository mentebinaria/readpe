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

#ifndef LIBPE_EXPORTS_H
#define LIBPE_EXPORTS_H

#include <stdint.h>
#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t ordinal; // ordinal of the function
	char *name; // name of the function
	char *fwd_name; // name of the forwarded function
	uint32_t address; // address of the function
} pe_exported_function_t;

typedef struct {
	pe_err_e err;
	char *name; // name of the DLL
	uint32_t functions_count;
	pe_exported_function_t *functions; // array of exported functions
} pe_exports_t;

void pe_exports_dealloc(pe_exports_t *exports);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
