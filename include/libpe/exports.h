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

#ifndef LIBPE_EXPORTS
#define LIBPE_EXPORTS

#include "pe.h"
#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t addr;
	char *name;	// name of the function at that address
} pe_exported_function_t;

typedef struct {
	pe_err_e err;
	uint32_t functions_count;
	pe_exported_function_t *functions; // array of exported functions
} pe_exports_t;

pe_exports_t pe_get_exports(pe_ctx_t *ctx);
void pe_dealloc_exports(pe_exports_t exports);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
