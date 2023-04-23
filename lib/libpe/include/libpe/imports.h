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

#ifndef LIBPE_IMPORTS_H
#define LIBPE_IMPORTS_H

#include <stdint.h>
#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char *name;
    uint16_t hint;
	uint16_t ordinal;
} pe_imported_function_t;

typedef struct {
	pe_err_e err;
	char *name;
	uint32_t functions_count;
	pe_imported_function_t *functions; // array of imported functions
} pe_imported_dll_t;

typedef struct {
	pe_err_e err;
	uint32_t dll_count;
	pe_imported_dll_t *dlls; // array of DLLs
} pe_imports_t;

void pe_imports_dealloc(pe_imports_t *imports);

/*
 * We have an array of names and an array of functions.
 *
 * functions[i] has functions corresponding to names[i]
 *
 * "Imports": [
 *		{
 *			"DllName": "SHELL32.dll",
 *				"Functions": [
 *						"ShellExecuteA",
 *						"FindExecutableA"
 *				]
 *		}
 *	 ]
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif
