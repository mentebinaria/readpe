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

#ifndef LIBPE_HASHES_H
#define LIBPE_HASHES_H

#include <stdint.h>
#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBPE_IMPHASH_FLAVOR_MANDIANT = 1,
	LIBPE_IMPHASH_FLAVOR_PEFILE = 2,
} pe_imphash_flavor_e;

typedef struct {
	char *name;
	char *md5;
	char *ssdeep;
	char *sha1;
	char *sha256;
} pe_hash_t;

typedef struct {
	pe_err_e err;
	pe_hash_t *dos;
	pe_hash_t *coff;
	pe_hash_t *optional;
} pe_hash_headers_t;

typedef struct {
	pe_err_e err;
	uint32_t count;
	pe_hash_t **sections;
} pe_hash_sections_t;

void pe_hash_headers_dealloc(pe_hash_headers_t *obj);
void pe_hash_sections_dealloc(pe_hash_sections_t *obj);
void pe_hash_dealloc(pe_hash_t *obj);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
