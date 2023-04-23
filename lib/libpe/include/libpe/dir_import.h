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

#ifndef LIBPE_DIR_IMPORT_H
#define LIBPE_DIR_IMPORT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

typedef struct {
	union {
		uint32_t Characteristics; // 0 for terminating null import descriptor
		uint32_t OriginalFirstThunk; // RVA to original unbound IAT
	} u1;
	uint32_t TimeDateStamp;
	uint32_t ForwarderChain; // -1 if no forwarders
	uint32_t Name;
	// RVA to IAT (if bound this IAT has actual addresses)
	uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

// import name entry
typedef struct {
	uint16_t Hint;
	uint8_t Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef struct {
	union {
		uint64_t ForwarderString; // RVA to a forwarder string
		uint64_t Function; // Memory address of the imported function
		uint64_t Ordinal; // Ordinal value of imported API
		uint64_t AddressOfData; // RVA to an IMAGE_IMPORT_BY_NAME with the imported API name
	} u1;
} IMAGE_THUNK_DATA64;

typedef struct {
	union {
		uint32_t ForwarderString; // RVA to a forwarder string
		uint32_t Function; // Memory address of the imported function
		uint32_t Ordinal; // Ordinal value of imported API
		uint32_t AddressOfData; // RVA to an IMAGE_IMPORT_BY_NAME with the imported API name
	} u1;
} IMAGE_THUNK_DATA32;

#pragma pack(pop)

#ifdef __cplusplus
} // extern "C"
#endif

#endif
