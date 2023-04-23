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

#ifndef LIBPE_DIRECTORIES_H
#define LIBPE_DIRECTORIES_H

#include <stdint.h>
#include "dir_import.h"
#include "dir_resources.h"
#include "dir_security.h"

#ifdef __cplusplus
extern "C" {
#endif

// Directory entries
typedef enum {
	IMAGE_DIRECTORY_ENTRY_EXPORT			= 0, // Export Table
	IMAGE_DIRECTORY_ENTRY_IMPORT			= 1, // Import Table
	IMAGE_DIRECTORY_ENTRY_RESOURCE			= 2, // Resource Table
	IMAGE_DIRECTORY_ENTRY_EXCEPTION			= 3, // Exception Table
	IMAGE_DIRECTORY_ENTRY_SECURITY			= 4, // Certificate Table
	IMAGE_DIRECTORY_ENTRY_BASERELOC			= 5, // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG				= 6, // Debug
	//IMAGE_DIRECTORY_ENTRY_COPYRIGHT			= 7, // (X86 usage)
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE		= 7, // Architecture
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR			= 8, // Global Ptr
	IMAGE_DIRECTORY_ENTRY_TLS				= 9, // TLS Table
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG		= 10, // Load Config Table
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT		= 11, // Bound Import
	IMAGE_DIRECTORY_ENTRY_IAT				= 12, // IAT
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT		= 13, // Delay Import Descriptor
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	= 14, // CLR Runtime Header
	IMAGE_DIRECTORY_RESERVED				= 15  // Reserved, must be zero
} ImageDirectoryEntry;

typedef struct {
	uint32_t Characteristics;
	uint32_t TimeDateStamp;
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint32_t Name;
	uint32_t Base;
	uint32_t NumberOfFunctions;
	uint32_t NumberOfNames;
	uint32_t AddressOfFunctions;
	uint32_t AddressOfNames;
	uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct {
	uint32_t StartAddressOfRawData;
	uint32_t EndAddressOfRawData;
	uint32_t AddressOfIndex;
	uint32_t AddressOfCallBacks; // PIMAGE_TLS_CALLBACK
	uint32_t SizeOfZeroFill;
	uint32_t Characteristics; // reserved for future use
} IMAGE_TLS_DIRECTORY32;

typedef struct {
	uint64_t StartAddressOfRawData;
	uint64_t EndAddressOfRawData;
	uint64_t AddressOfIndex;
	uint64_t AddressOfCallBacks;
	uint32_t SizeOfZeroFill;
	uint32_t Characteristics;
} IMAGE_TLS_DIRECTORY64;

typedef struct {
	uint32_t VirtualAddress;
	uint32_t Size;
} IMAGE_DATA_DIRECTORY;

#ifdef __cplusplus
} // extern "C"
#endif

#endif
