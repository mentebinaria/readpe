/*
	pev - libpe the PE library

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

#ifndef LIBPE_H
#define LIBPE_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC_MZ 0x5a4d
#define MAX_DIRECTORIES 32
#define MAX_SECTIONS 96

#define SIGNATURE_NE 0x454E // NE\0\0 in little-endian
#define SIGNATURE_PE 0x4550 // PE\0\0 in little-endian

#pragma pack(push, 1)

typedef struct {
	char name[40];
	uint16_t code;
} MACHINE_ENTRY;

typedef struct {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	int32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
} IMAGE_FILE_HEADER, IMAGE_COFF_HEADER;

typedef struct {
	uint16_t Magic; 
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData; // only in PE32
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Reserved1;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_32;

typedef struct {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Reserved1;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags; /* must be zero */
	uint32_t NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_64;

typedef enum {
	MAGIC_ROM	= 0x107,
	MAGIC_PE32	= 0x10b,
	MAGIC_PE64	= 0x20b
} opt_type_e;

typedef struct {
	uint16_t type; // opt_type_e
	size_t length;
	IMAGE_OPTIONAL_HEADER_32 *_32;
	IMAGE_OPTIONAL_HEADER_64 *_64;
} IMAGE_OPTIONAL_HEADER;

typedef struct {
	uint32_t VirtualAddress;
	uint32_t Size;
} IMAGE_DATA_DIRECTORY;

#define SECTION_NAME_SIZE	8

typedef struct {
	uint8_t Name[SECTION_NAME_SIZE]; // TODO: Should we use char instead?
	union {
		uint32_t PhysicalAddress; // same value as next field
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
} IMAGE_SECTION_HEADER;

typedef struct {
	// DOS header
	IMAGE_DOS_HEADER *dos_hdr;
	// Signature
	uint32_t signature;
	// COFF header
	IMAGE_COFF_HEADER *coff_hdr;
	// Optional headers
	IMAGE_OPTIONAL_HEADER *optional_hdr;
	// Directories
	uint32_t num_directories;
	void *directories_ptr;
	IMAGE_DATA_DIRECTORY **directories; // array up to MAX_DIRECTORIES
	// Sections
	uint16_t num_sections;
	void *sections_ptr;
	IMAGE_SECTION_HEADER **sections; // array up to MAX_SECTIONS

#if 0
	bool is_dll;
	uint16_t e_lfanew;
	uint16_t architecture;
	uint64_t entrypoint;
	uint64_t imagebase;
	uint64_t size;

	uint16_t num_sections;
	uint16_t num_directories;
	uint16_t num_rsrc_entries;

	uint16_t addr_sections;
	uint16_t addr_directories;
	uint16_t addr_dos;
	uint16_t addr_optional;
	uint16_t addr_coff;
	uint16_t addr_rsrc_sec;
	uint16_t addr_rsrc_dir;

	// pointers (will be freed if needed)
	IMAGE_OPTIONAL_HEADER *optional_ptr;
	IMAGE_SECTION_HEADER **sections_ptr;
	IMAGE_DATA_DIRECTORY **directories_ptr;
	//IMAGE_TLS_DIRECTORY32 *tls_ptr;
	IMAGE_RESOURCE_DIRECTORY *rsrc_ptr;
	IMAGE_RESOURCE_DIRECTORY_ENTRY **rsrc_entries_ptr;
#endif
} PE_FILE;

#pragma pack(pop)

typedef struct {
	char *path;
	struct stat stat;
	void *map_addr;
	PE_FILE pe;
} pe_ctx_t;

int pe_load(pe_ctx_t *ctx, const char *path);
int pe_unload(pe_ctx_t *ctx);
int pe_parse(pe_ctx_t *ctx);
bool is_pe(pe_ctx_t *ctx);

#endif
