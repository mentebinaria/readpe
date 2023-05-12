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

#ifndef LIBPE_SECTIONS_H
#define LIBPE_SECTIONS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECTION_NAME_SIZE 8

// These informations were filled from various sources:
// - various versions of SDK files ntimage.h, winnt.h and coff.doc, pecoff*.doc documents
// - behavior of MSVC40 CL.EXE (I386 and M68K versions), LINK.EXE and DUMPBIN.EXE
typedef enum {
	IMAGE_SCN_SCALE_INDEX				= 0x00000001, // Address of tls index is scaled (multiplied by 4). This is valid only for .tls section and only on MIPS.
	IMAGE_SCN_TYPE_NO_LOAD				= 0x00000002, // Reserved.
	IMAGE_SCN_TYPE_GROUPED				= 0x00000004, // Used for 16-bit offset code. Linker combines sections with the same name (they may have different flags) into one output section with max 64 kB size. All offsets inside the section are signed 16-bit from the middle of the section. This is valid only for object files. (Not supported by LINK.EXE)
	IMAGE_SCN_TYPE_NO_PAD				= 0x00000008, // Same as IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
	IMAGE_SCN_TYPE_COPY				= 0x00000010, // Reserved.
	IMAGE_SCN_CNT_CODE				= 0x00000020, // The section contains executable code.
	IMAGE_SCN_CNT_INITIALIZED_DATA			= 0x00000040, // The section contains initialized data.
	IMAGE_SCN_CNT_UNINITIALIZED_DATA		= 0x00000080, // The section contains uninitialized data.
	IMAGE_SCN_LNK_OTHER				= 0x00000100, // The section contains other than info, code or data. This is valid only for object files.
	IMAGE_SCN_LNK_INFO				= 0x00000200, // The section contains comments or other information. This is valid only for object files.
	IMAGE_SCN_LNK_OVERLAY				= 0x00000400, // The section contains an overlay (Reserved).
	IMAGE_SCN_LNK_REMOVE				= 0x00000800, // The section will not become part of the image. This is valid only for object files.
	IMAGE_SCN_LNK_COMDAT				= 0x00001000, // The section contains COMDAT data. This is valid only for object files.
//	RESERVED					= 0x00002000, // Reserved.
	IMAGE_SCN_MEM_PROTECTED				= 0x00004000, // The section is memory protected. This is valid only for M68K (Mac OS memory management).
	IMAGE_SCN_NO_DEFER_SPEC_EXC			= 0x00004000, // Reset speculative exceptions handling bits in the TLB entries for this section. This is not valid for M68K.
	IMAGE_SCN_MEM_FARDATA				= 0x00008000, // The section contains FAR_EXTERNAL relocations. This is valid only for M68K (Mac OS memory management).
	IMAGE_SCN_GPREL					= 0x00008000, // The section contains data referenced through the global pointer. This is not valid for M68K.
	IMAGE_SCN_MEM_SYSHEAP				= 0x00010000, // The section uses System heap. This is valid only for M68K (Mac OS memory management).
	IMAGE_SCN_MEM_PURGEABLE				= 0x00020000, // The section can be released from RAM. This is valid only for M68K (Mac OS memory management).
	IMAGE_SCN_MEM_16BIT				= 0x00020000, // The section contains 16-bit code. This is valid only for non-M68K architectures where it makes sense (I386, THUMB, MIPS16, MIPSFPU16, ...).
	IMAGE_SCN_MEM_LOCKED				= 0x00040000, // The section is locked/resident and prevented from being moved in RAM. This is valid only for M68K (Mac OS memory management) and I386 object files (e.g. for building Linear Executables).
	IMAGE_SCN_MEM_PRELOAD				= 0x00080000, // The section is preloaded to RAM. This is valid only for M68K (Mac OS memory management) and I386 object files (e.g. for building Linear Executables).
	IMAGE_SCN_ALIGN_1BYTES				= 0x00100000, // Align data on a 1-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_2BYTES				= 0x00200000, // Align data on a 2-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_4BYTES				= 0x00300000, // Align data on a 4-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_8BYTES				= 0x00400000, // Align data on a 8-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_16BYTES				= 0x00500000, // Align data on a 16-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_32BYTES				= 0x00600000, // Align data on a 32-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_64BYTES				= 0x00700000, // Align data on a 64-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_128BYTES			= 0x00800000, // Align data on a 128-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_256BYTES			= 0x00900000, // Align data on a 256-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_512BYTES			= 0x00A00000, // Align data on a 512-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_1024BYTES			= 0x00B00000, // Align data on a 1024-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_2048BYTES			= 0x00C00000, // Align data on a 2048-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_4096BYTES			= 0x00D00000, // Align data on a 4096-byte boundary. This is valid only for object files.
	IMAGE_SCN_ALIGN_8192BYTES			= 0x00E00000, // Align data on a 8192-byte boundary. This is valid only for object files.
//	RESERVED					= 0x00F00000, // Reserved.
	IMAGE_SCN_LNK_NRELOC_OVFL			= 0x01000000, // The section contains extended relocations. This is valid only for object files.
	IMAGE_SCN_MEM_DISCARDABLE			= 0x02000000, // The section can be discarded as needed.
	IMAGE_SCN_MEM_NOT_CACHED			= 0x04000000, // The section cannot be cached.
	IMAGE_SCN_MEM_NOT_PAGED				= 0x08000000, // The section cannot be paged.
	IMAGE_SCN_MEM_SHARED				= 0x10000000, // The section is shareable. When used with a DLL, the data in this section will be shared among all processes using the DLL.
	IMAGE_SCN_MEM_EXECUTE				= 0x20000000, // The section is executable.
	IMAGE_SCN_MEM_READ				= 0x40000000, // The section is readable.
	IMAGE_SCN_MEM_WRITE				= -2147483648 // The section is writeable. (0x80000000U)
} SectionCharacteristics;

// Used only when IMAGE_ROM_OPTIONAL_HEADER is present
typedef enum {
	STYP_DUMMY	= 0x00000001, // Dummy
	STYP_TEXT	= 0x00000020, // Text
	STYP_DATA	= 0x00000040, // Data
	STYP_SBSS	= 0x00000080, // GP Uninit Data
	STYP_RDATA	= 0x00000100, // Readonly Data
	STYP_SDATA	= 0x00000200, // GP Init Data
	STYP_BSS	= 0x00000400, // Uninit Data
	STYP_UCODE	= 0x00000800, // UCode
	STYP_LIT8	= 0x08000000, // Literal 8
	STYP_LIT4	= 0x10000000, // Literal 4
	S_NRELOC_OVFL	= 0x20000000, // Non-Relocatable overlay
	STYP_LIB	= 0x40000000, // Library
	STYP_INIT	= -2147483648 // Init Code (0x80000000U)
} ROMSectionCharacteristics;

#pragma pack(push, 1)

// Quoting pecoff_v8.docx: "Entries in the section table are numbered starting from one (1)".
typedef struct {
	uint8_t Name[SECTION_NAME_SIZE]; // TODO: Should we use char instead?
	union {
		uint32_t PhysicalAddress; // same value as next field
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations; // always zero in executables
	uint32_t PointerToLinenumbers; // deprecated
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers; // deprecated
	uint32_t Characteristics; // SectionCharacteristics or ROMSectionCharacteristics
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

#ifdef __cplusplus
} // extern "C"
#endif

#endif
