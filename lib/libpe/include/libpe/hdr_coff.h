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

#ifndef LIBPE_HDR_COFF_H
#define LIBPE_HDR_COFF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	IMAGE_FILE_MACHINE_UNKNOWN		= 0x0,
	IMAGE_FILE_MACHINE_ALPHA_OLD		= 0x183,
	IMAGE_FILE_MACHINE_ALPHA		= 0x184,
	IMAGE_FILE_MACHINE_ALPHA64		= 0x284,
	IMAGE_FILE_MACHINE_AM33			= 0x1d3,
	IMAGE_FILE_MACHINE_AMD64		= 0x8664,
	IMAGE_FILE_MACHINE_ARM			= 0x1c0,
	IMAGE_FILE_MACHINE_ARMV7		= 0x1c4,
	IMAGE_FILE_MACHINE_ARM64		= 0xaa64,
	IMAGE_FILE_MACHINE_ARM64EC		= 0xa641,
	IMAGE_FILE_MACHINE_ARM64X		= 0xa64e,
	IMAGE_FILE_MACHINE_CEE			= 0xc0ee,
	IMAGE_FILE_MACHINE_CEF			= 0xcef,
	IMAGE_FILE_MACHINE_CHPE_X86		= 0x3a64,
	IMAGE_FILE_MACHINE_EBC			= 0xebc,
	IMAGE_FILE_MACHINE_I386			= 0x14c,
	IMAGE_FILE_MACHINE_I860			= 0x14d,
	IMAGE_FILE_MACHINE_IA64			= 0x200,
	IMAGE_FILE_MACHINE_LOONGARCH32		= 0x6232,
	IMAGE_FILE_MACHINE_LOONGARCH64		= 0x6264,
	IMAGE_FILE_MACHINE_M32R			= 0x9041,
	IMAGE_FILE_MACHINE_M68K			= 0x268,
	IMAGE_FILE_MACHINE_MIPS16		= 0x266,
	IMAGE_FILE_MACHINE_MIPSFPU		= 0x366,
	IMAGE_FILE_MACHINE_MIPSFPU16	= 0x466,
	IMAGE_FILE_MACHINE_MPPC_601		= 0x601,
	IMAGE_FILE_MACHINE_OMNI			= 0xace1,
	IMAGE_FILE_MACHINE_PARISC		= 0x290,
	IMAGE_FILE_MACHINE_POWERPC		= 0x1f0,
	IMAGE_FILE_MACHINE_POWERPCFP	= 0x1f1,
	IMAGE_FILE_MACHINE_POWERPCBE		= 0x1f2,
	IMAGE_FILE_MACHINE_R3000		= 0x162,
	IMAGE_FILE_MACHINE_R3000_BE		= 0x160,
	IMAGE_FILE_MACHINE_R4000		= 0x166,
	IMAGE_FILE_MACHINE_R10000		= 0x168,
	IMAGE_FILE_MACHINE_RISCV32		= 0x5032,
	IMAGE_FILE_MACHINE_RISCV64		= 0x5064,
	IMAGE_FILE_MACHINE_RISCV128		= 0x5128,
	IMAGE_FILE_MACHINE_SH3			= 0x1a2,
	IMAGE_FILE_MACHINE_SH3DSP		= 0x1a3,
	IMAGE_FILE_MACHINE_SH3E			= 0x1a4,
	IMAGE_FILE_MACHINE_SH4			= 0x1a6,
	IMAGE_FILE_MACHINE_SH5			= 0x1a8,
	IMAGE_FILE_MACHINE_TRICORE		= 0x520,
	IMAGE_FILE_MACHINE_TAHOE		= 0x7cc,
	IMAGE_FILE_MACHINE_THUMB		= 0x1c2,
	IMAGE_FILE_MACHINE_WCEMIPSV2	= 0x169
} MachineType;

typedef enum {
	// Image only, Windows CE, Windows NT and above. Indicates that the
	// file does not contain base relocations and must therefore be
	// loaded at its preferred base address. If the base address is not
	// available, the loader reports an error. The default behavior of
	// the linker is to strip base relocations from EXEs.
	IMAGE_FILE_RELOCS_STRIPPED			= 0x0001,

	// Image only. Indicates that the image file is valid and can be run.
	// If this flag is not set, it indicates a linker error.
	IMAGE_FILE_EXECUTABLE_IMAGE			= 0x0002,

	// COFF line numbers have been removed.
	// Deprecated and should be zero.
	IMAGE_FILE_LINE_NUMS_STRIPPED		= 0x0004,

	// COFF symbol table entries for local symbols have been removed.
	// Deprecated and should be zero.
	IMAGE_FILE_LOCAL_SYMS_STRIPPED		= 0x0008,

	// Obsolete. Aggressively trim working set.
	// Deprecated in Windows 2000 and later. Must be zero.
	IMAGE_FILE_AGGRESSIVE_WS_TRIM		= 0x0010,

	// App can handle > 2gb addresses.
	// Image can be loaded at address above 2GB.
	IMAGE_FILE_LARGE_ADDRESS_AWARE		= 0x0020,

	// Machine based on 16-bit-word architecture.
	IMAGE_FILE_16BIT_MACHINE		= 0x0040,

	// Bytes of the word are reversed from CPU defaults.
	// Test either IMAGE_FILE_BYTES_REVERSED_LO or IMAGE_FILE_BYTES_REVERSED_HI, they are in the same bit position in each short word.
	// Microsoft PE 32-Bit LINK.EXE Version 1.00 always sets this bit, but no words are reversed. New LINK.EXE versions never set this bit.
	// Deprecated and should be zero.
	IMAGE_FILE_BYTES_REVERSED_LO		= 0x0080,

	// Machine based on 32-bit-word architecture.
	IMAGE_FILE_32BIT_MACHINE			= 0x0100,

	// Debugging information removed from image file.
	IMAGE_FILE_DEBUG_STRIPPED			= 0x0200,

	// If image is on removable media, fully load it and copy it to the
	// swap file.
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	= 0x0400,

	// If image is on network media, fully load it and copy it to the
	// swap file.
	IMAGE_FILE_NET_RUN_FROM_SWAP		= 0x0800,

	// The image file is a system kernel-mode file, not a user program.
	// Images with this flag can't be loaded in user-mode. Images without
	// this flag can be loaded in both kernel-mode and user-mode.
	IMAGE_FILE_SYSTEM					= 0x1000,

	// The image file is a dynamic-link library (DLL). Such files are
	// considered executable files for almost all purposes, although
	// they cannot be directly run.
	IMAGE_FILE_DLL						= 0x2000,

	// File should be run only on a UP (uniprocessor) machine.
	// When running on multiprocessor machine, process has assigned
	// one selected core via CPU affinity on which it always run.
	IMAGE_FILE_UP_SYSTEM_ONLY			= 0x4000,

	// Bytes of the word are reversed from CPU defaults.
	// Test either IMAGE_FILE_BYTES_REVERSED_LO or IMAGE_FILE_BYTES_REVERSED_HI, they are in the same bit position in each short word.
	// Microsoft PE 32-Bit LINK.EXE Version 1.00 always sets this bit, but no words are reversed. New LINK.EXE versions never set this bit.
	// Deprecated and should be zero.
	IMAGE_FILE_BYTES_REVERSED_HI		= 0x8000
} ImageCharacteristics;

#pragma pack(push, 1)

typedef struct {
	uint16_t Machine; // MachineType
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics; // ImageCharacteristics
} IMAGE_FILE_HEADER, IMAGE_COFF_HEADER;

#pragma pack(pop)

#ifdef __cplusplus
} // extern "C"
#endif

#endif
