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

// for memmem() to work.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "libpe/pe.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

static double calculate_entropy(const unsigned int counted_bytes[256], const size_t total_length) {
	double entropy = 0.;

	for (size_t i = 0; i < 256; i++) {
		double temp = (double)counted_bytes[i] / total_length;
		if (temp > 0.)
			entropy += temp * fabs( log2(temp) );
	}

	return entropy;
}

double pe_calculate_entropy_file(pe_ctx_t *ctx) {
	unsigned int counted_bytes[256] = { 0 };

	const uint8_t *file_bytes = LIBPE_PTR_ADD(ctx->map_addr, 0);
	const uint64_t filesize = pe_filesize(ctx);
	for (uint64_t ofs=0; ofs < filesize; ofs++) {
		const uint8_t byte = file_bytes[ofs];
		counted_bytes[byte]++;
	}

	return calculate_entropy(counted_bytes, (size_t)filesize);
}

bool pe_fpu_trick(pe_ctx_t *ctx) {
  // NOTE: What 0xdf has to do with fpu?
	return !! memmem( ctx->map_addr, ctx->map_size, "\xdf\xdf\xdf\xdf", 4 );

//	const char *opcode_ptr = ctx->map_addr;
//
//	for (uint32_t i=0, times=0; i < ctx->map_size; i++) {
//		if (*opcode_ptr++ == '\xdf') {
//			if (++times == 4)
//				return true;
//		} else {
//			times = 0;
//		}
//	}
//
//	return false;
}

int cpl_analysis(pe_ctx_t *ctx) {
	const IMAGE_COFF_HEADER *hdr_coff_ptr = pe_coff(ctx);
	const IMAGE_DOS_HEADER *hdr_dos_ptr = pe_dos(ctx);

	if (hdr_coff_ptr == NULL || hdr_dos_ptr == NULL)
		return 0;

	static const uint16_t characteristics1 =
		( IMAGE_FILE_EXECUTABLE_IMAGE
			| IMAGE_FILE_LINE_NUMS_STRIPPED
			| IMAGE_FILE_LOCAL_SYMS_STRIPPED
			| IMAGE_FILE_BYTES_REVERSED_LO
			| IMAGE_FILE_32BIT_MACHINE
			| IMAGE_FILE_DLL
			| IMAGE_FILE_BYTES_REVERSED_HI);
	static const uint16_t characteristics2 =
		( IMAGE_FILE_EXECUTABLE_IMAGE
			| IMAGE_FILE_LINE_NUMS_STRIPPED
			| IMAGE_FILE_LOCAL_SYMS_STRIPPED
			| IMAGE_FILE_BYTES_REVERSED_LO
			| IMAGE_FILE_32BIT_MACHINE
			| IMAGE_FILE_DEBUG_STRIPPED
			| IMAGE_FILE_DLL
			| IMAGE_FILE_BYTES_REVERSED_HI);
	static const uint16_t characteristics3 =
		( IMAGE_FILE_EXECUTABLE_IMAGE
			| IMAGE_FILE_LINE_NUMS_STRIPPED
			| IMAGE_FILE_32BIT_MACHINE
			| IMAGE_FILE_DEBUG_STRIPPED
			| IMAGE_FILE_DLL);

	// FIXME: Which timestamps are those?
	// UNIX timestams:
	//    708992537 = 19/jun/1992 @ 19:22:17
	//   1354555867 =  3/dez/2012 @ 15:31:07
	//
	// Findings:
	// *  708992537 is the timestamp from an old delphi compiler bug
	// * 1354555867 was probably just the current time
	if ((hdr_coff_ptr->TimeDateStamp == 708992537 ||
				hdr_coff_ptr->TimeDateStamp > 1354555867)
			&& (hdr_coff_ptr->Characteristics == characteristics1 || // equals 0xa18e
				hdr_coff_ptr->Characteristics == characteristics2 || // equals 0xa38e
				hdr_coff_ptr->Characteristics == characteristics3) // equals 0x2306
			&& hdr_dos_ptr->e_sp == 0xb8    // ???
		 )
		return 1;

	return 0;
}

int pe_get_cpl_analysis(pe_ctx_t *ctx) {
	return pe_is_dll(ctx) ? cpl_analysis(ctx) : -1;
}

const IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(pe_ctx_t *ctx, uint32_t ep) {
	const uint16_t num_sections = pe_sections_count(ctx);
	if (num_sections == 0)
		return NULL;

	const IMAGE_SECTION_HEADER *section = pe_rva2section(ctx, ep);
	if (section == NULL)
		return NULL;

	if (section->Characteristics & IMAGE_SCN_CNT_CODE)
		return NULL;

	return section;
}

int pe_has_fake_entrypoint(pe_ctx_t *ctx) {
	const IMAGE_OPTIONAL_HEADER *optional = pe_optional(ctx);
	if (optional == NULL)
		return -1; // Unable to read optional header.

	const uint32_t ep = optional->_32
		? optional->_32->AddressOfEntryPoint
		: (optional->_64 ? optional->_64->AddressOfEntryPoint : 0);

	int value;

	if (ep == 0) {
		value = -2; // null
	}  else if (pe_check_fake_entrypoint(ctx, ep)) {
		value = 1; // fake 
	}  else {
		value = 0; // normal
	}

	return value;
}

uint32_t pe_get_tls_directory(pe_ctx_t *ctx) {
	if (ctx->pe.num_directories == 0 || ctx->pe.num_directories > MAX_DIRECTORIES)
		return 0;

	const IMAGE_DATA_DIRECTORY *directory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_TLS);
	if (directory == NULL)
		return 0;

	if (directory->Size == 0)
		return 0;

	return directory->VirtualAddress;
}

static int count_tls_callbacks(pe_ctx_t *ctx) {
	int ret = 0;

	const IMAGE_OPTIONAL_HEADER *optional_hdr = pe_optional(ctx);
	if (optional_hdr == NULL)
		return 0;

	IMAGE_SECTION_HEADER ** const sections = pe_sections(ctx);
	if (sections == NULL)
		return 0;

	const uint64_t tls_addr = pe_get_tls_directory(ctx);
	if (tls_addr == 0)
		return 0;

	const uint16_t num_sections = pe_sections_count(ctx);

	uint64_t ofs = 0;

	// search for tls in all sections
	for (uint16_t i=0, j=0; i < num_sections; i++) {
		const bool can_process = tls_addr >= sections[i]->VirtualAddress
			&& tls_addr < (sections[i]->VirtualAddress + sections[i]->SizeOfRawData);

		if (!can_process)
			continue;
		
		ofs = tls_addr - sections[i]->VirtualAddress + sections[i]->PointerToRawData;

		switch (optional_hdr->type) {
			default: 
				return 0;
			case MAGIC_PE32:
			{
				const IMAGE_TLS_DIRECTORY32 *tls_dir = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, tls_dir, sizeof(IMAGE_TLS_DIRECTORY32))) {
					// TODO: Should we report something?
					return 0;
				}

				if (!(tls_dir->AddressOfCallBacks & optional_hdr->_32->ImageBase))
					break;

				ofs = pe_rva2ofs(ctx, tls_dir->AddressOfCallBacks - optional_hdr->_32->ImageBase);
				break;
			}
			case MAGIC_PE64:
			{
				const IMAGE_TLS_DIRECTORY64 *tls_dir = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, tls_dir, sizeof(IMAGE_TLS_DIRECTORY64))) {
					// TODO: Should we report something?
					return 0;
				}

				if (!(tls_dir->AddressOfCallBacks & optional_hdr->_64->ImageBase))
					break;

				ofs = pe_rva2ofs(ctx, tls_dir->AddressOfCallBacks - optional_hdr->_64->ImageBase);
				break;
			}
		}

		ret = -1; // tls directory and section exists

		uint32_t funcaddr = 0;

		// FIXME: Why this loop if 'funcaddr' isn't updated?
		do {
			const uint32_t *funcaddr_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
			if (!pe_can_read(ctx, funcaddr_ptr, sizeof(*funcaddr_ptr))) {
				// TODO: Should we report something?
				return 0;
			}

			// FIXME: This funcaddr is declared in block scope!
			uint32_t funcaddr = *funcaddr_ptr;
			if (funcaddr) {
				ret = ++j; // function found
			}
		} while (funcaddr);
	}

	return ret;
}

int pe_get_tls_callback(pe_ctx_t *ctx) {
	const int callbacks = count_tls_callbacks(ctx);
	int ret = 0;

	if (callbacks == 0)
		ret = LIBPE_E_NO_CALLBACKS_FOUND; // not found
	else if (callbacks == -1)			  // FIXME: Is this correct?
		ret = LIBPE_E_NO_FUNCTIONS_FOUND; // found no functions
	else if (callbacks > 0)
		ret = callbacks;
	
	return ret;
}
