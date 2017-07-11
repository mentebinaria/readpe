#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include "pe.h"

double calculate_entropy(const unsigned int counted_bytes[256], const size_t total_length)
{
	static const double log_2 = 1.44269504088896340736;
	double entropy = 0.;

	for (size_t i = 0; i < 256; i++) {
		double temp = (double)counted_bytes[i] / total_length;
		if (temp > 0.)
			entropy += fabs(temp * (log(temp) * log_2));
	}

	return entropy;
}

double calculate_entropy_file(pe_ctx_t *ctx) {
	unsigned int counted_bytes[256];
	memset(counted_bytes, 0, sizeof(counted_bytes));

	const uint8_t *file_bytes = LIBPE_PTR_ADD(ctx->map_addr, 0);
	const uint64_t filesize = pe_filesize(ctx);
	for (uint64_t ofs=0; ofs < filesize; ofs++) {
		const uint8_t byte = file_bytes[ofs];
		counted_bytes[byte]++;
	}

	return calculate_entropy(counted_bytes, (size_t)filesize);
}

bool fpu_trick(pe_ctx_t *ctx) {
	const char *opcode_ptr = ctx->map_addr;

	for (uint32_t i=0, times=0; i < ctx->map_size; i++) {
		if (*opcode_ptr++ == '\xdf') {
			if (++times == 4)
				return true;
		}
		else
			times = 0;
	}

	return false;
}

int cpl_analysis(pe_ctx_t *ctx)
{
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

	if ((hdr_coff_ptr->TimeDateStamp == 708992537 ||
				hdr_coff_ptr->TimeDateStamp > 1354555867)
			&& (hdr_coff_ptr->Characteristics == characteristics1 || // equals 0xa18e
				hdr_coff_ptr->Characteristics == characteristics2 || // equals 0xa38e
				hdr_coff_ptr->Characteristics == characteristics3) // equals 0x2306
			&& hdr_dos_ptr->e_sp == 0xb8
		 )
		return 1;

	return 0;
}

int get_cpl_analysis(pe_ctx_t *ctx) {
	int ret;
	if (pe_is_dll(ctx)) {
		ret = cpl_analysis(ctx);
	} else {
		ret = -1; 
	}
	return ret;
}

const IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(pe_ctx_t *ctx, uint32_t ep)
{
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

int check_fake_entrypoint(pe_ctx_t *ctx) {
	const IMAGE_OPTIONAL_HEADER *optional = pe_optional(ctx);
	if (optional == NULL)
		return INT_MAX; // Unable to read optional header.
	uint32_t ep = (optional->_32 ? optional->_32->AddressOfEntryPoint :
			(optional->_64 ? optional->_64->AddressOfEntryPoint : 0));

	// fake ep
	int value;

	if (ep == 0) {
		value = -1; // null
	} 
	else if (pe_check_fake_entrypoint(ctx, ep)) {
		value = 1; // fake 
	} 
	else {
		value = 0;       // normal 
	}
	return value;
}

uint32_t pe_get_tls_directory(pe_ctx_t *ctx)
{
	if (ctx->pe.num_directories == 0 || ctx->pe.num_directories > MAX_DIRECTORIES)
		return 0;

	const IMAGE_DATA_DIRECTORY *directory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_TLS);
	if (directory == NULL)
		return 0;

	if (directory->Size == 0)
		return 0;

	return directory->VirtualAddress;
}

int pe_get_tls_callbacks(pe_ctx_t *ctx)
{
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
	for (uint16_t i=0, j=0; i < num_sections; i++)
	{
		if (tls_addr >= sections[i]->VirtualAddress &&
				tls_addr < (sections[i]->VirtualAddress + sections[i]->SizeOfRawData))
		{
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

			//char value[MAX_MSG];
			uint32_t funcaddr = 0;

			do
			{
				const uint32_t *funcaddr_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, funcaddr_ptr, sizeof(*funcaddr_ptr))) {
					// TODO: Should we report something?
					return 0;
				}

				uint32_t funcaddr = *funcaddr_ptr;
				if (funcaddr) {
					ret = ++j; // function found
				}
			} while (funcaddr);

			return ret;
		}
	}

	return 0;
}

int get_tls_callback(pe_ctx_t *ctx) {
	int callbacks = pe_get_tls_callbacks(ctx);
	int ret;
	if (callbacks == 0)
		ret = INT_MIN; // not found
	else if (callbacks == -1)
		ret = INT_MAX; // found no functions
	else if (callbacks > 0)
		ret = callbacks;
	return ret;
}
