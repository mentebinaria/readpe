/*
	pev - the PE file analyzer toolkit

	pescan.c - search for suspicious things in PE files.

	Copyright (C) 2013 - 2020 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

#include "common.h"
#include <ctype.h>
#include <time.h>
#include <math.h>
#include "plugins.h"

#define PROGRAM "pescan"

typedef struct {
	bool verbose;
} options_t;

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s OPTIONS FILE\n"
		"Search for suspicious things in PE files\n"
		"\nExample: %s putty.exe\n"
		"\nOptions:\n"
		" -f, --format <%s>  Change output format (default: text).\n"
		" -v, --verbose                          Show more information about found items.\n"
		" -V, --version                          Show version.\n"
		" --help                                 Show this help.\n",
		PROGRAM, PROGRAM, formats);
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	/* Parameters for getopt_long() function */
	static const char short_options[] = "f:vV";

	static const struct option long_options[] = {
		{ "format",		required_argument,	NULL,	'f' },
		{ "help",		no_argument,		NULL,	 1  },
		{ "verbose",	no_argument,		NULL,	'v' },
		{ "version",	no_argument,		NULL,	'V' },
		{ NULL,			0,					NULL, 	 0  }
	};

	int c, ind;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1:		// --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'f':
				if (output_set_format_by_name(optarg) < 0)
					EXIT_ERROR("invalid format option");
				break;
			case 'v':
				options->verbose = true;
				break;
			case 'V':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	return options;
}

// check for abnormal dos stub (common in packed files)
static bool normal_dos_stub(pe_ctx_t *ctx, uint32_t *stub_offset)
{
	const uint8_t dos_stub[] =
		"\x0e"               // push cs
		"\x1f"               // pop ds
		"\xba\x0e\x00"       // mov dx, 0x0e
		"\xb4\x09"           // mov ah, 0x09
		"\xcd\x21"           // int 0x21
		"\xb8\x01\x4c"       // mov ax, 0x4c01
		"\xcd\x21"           // int 0x21
		"This program cannot be run in DOS mode.\r\r\n$";

	const size_t dos_stub_size = sizeof(dos_stub) - 1; // -1 to ignore ending null

	const IMAGE_DOS_HEADER *dos = pe_dos(ctx);
	if (dos == NULL) {
		LIBPE_WARNING("unable to retrieve PE DOS header");
		return false;
	}

	*stub_offset = dos->e_cparhdr << 4;

	// dos stub starts at e_cparhdr shifted by 4
	const char *dos_stub_ptr = LIBPE_PTR_ADD(ctx->map_addr, *stub_offset);
	if (!pe_can_read(ctx, dos_stub_ptr, dos_stub_size)) {
		LIBPE_WARNING("unable to seek in file");
		return false;
	}

	return memcmp(dos_stub, dos_stub_ptr, dos_stub_size) == 0;
}

static const IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(pe_ctx_t *ctx, uint32_t ep)
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

static uint32_t pe_get_tls_directory(pe_ctx_t *ctx)
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

/*
 * -1 - fake tls callbacks detected
 *  0 - no tls directory
 * >0 - number of callbacks functions found
*/
static int pe_get_tls_callbacks(pe_ctx_t *ctx, const options_t *options)
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

			char value[MAX_MSG];
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

					if (options->verbose) {
						snprintf(value, MAX_MSG, "%#x", funcaddr);
						output("TLS callback function", value);
					}
				}
			} while (funcaddr);

			return ret;
		}
	}

	return 0;
}

static bool strisprint(const char *string)
{
	const char *s = string;

	if (strncmp(string, ".tls", 5) == 0)
		return false;

	if (*s++ != '.')
		return false;

	while (*s)
	{
		if (!isalpha((int)*s))
			return false;

		s++;
	}
	return true;
}

static void stradd(char *dest, const char *src, bool *pad)
{
	if (*pad)
		strcat(dest, ", ");

	strcat(dest, src);
	*pad = true;
}

static void print_strange_sections(pe_ctx_t *ctx)
{
	const uint16_t num_sections = pe_sections_count(ctx);
	if (num_sections == 0)
		return;

	char value[MAX_MSG];

	if (ctx->pe.num_sections <= 2)
		snprintf(value, MAX_MSG, "%d (low)", num_sections);
	else if (ctx->pe.num_sections > 8)
		snprintf(value, MAX_MSG, "%d (high)", num_sections);
	else
		snprintf(value, MAX_MSG, "%d", num_sections);

	output("section count", value);

	IMAGE_SECTION_HEADER ** const sections = pe_sections(ctx);

	output_open_scope("sections", OUTPUT_SCOPE_TYPE_ARRAY);

	bool aux = false;
	for (uint16_t i=0; i < num_sections; i++, aux=false)
	{
		output_open_scope("section", OUTPUT_SCOPE_TYPE_OBJECT);
		memset(&value, 0, sizeof(value));

		if (!strisprint((const char *)sections[i]->Name))
			stradd(value, "suspicious name", &aux);

		if (sections[i]->SizeOfRawData == 0)
			stradd(value, "zero length", &aux);
		else if (sections[i]->SizeOfRawData <= 512)
			stradd(value, "small length", &aux);

		// rwx or writable + executable code
		if (sections[i]->Characteristics & IMAGE_SCN_MEM_WRITE &&
			(sections[i]->Characteristics & IMAGE_SCN_CNT_CODE ||
			sections[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			stradd(value, "self-modifying", &aux);

		if (!aux)
			strncpy(value, "normal", 7);

		output((const char *)sections[i]->Name, value);
		output_close_scope(); // section
	}
	output_close_scope(); // sections
}

static bool normal_imagebase(pe_ctx_t *ctx)
{
	return  (ctx->pe.imagebase == 0x100000000 ||
				ctx->pe.imagebase == 0x1000000 ||
				ctx->pe.imagebase == 0x400000);
}

// new anti-disassembly technique with undocumented Intel FPU instructions
static bool fpu_trick(pe_ctx_t *ctx)
{
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

static void print_timestamp(const options_t *options, const IMAGE_COFF_HEADER *hdr_coff_ptr)
{
	const time_t now = time(NULL);
	char value[MAX_MSG];

	if (hdr_coff_ptr->TimeDateStamp == 0)
		snprintf(value, MAX_MSG, "zero/invalid");
	else if (hdr_coff_ptr->TimeDateStamp < 946692000)
		snprintf(value, MAX_MSG, "too old (pre-2000)");
	else if (hdr_coff_ptr->TimeDateStamp > (uint32_t) now)
		snprintf(value, MAX_MSG, "future time");
	else
		snprintf(value, MAX_MSG, "normal");

	if (options->verbose)
	{
		char timestr[33];
		strftime(timestr, sizeof(timestr),
			" - %a, %d %b %Y %H:%M:%S UTC",
			gmtime((time_t *) &hdr_coff_ptr->TimeDateStamp));

		strcat(value, timestr);
	}

	output("timestamp", value);
}

static int8_t cpl_analysis(pe_ctx_t *ctx)
{
	const IMAGE_COFF_HEADER *hdr_coff_ptr = pe_coff(ctx);
	const IMAGE_DOS_HEADER *hdr_dos_ptr = pe_dos(ctx);

	if (hdr_coff_ptr == NULL || hdr_dos_ptr == NULL)
		return -1;

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

int main(int argc, char *argv[])
{
	pev_config_t config;
	PEV_INITIALIZE(&config);

	if (argc < 2) {
		usage();
		return EXIT_FAILURE;
	}

	output_set_cmdline(argc, argv);

	options_t *options = parse_options(argc, argv); // opcoes

	const char *path = argv[argc-1];
	pe_ctx_t ctx;

	pe_err_e err = pe_load_file(&ctx, path);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	err = pe_parse(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	if (!pe_is_pe(&ctx))
		EXIT_ERROR("not a valid PE file");

	output_open_document();

	// File entropy
	const double entropy = pe_calculate_entropy_file(&ctx);

	char value[MAX_MSG];

	if (entropy < 7.0)
		snprintf(value, MAX_MSG, "%f (normal)", entropy);
	else
		snprintf(value, MAX_MSG, "%f (probably packed)", entropy);
	output("file entropy", value);

	if (pe_is_dll(&ctx)) {
		uint16_t ret = cpl_analysis(&ctx);
		switch (ret) {
			case 1:
				output("cpl analysis", "malware");
				break;
			default:
				output("cpl analysis:", "no threat");
				break;
		}
	}

	output("fpu anti-disassembly", fpu_trick(&ctx) ? "yes" : "no");

	// imagebase analysis
	if (!normal_imagebase(&ctx)) {
		if (options->verbose)
			snprintf(value, MAX_MSG, "suspicious - %#"PRIx64, ctx.pe.imagebase);
		else
			snprintf(value, MAX_MSG, "suspicious");
	} else {
		if (options->verbose)
			snprintf(value, MAX_MSG, "normal - %#"PRIx64, ctx.pe.imagebase);
		else
			snprintf(value, MAX_MSG, "normal");
	}
	output("imagebase", value);

	const IMAGE_OPTIONAL_HEADER *optional = pe_optional(&ctx);
	if (optional == NULL) {
		LIBPE_WARNING("unable to read optional header");
	} else {
		uint32_t ep = (optional->_32 ? optional->_32->AddressOfEntryPoint :
			(optional->_64 ? optional->_64->AddressOfEntryPoint : 0));

		// fake ep
		if (ep == 0) {
			snprintf(value, MAX_MSG, "null");
		} else if (pe_check_fake_entrypoint(&ctx, ep)) {
			if (options->verbose)
				snprintf(value, MAX_MSG, "fake - va: %#x - raw: %#"PRIx64, ep, pe_rva2ofs(&ctx, ep));
			else
				snprintf(value, MAX_MSG, "fake");
		} else {
			if (options->verbose)
				snprintf(value, MAX_MSG, "normal - va: %#x - raw: %#"PRIx64, ep, pe_rva2ofs(&ctx, ep));
			else
				snprintf(value, MAX_MSG, "normal");
		}

		output("entrypoint", value);
	}

	// dos stub
	uint32_t stub_offset;
	if (!normal_dos_stub(&ctx, &stub_offset)) {
		if (options->verbose)
			snprintf(value, MAX_MSG, "suspicious - raw: %#x", stub_offset);
		else
			snprintf(value, MAX_MSG, "suspicious");
	} else
		snprintf(value, MAX_MSG, "normal");

	output("DOS stub", value);

	// tls callbacks
	int callbacks = pe_get_tls_callbacks(&ctx, options);

	if (callbacks == 0)
		snprintf(value, MAX_MSG, "not found");
	else if (callbacks == -1)
		snprintf(value, MAX_MSG, "found - no functions");
	else if (callbacks > 0)
		snprintf(value, MAX_MSG, "found - %d function(s)", callbacks);

	output("TLS directory", value);

	// invalid timestamp
	IMAGE_COFF_HEADER *coff = pe_coff(&ctx);
	if (coff == NULL) {
		LIBPE_WARNING("unable to read coff header");
	} else {
		print_timestamp(options, coff);
	}

	// section analysis
	print_strange_sections(&ctx);

	output_close_document();

	// free memory
	free_options(options);
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	PEV_FINALIZE(&config);

	return EXIT_SUCCESS;
}
