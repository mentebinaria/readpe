/*
	pev - the PE file analyzer toolkit

	pescan.c - search for suspicious things in PE files

	Copyright (C) 2012 pev authors

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

#include "pescan.h"
#include <ctype.h>
#include <time.h>
#include <math.h>

typedef struct {
	bool verbose;
} options_t;

static void usage(void)
{
	printf("\n%s %s\n%s\n\nUsage: %s OPTIONS FILE\n"
		"Search for suspicious things in PE files\n"
		"\nExample: %s putty.exe\n"
		"\nOptions:\n"
	   " -f, --format <text|csv|xml|html>       change output format (default: text)\n"
		" -v, --verbose                          show more info about items found\n"
		" --help                                 show this help and exit\n",
		PROGRAM, TOOLKIT, COPY, PROGRAM, PROGRAM);
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = xmalloc(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	/* Parameters for getopt_long() function */
	static const char short_options[] = "f:v";

	static const struct option long_options[] = {
		{"format",		required_argument,	NULL,	'f'},
		{"help",		no_argument,		NULL,	 1 },
		{"verbose",		no_argument,		NULL,	'v'},
		{ NULL,			0,					NULL, 	 0 }
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
				parse_format(optarg);
				break;
			case 'v':
				options->verbose = true;
				break;
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	return options;
}

// check for abnormal dos stub (common in packed files)
/*
static bool normal_dos_stub(PE_FILE *pe, DWORD *stub_offset)
{
   BYTE dos_stub[] =
	   "\x0e"               // push cs
	   "\x1f"               // pop ds
	   "\xba\x0e\x00"       // mov dx, 0x0e
	   "\xb4\x09"           // mov ah, 0x09
	   "\xcd\x21"           // int 0x21
	   "\xb8\x01\x4c"       // mov ax, 0x4c01
	   "\xcd\x21"           // int 0x21
	   "This program cannot be run in DOS mode.\r\r\n$";

   BYTE data[sizeof(dos_stub)-1]; // -1 to ignore ending null
   IMAGE_DOS_HEADER dos;

   if (!pe_get_dos(pe, &dos))
      EXIT_ERROR("unable to retrieve PE DOS header");

	*stub_offset = dos.e_cparhdr << 4;

   // dos stub starts at e_cparhdr shifted by 4
   if (fseek(pe->handle, *stub_offset, SEEK_SET))
      EXIT_ERROR("unable to seek in file");

   if (!fread(&data, sizeof(data), 1, pe->handle))
      EXIT_ERROR("unable to read DOS stub");

   if (memcmp(dos_stub, data, sizeof(data))==0)
      return true;

   return false;
}

static IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(PE_FILE *pe, DWORD *ep)
{
	IMAGE_SECTION_HEADER *epsec = NULL;

	if (!pe->optional_ptr)
		pe_get_optional(pe);

	if (!pe->num_sections || !pe->sections_ptr)
		pe_get_sections(pe);

	if (!pe->num_sections)
		return NULL;

	epsec = pe_rva2section(pe, *ep);

	if (!epsec)
		return NULL;

	if (!(epsec->Characteristics & 0x20))
		return epsec;

   return NULL;
}

static DWORD pe_get_tls_directory(PE_FILE *pe)
{
	if (!pe_get_directories(pe))
		return 0;

	if (pe->num_directories > 32)
		return 0;

	IMAGE_DATA_DIRECTORY *directory = pe_get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_TLS);
	if (!directory)
		return false;

	if (directory->Size > 0)
		return directory->VirtualAddress;

	return 0;
}
*/
/*
 * -1 - fake tls callbacks detected
 *  0 - no tls directory
 * >0 - number of callbacks functions found
*/
/*
static int pe_get_tls_callbacks(PE_FILE *pe)
{
	QWORD tls_addr = 0;
	int ret = 0;

	if (!pe)
		return 0;

	tls_addr = pe_get_tls_directory(pe);

	if (!tls_addr || !pe_get_sections(pe))
		return 0;


	// search for tls in all sections
	for (unsigned int i=0, j=0; i < pe->num_sections; i++)
	{
		if (tls_addr >= pe->sections_ptr[i]->VirtualAddress &&
		tls_addr < (pe->sections_ptr[i]->VirtualAddress + pe->sections_ptr[i]->SizeOfRawData))
		{
			unsigned int funcaddr = 0;

			if (fseek(pe->handle, tls_addr - pe->sections_ptr[i]->VirtualAddress
			+ pe->sections_ptr[i]->PointerToRawData, SEEK_SET))
			 	return 0;

			if (pe->architecture == PE32)
			{
				IMAGE_TLS_DIRECTORY32 tlsdir32;

				if (!fread(&tlsdir32, sizeof(tlsdir32), 1, pe->handle))
					return 0;

				if (! (tlsdir32.AddressOfCallBacks & pe->optional_ptr->_32->ImageBase))
					break;

				if (fseek(pe->handle,
						rva2ofs(pe, tlsdir32.AddressOfCallBacks - pe->optional_ptr->_32->ImageBase), SEEK_SET))
					return 0;
			}
			else if (pe->architecture == PE64)
			{
				IMAGE_TLS_DIRECTORY64 tlsdir64;

				if (!fread(&tlsdir64, sizeof(tlsdir64), 1, pe->handle))
					return 0;

				if (! (tlsdir64.AddressOfCallBacks & pe->optional_ptr->_64->ImageBase))
					break;

				if (fseek(pe->handle,
				 rva2ofs(pe, tlsdir64.AddressOfCallBacks - pe->optional_ptr->_64->ImageBase), SEEK_SET))
					return 0;
			}
			else
				return 0;

			ret = -1; // tls directory and section exists
			do
			{
				fread(&funcaddr, sizeof(int), 1, pe->handle);
				if (funcaddr)
				{
					char value[MAX_MSG];

					ret = ++j; // function found

					if (config.verbose)
					{
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
	char *s = (char *) string;

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

static void stradd(char *dest, char *src, bool *pad)
{
	if (*pad)
		strcat(dest, ", ");

	strcat(dest, src);
	*pad = true;
}

static void print_strange_sections(PE_FILE *pe)
{
	bool aux = false;

	if (!pe_get_sections(pe) || !pe->num_sections)
		return;

	if (pe->num_sections <= 2)
		snprintf(value, MAX_MSG, "%d (low)", pe->num_sections);
	else if (pe->num_sections > 8)
		snprintf(value, MAX_MSG, "%d (high)", pe->num_sections);
	else
		snprintf(value, MAX_MSG, "%d", pe->num_sections);

	output("section count", value);
	for (unsigned i=0; i < pe->num_sections && i <= 65535; i++, aux=false)
	{
		memset(&value, 0, sizeof(value));

		if (!strisprint((const char *)pe->sections_ptr[i]->Name))
			stradd(value, "suspicious name", &aux);

		if (!pe->sections_ptr[i]->SizeOfRawData)
			stradd(value, "zero length", &aux);
		else if (pe->sections_ptr[i]->SizeOfRawData <= 512)
			stradd(value, "small length", &aux);

		// rwx or writable + executable code
		if (pe->sections_ptr[i]->Characteristics & 0x80000000 &&
		(pe->sections_ptr[i]->Characteristics & 0x20 ||
		pe->sections_ptr[i]->Characteristics & 0x20000000))
			stradd(value, "self-modifying", &aux);

		if (!aux)
			strncpy(value, "normal", 7);

		output((char *)pe->sections_ptr[i]->Name, value);
	}
}

static bool normal_imagebase(PE_FILE *pe)
{
	if (!pe->imagebase)
		pe_get_optional(pe);

	return  (pe->imagebase == 0x100000000 ||
				pe->imagebase == 0x1000000 ||
				pe->imagebase == 0x400000);
}

static void print_timestamp(DWORD *stamp)
{
	time_t now = time(NULL);
	char timestr[33];

	if (*stamp == 0)
		snprintf(value, MAX_MSG, "zero/invalid");
	else if (*stamp < 946692000)
		snprintf(value, MAX_MSG, "too old (pre-2000)");
	else if (*stamp > (DWORD) now)
		snprintf(value, MAX_MSG, "future time");
	else
		snprintf(value, MAX_MSG, "normal");

	if (config.verbose)
	{
		strftime(timestr, sizeof(timestr),
			" - %a, %d %b %Y %H:%M:%S UTC",
			gmtime((time_t *) stamp));

		strcat(value, timestr);
		//strcat(value, " - ");
		//strcat(value, ctime((time_t *) stamp));
	}

	output("timestamp", value);

}
*/

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

double calculate_entropy_file(pe_ctx_t *ctx)
{
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

int8_t cpl_analysis(pe_ctx_t *ctx)
{
	IMAGE_COFF_HEADER *hdr_coff_ptr = pe_coff(ctx);
	IMAGE_DOS_HEADER *hdr_dos_ptr = pe_dos(ctx);

	if (!hdr_coff_ptr || !hdr_dos_ptr)
		return -1;

	if (
		 (hdr_coff_ptr->TimeDateStamp == 708992537 ||
		 hdr_coff_ptr->TimeDateStamp > 1354555867) &&
		 (hdr_coff_ptr->Characteristics == 0xa18e ||
		  hdr_coff_ptr->Characteristics == 0xa38e ||
		  hdr_coff_ptr->Characteristics == 0x2306) &&
		 hdr_dos_ptr->e_sp == 0xb8
		)
		return 1;

	return 0;
	
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		return EXIT_FAILURE;
	}

	options_t *options = parse_options(argc, argv); // opcoes

	const char *path = argv[argc-1];
	pe_ctx_t ctx;

	pe_err_e err = pe_load(&ctx, path);
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

	static char value[MAX_MSG];

	// File entropy
	double entropy = calculate_entropy_file(&ctx);

	if (entropy < 7.0)
		snprintf(value, MAX_MSG, "normal (%f)", entropy);
	else
		snprintf(value, MAX_MSG, "packed (%f)", entropy);
	output("file entropy", value);

	if (pe_is_dll(&ctx)) {
		uint16_t ret = cpl_analysis(&ctx);
		switch (ret) {
			case 1:
				output("cpl analysis", "banker");
				break;
			default:
				output("cpl analysis:", "no threat");
				break;
		}
	}


/*
	if (!pe_get_optional(&pe))
		return 1;

  	ep = (pe.optional_ptr->_32 ? pe.optional_ptr->_32->AddressOfEntryPoint :
	(pe.optional_ptr->_64 ? pe.optional_ptr->_64->AddressOfEntryPoint : 0));

	// fake ep
	if (ep == 0)
		snprintf(value, MAX_MSG, "null");
	else if (pe_check_fake_entrypoint(&pe, &ep)) {
		if (config.verbose)
			snprintf(value, MAX_MSG, "fake - va: %#x - raw: %#"PRIx64, ep, rva2ofs(&pe, ep));
		else
			snprintf(value, MAX_MSG, "fake");
	} else {
		if (config.verbose)
			snprintf(value, MAX_MSG, "normal - va: %#x - raw: %#"PRIx64, ep, rva2ofs(&pe, ep));
		else
			snprintf(value, MAX_MSG, "normal");
	}

	output("entrypoint", value);

	// dos stub
	memset(&value, 0, sizeof(value));
	if (!normal_dos_stub(&pe, &stub_offset)) {
		if (config.verbose)
			snprintf(value, MAX_MSG, "suspicious - raw: %#x", stub_offset);
		else
			snprintf(value, MAX_MSG, "suspicious");
	} else
		snprintf(value, MAX_MSG, "normal");

	output("DOS stub", value);

	// tls callbacks
	callbacks = pe_get_tls_callbacks(&pe);

	if (callbacks == 0)
		snprintf(value, MAX_MSG, "not found");
	else if (callbacks == -1)
		snprintf(value, MAX_MSG, "found - no functions");
	else if (callbacks >0)
		snprintf(value, MAX_MSG, "found - %d function(s)", callbacks);

	output("TLS directory", value);
	memset(&value, 0, sizeof(value));

	// section analysis
	print_strange_sections(&pe);

	// no imagebase
	if (!normal_imagebase(&pe)) {
		if (config.verbose)
			snprintf(value, MAX_MSG, "suspicious - %#"PRIx64, pe.imagebase);
		else
			snprintf(value, MAX_MSG, "suspicious");
	} else {
		if (config.verbose)
			snprintf(value, MAX_MSG, "normal - %#"PRIx64, pe.imagebase);
		else
			snprintf(value, MAX_MSG, "normal");
	}
	output("imagebase", value);

	// invalid timestamp
	IMAGE_COFF_HEADER coff;

	if (!pe_get_coff(&pe, &coff))
		EXIT_ERROR("unable to read coff header");

	print_timestamp(&coff.TimeDateStamp);
*/

	// libera a memoria
	free_options(options);

	// free
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
