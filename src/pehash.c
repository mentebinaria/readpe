/*
	pev - the PE file analyzer toolkit

	pehash.c - calculate hashes of PE pieces

	Copyright (C) 2012 - 2017 pev authors

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
#include <openssl/evp.h>
#include <openssl/md5.h>
#include "../lib/libfuzzy/fuzzy.h"
#include "plugins.h"
#include "utlist.h"
#include "utils.h"
#include "ordlookup.h"

#define PROGRAM "pehash"

#define IMPHASH_FLAVOR_MANDIANT 1
#define IMPHASH_FLAVOR_PEFILE 2

unsigned pefile_warn = 0;

typedef struct {
	bool all;
	bool content;
	struct {
		bool all;
		bool dos;
		bool coff;
		bool optional;
	} headers;
	struct {
		char *name;
		uint16_t index;
	} sections;
} options_t;

/* By liw. */
static char *last_strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0')
        return (char *) haystack;

    char *result = NULL;
    for (;;) {
        char *p = strstr(haystack, needle);
        if (p == NULL)
            break;
        result = p;
        haystack = p + 1;
    }

    return result;
}

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s OPTIONS FILE\n"
		"Calculate hashes of PE pieces\n"
		"\nExample: %s -s '.text' winzip.exe\n"
		"\nOptions:\n"
		" -f, --format <%s> change output format (default: text)\n"
		" -a, --all                             hash file, sections and headers with md5, sha1, sha256, ssdeep and imphash\n"
		" -c, --content                         hash only the file content (default)\n"
		" -h, --header <dos|coff|optional>      hash only the header with the specified name\n"
		" -s, --section <section_name>          hash only the section with the specified name\n"
		" --section-index <section_index>       hash only the section at the specified index (1..n)\n"
		" -V, --version                         show version and exit\n"
		" --help                                show this help and exit\n",
		PROGRAM, PROGRAM, formats);
}

static void parse_header_name(options_t *options, const char *optarg)
{
	if (strcmp(optarg, "dos") == 0)
		options->headers.dos = true;
	else if (strcmp(optarg, "coff") == 0)
		options->headers.coff = true;
	else if (strcmp(optarg, "optional") == 0)
		options->headers.optional = true;
	else
		EXIT_ERROR("invalid header name option");
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	if (options->sections.name != NULL)
		free(options->sections.name);

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	// parameters for getopt_long() function
	static const char short_options[] = "f:a:c:h:s:V";

	static const struct option long_options[] = {
		{ "help",          no_argument,         NULL,  1  },
		{ "format",        required_argument,   NULL, 'f' },
		{ "all",           no_argument,         NULL, 'a' },
		{ "content",       no_argument,         NULL, 'c' },
		{ "header",        required_argument,   NULL, 'h' },
		{ "section-name",  required_argument,   NULL, 's' },
		{ "section-index", required_argument,   NULL,  2  },
		{ "version",       no_argument,         NULL, 'V' },
		{  NULL,           0,                   NULL,  0  }
	};

	// Setting the default option
	options->content = true;

	int c, ind;
	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1:     // --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'f':
				if (output_set_format_by_name(optarg) < 0)
					EXIT_ERROR("invalid format option");
				break;
			case 'a':
				options->all = true;
				break;
			case 'c': // default
				options->all = false; //TODO remover?
				options->content = true;
				break;
			case 's':
				options->all = false;
				options->headers.all = false;
				// TODO: How do we need to handle non-ascii names?
				options->sections.name = strdup(optarg);
				break;
			case 2:
				options->all = false;
				options->headers.all = false;
				options->sections.index = strtol(optarg, NULL, 10);
				if (options->sections.index < 1 || options->sections.index > MAX_SECTIONS) {
					EXIT_ERROR("Bad argument for section-index,");
				}
				break;
			case 'V':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			case 'h':
				options->all = false;
				options->headers.all = false;
				parse_header_name(options, optarg);
				break;
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	// TODO: Warn about simultaneous usage of -h, -s, and --section-index.

	return options;
}

static void calc_hash(const char *alg_name, const unsigned char *data, size_t size, char *output)
{
	if (strcmp("ssdeep", alg_name) == 0) {
		fuzzy_hash_buf(data, size, output);
		return;
	}

	const EVP_MD *md = EVP_get_digestbyname(alg_name);
	//assert(md != NULL); // We already checked this in parse_hash_algorithm()

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

// See https://wiki.openssl.org/index.php/1.1_API_Changes
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX md_ctx_auto;
	EVP_MD_CTX *md_ctx = &md_ctx_auto;
#else
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
#endif

	// FIXME: Handle errors - Check return values.
	EVP_MD_CTX_init(md_ctx);
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, data, size);
	EVP_DigestFinal_ex(md_ctx, md_value, &md_len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_cleanup(md_ctx);
#else
	EVP_MD_CTX_free(md_ctx);
#endif

	for (unsigned int i=0; i < md_len; i++)
		sprintf(&output[i * 2], "%02x", md_value[i]);
}

static void print_basic_hash(const unsigned char *data, size_t size)
{
	char *basic_hashes[] = { "md5", "sha1", "sha256", "ssdeep" };
	char hash_value[EVP_MAX_MD_SIZE * 2 + 1];

	if (!data || !size)
		return;

	for (unsigned i=0; i < sizeof(basic_hashes) / sizeof(char *); i++) {
		calc_hash(basic_hashes[i], data, size, hash_value);
		output(basic_hashes[i], hash_value);
	}
}

typedef struct element {
    char *dll_name;
    char *function_name;
    //struct element *prev; /* needed for a doubly-linked list only */
    struct element *next; /* needed for singly- or doubly-linked lists */
} element;

static void imphash_load_imported_functions(pe_ctx_t *ctx, uint64_t offset, char *dll_name, struct element **head, int flavor)
{
	uint64_t ofs = offset;

	char hint_str[16];
	char fname[MAX_FUNCTION_NAME];
	bool is_ordinal;

	memset(hint_str, 0, sizeof(hint_str));
	memset(fname, 0, sizeof(fname));

	while (1) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
			{
				const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
					// TODO: Should we report something?
					return;
				}

				// Type punning
				const uint32_t thunk_type = *(uint32_t *)thunk;
				if (thunk_type == 0)
					return;

				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

				if (is_ordinal) {
					snprintf(hint_str, sizeof(hint_str)-1, "%"PRIu32,
						thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
				} else {
					const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						// TODO: Should we report something?
						return;
					}

					snprintf(hint_str, sizeof(hint_str)-1, "%d", imp_name->Hint);
					strncpy(fname, (char *)imp_name->Name, sizeof(fname)-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[sizeof(fname) - 1] = '\0';
					//size_t fname_len = strlen(fname);
				}
				ofs += sizeof(IMAGE_THUNK_DATA32);
				break;
			}
			case MAGIC_PE64:
			{
				const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64))) {
					// TODO: Should we report something?
					return;
				}

				// Type punning
				const uint64_t thunk_type = *(uint64_t *)thunk;
				if (thunk_type == 0)
					return;

				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG64) != 0;

				if (is_ordinal) {
					snprintf(hint_str, sizeof(hint_str)-1, "%llu",
						thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64);
				} else {
					uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						// TODO: Should we report something?
						return;
					}

					snprintf(hint_str, sizeof(hint_str)-1, "%d", imp_name->Hint);
					strncpy(fname, (char *)imp_name->Name, sizeof(fname)-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[sizeof(fname) - 1] = '\0';
					//size_t fname_len = strlen(fname);
				}
				ofs += sizeof(IMAGE_THUNK_DATA64);
				break;
			}
		}

		if (!dll_name)
			continue;

		// Beginning of imphash logic - that's the weirdest thing I've even seen...

		for (unsigned i=0; i < strlen(dll_name); i++)
			dll_name[i] = tolower(dll_name[i]);

		char *aux = NULL;

		//TODO use a reverse search function instead

		if (flavor == IMPHASH_FLAVOR_MANDIANT)
			aux = last_strstr(dll_name, ".");
		else if (flavor == IMPHASH_FLAVOR_PEFILE) {
			aux = last_strstr(dll_name, ".dll");
			if (aux)
				*aux = '\0';

			aux = last_strstr(dll_name, ".ocx");
			if (aux)
				*aux = '\0';

			aux = last_strstr(dll_name, ".sys");
			if (aux)
				*aux = '\0';
		}
		
		if (aux)
			*aux = '\0';
		
		for (unsigned i=0; i < strlen(fname); i++)
			fname[i] = tolower(fname[i]);

		struct element *el = (struct element *) malloc(sizeof(struct element));

		el->dll_name = strdup(dll_name);

		if (flavor == IMPHASH_FLAVOR_MANDIANT) {
			el->function_name = strdup(is_ordinal ? hint_str : fname);
		}
		else if (flavor == IMPHASH_FLAVOR_PEFILE) { 
			
			int hint = strtoul(hint_str, NULL, 10);

			if ( strncmp(dll_name, "oleaut32", 8) == 0 && is_ordinal) {
				for (unsigned i=0; i < sizeof(oleaut32_arr) / sizeof(ord_t); i++)
					if (hint == oleaut32_arr[i].number)
						el->function_name = strdup(oleaut32_arr[i].fname);
			}
			else if ( strncmp(dll_name, "ws2_32", 6) == 0 && is_ordinal) {
				for (unsigned i=0; i < sizeof(ws2_32_arr) / sizeof(ord_t); i++)
					if (hint == ws2_32_arr[i].number)
						el->function_name = strdup(ws2_32_arr[i].fname);
			}
			else {
				char ord[MAX_FUNCTION_NAME];
				memset(ord, 0, MAX_FUNCTION_NAME);

				if (is_ordinal) {
					snprintf(ord, MAX_FUNCTION_NAME, "ord%s", hint_str);
					el->function_name = strdup(ord);
				} else {
					el->function_name = strdup(fname);
				}
			}
		}

		for (unsigned i=0; i < strlen(el->function_name); i++)
			el->function_name[i] = tolower(el->function_name[i]);

		LL_APPEND(*head, el);
	}
}

static void imphash(pe_ctx_t *ctx, int flavor)
{
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		return;

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "import directory not found\n");
		return;
	}
	uint64_t ofs = pe_rva2ofs(ctx, va);
	element *elt, *tmp, *head = NULL;
	int count = 0;

	while (1) {
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			// TODO: Should we report something?
			output_close_scope();
			return;
		}

		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		const uint64_t aux = ofs; // Store current ofs

		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0)
			break;

		const char *dll_name_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		// Validate whether it's ok to access at least 1 byte after dll_name_ptr.
		// It might be '\0', for example.
		if (!pe_can_read(ctx, dll_name_ptr, 1)) {
			// TODO: Should we report something?
			break;
		}

		char dll_name[MAX_DLL_NAME];
		strncpy(dll_name, dll_name_ptr, sizeof(dll_name)-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		dll_name[sizeof(dll_name) - 1] = '\0';

		//output_open_scope("Library", OUTPUT_SCOPE_TYPE_OBJECT);
		//output("Name", dll_name);

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			output_close_scope(); // Library
			break;
		}

		imphash_load_imported_functions(ctx, ofs, dll_name, &head, flavor);
		ofs = aux; // Restore previous ofs
	}

	LL_COUNT(head, elt, count);
	//printf("%d number of elements in list outside\n", count);

	size_t imphash_string_size = sizeof(char) * count * MAX_DLL_NAME + MAX_FUNCTION_NAME;

	char *imphash_string = (char *) malloc_s(imphash_string_size);

	memset(imphash_string, 0, imphash_string_size);

	LL_FOREACH_SAFE(head, elt, tmp) \
		sprintf(imphash_string, "%s%s.%s,", imphash_string, elt->dll_name, elt->function_name); \
		LL_DELETE(head, elt);

	free(elt);

	imphash_string_size = strlen(imphash_string);
	imphash_string[imphash_string_size-1] = '\0'; // remove the last comma sign

	//puts(imphash_string); // DEBUG

	char imphash[33];
	calc_hash("md5", (unsigned char *)imphash_string, strlen(imphash_string), imphash);
	free(imphash_string);

	if (flavor == IMPHASH_FLAVOR_MANDIANT)
		output("imphash (Mandiant)", imphash);
	else if (flavor == IMPHASH_FLAVOR_PEFILE)
		output("imphash", imphash);
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

	OpenSSL_add_all_digests();

	options_t *options = parse_options(argc, argv);

	pe_ctx_t ctx;

	pe_err_e err = pe_load_file(&ctx, argv[argc-1]);
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

	const IMAGE_SECTION_HEADER *section_ptr = NULL;
	const unsigned char *data = NULL;
	uint64_t data_size = 0;

	unsigned c = pe_sections_count(&ctx);
	IMAGE_SECTION_HEADER ** const sections = pe_sections(&ctx);

	data = ctx.map_addr;
	data_size = pe_filesize(&ctx);

	output_open_document();

	if (options->headers.all || options->headers.dos || options->headers.coff || options->headers.optional ||
		options->sections.name || options->sections.index) {
		options->all = false;
		options->content = false;
	}

	if (options->all) {
		options->content = true;
		options->headers.all = true;
	}

	if (options->content) {
		output_open_scope("file", OUTPUT_SCOPE_TYPE_OBJECT);
		output("filepath", ctx.path);
		print_basic_hash(data, data_size);
		//imphash(&ctx, IMPHASH_FLAVOR_MANDIANT);
		imphash(&ctx, IMPHASH_FLAVOR_PEFILE);
		
		output_close_scope(); // file
		if (!options->all) // whole file content only
			goto BYE;
	}

	if (options->headers.all) {
		options->headers.dos = true;
		options->headers.coff = true;
		options->headers.optional = true;
	}

	if (options->headers.all || options->headers.dos || options->headers.coff || options->headers.optional)
		output_open_scope("headers", OUTPUT_SCOPE_TYPE_ARRAY);

	if (options->headers.all || options->headers.dos) {
		const IMAGE_DOS_HEADER *dos_hdr = pe_dos(&ctx);
		data = (const unsigned char *)dos_hdr;
		data_size = sizeof(IMAGE_DOS_HEADER);

		output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
		output("header_name", "IMAGE_DOS_HEADER");
		print_basic_hash(data, data_size);
		output_close_scope(); // header
	}

	if (options->headers.all || options->headers.coff) {
		const IMAGE_COFF_HEADER *coff_hdr = pe_coff(&ctx);
		data = (const unsigned char *)coff_hdr;
		data_size = sizeof(IMAGE_COFF_HEADER);

		output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
		output("header_name", "IMAGE_COFF_HEADER");
		print_basic_hash(data, data_size);
		output_close_scope(); // header
	}

	if (options->headers.all || options->headers.optional) {
      const IMAGE_OPTIONAL_HEADER *opt_hdr = pe_optional(&ctx);
      switch (opt_hdr->type) {
         case MAGIC_ROM:
            // Oh boy! We do not support ROM. Abort!
            fprintf(stderr, "ROM image is not supported\n");
            break;
         case MAGIC_PE32:
            if (!pe_can_read(&ctx, opt_hdr->_32, sizeof(IMAGE_OPTIONAL_HEADER_32))) {
               // TODO: Should we report something?
               break;
            }
            data = (const unsigned char *)opt_hdr->_32;
            data_size = sizeof(IMAGE_OPTIONAL_HEADER_32);
            break;
         case MAGIC_PE64:
            if (!pe_can_read(&ctx, opt_hdr->_64, sizeof(IMAGE_OPTIONAL_HEADER_64))) {
               // TODO: Should we report something?
               break;
            }
            data = (const unsigned char *)opt_hdr->_64;
            data_size = sizeof(IMAGE_OPTIONAL_HEADER_64);
            break;
		}

		output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
		output("header_name", "IMAGE_OPTIONAL_HEADER");
		print_basic_hash(data, data_size);
		output_close_scope(); // header
	}

	if (options->headers.all || options->headers.dos || options->headers.coff || options->headers.optional)
		output_close_scope(); // headers

	if (options->all || options->sections.name || options->sections.index)
		output_open_scope("sections", OUTPUT_SCOPE_TYPE_ARRAY);

	if (options->all) {
		for (unsigned int i=0; i<c; i++) {
			data_size = sections[i]->SizeOfRawData;
			data = LIBPE_PTR_ADD(ctx.map_addr, sections[i]->PointerToRawData);

			if (!pe_can_read(&ctx, data, data_size)) {
				EXIT_ERROR("Unable to read section data");
			}

			output_open_scope("section", OUTPUT_SCOPE_TYPE_OBJECT);
			output("section_name", (char *)sections[i]->Name);
			if (data_size) {
				print_basic_hash(data, data_size);
			}
			output_close_scope(); // section
		}
		//output_close_scope(); // sections
	} else if (options->sections.name != NULL) {
		const IMAGE_SECTION_HEADER *section = pe_section_by_name(&ctx, options->sections.name);
		if (section == NULL) {
			EXIT_ERROR("The requested section could not be found on this binary");
		}
		section_ptr = section;
	} else if (options->sections.index > 0) {
		const uint16_t num_sections = pe_sections_count(&ctx);
		if (num_sections == 0 || options->sections.index > num_sections) {
			EXIT_ERROR("The requested section could not be found on this binary");
		}
		IMAGE_SECTION_HEADER ** const sections = pe_sections(&ctx);
		const IMAGE_SECTION_HEADER *section = sections[options->sections.index - 1];
		section_ptr = section;
	}

	if (section_ptr != NULL) {
		if (section_ptr->SizeOfRawData > 0) {
			const uint8_t *section_data_ptr = LIBPE_PTR_ADD(ctx.map_addr, section_ptr->PointerToRawData);
			// printf("map_addr = %p\n", ctx.map_addr);
			// printf("section_data_ptr = %p\n", section_data_ptr);
			// printf("SizeOfRawData = %u\n", section_ptr->SizeOfRawData);
			if (!pe_can_read(&ctx, section_data_ptr, section_ptr->SizeOfRawData)) {
				EXIT_ERROR("The requested section has an invalid size");
			}
			data = (const unsigned char *)section_data_ptr;
			data_size = section_ptr->SizeOfRawData;
		} else {
			data = (const unsigned char *)"";
			data_size = 0;
		}
	}

	if (!options->all && data != NULL) {
		output_open_scope("section", OUTPUT_SCOPE_TYPE_OBJECT);
		output("section_name", options->sections.name);
		print_basic_hash(data, data_size);
		output_close_scope();
	}

	if (options->all || options->sections.name || options->sections.index)
		output_close_scope();

	BYE:
	output_close_document();

	// free
	free_options(options);

	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	EVP_cleanup(); // Clean OpenSSL_add_all_digests.
	PEV_FINALIZE(&config);
	return EXIT_SUCCESS;
}
