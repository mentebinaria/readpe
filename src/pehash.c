/*
	pev - the PE file analyzer toolkit

	pehash.c - calculate hashes of PE pieces

	Copyright (C) 2012 - 2015 pev authors

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
*/

#include "common.h"
#include <openssl/evp.h>
#include "../lib/libfuzzy/fuzzy.h"
#include "plugins.h"

#define PROGRAM "pehash"

#define PRINT_HASH_OR_HASHES \
		if (options->algorithms.alg_name) { \
			calc_hash(options->algorithms.alg_name, data, data_size, hash_value); \
			output(options->algorithms.alg_name, hash_value); \
		} else { \
			print_basic_hash(data, data_size); \
		}

typedef struct {
	bool all;
	struct {
		bool all;
		char *alg_name;
		bool ssdeep;
	} algorithms;
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

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s OPTIONS FILE\n"
		"Calculate hashes of PE pieces\n"
		"\nExample: %s -s '.text' winzip.exe\n"
		"\nOptions:\n"
		" -f, --format <%s> change output format (default: text)\n"
		" -a, --algorithm <algorithm>           calculate hash using one of the following algorithms:\n"
		"                                       md4, md5, ripemd160, sha, sha1, sha224, sha256\n"
		"                                       sha384, sha512, whirlpool or ssdeep\n\n"
		" -h, --header <dos|coff|optional>      hash only the header with the specified name\n"
		" -s, --section <section_name>          hash only the section with the specified name\n"
		" --section-index <section_index>       hash only the section at the specified index (1..n)\n"
		" -v, --version                         show version and exit\n"
		" --help                                show this help and exit\n",
		PROGRAM, PROGRAM, formats);
}

static void parse_hash_algorithm(options_t *options, const char *optarg)
{
	if (strcmp("ssdeep", optarg) == 0) {
		options->algorithms.ssdeep = true;
	} else {
		const EVP_MD *md = EVP_get_digestbyname(optarg);
		if (md == NULL)
			EXIT_ERROR("The requested algorithm is not supported");
	}

	options->algorithms.alg_name = strdup(optarg);
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

	if (options->algorithms.alg_name != NULL)
		free(options->algorithms.alg_name);

	if (options->sections.name != NULL)
		free(options->sections.name);

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	// parameters for getopt_long() function
	static const char short_options[] = "f:a:h:s:v";

	static const struct option long_options[] = {
		{ "help",          no_argument,         NULL,  1  },
		{ "format",        required_argument,   NULL, 'f' },
		{ "algorithm",     required_argument,   NULL, 'a' },
		{ "header",        required_argument,   NULL, 'h' },
		{ "section-name",  required_argument,   NULL, 's' },
		{ "section-index", required_argument,   NULL,  2  },
		{ "version",       no_argument,         NULL, 'v' },
		{  NULL,           0,                   NULL,  0  }
	};

	// Default options.
	options->algorithms.all = true;
	options->headers.all = true;
	options->all = true;

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
				options->algorithms.all = false;
				parse_hash_algorithm(options, optarg);
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
			case 'v':
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

	EVP_MD_CTX md_ctx;
	// FIXME: Handle errors - Check return values.
	EVP_MD_CTX_init(&md_ctx);
	EVP_DigestInit_ex(&md_ctx, md, NULL);
	EVP_DigestUpdate(&md_ctx, data, size);
	EVP_DigestFinal_ex(&md_ctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&md_ctx);

	for (unsigned int i=0; i < md_len; i++)
		sprintf(&output[i * 2], "%02x", md_value[i]);
}

static void print_basic_hash(const unsigned char *data, size_t size)
{
	char *basic_hashes[] = { "md5", "sha1", "ssdeep" };
	char hash_value[EVP_MAX_MD_SIZE * 2 + 1];

	if (!data || !size)
		return;

	for (int i=0; i < 3; i++) {
		calc_hash(basic_hashes[i], data, size, hash_value);
		output(basic_hashes[i], hash_value);
	}
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
	char hash_value[EVP_MAX_MD_SIZE * 2 + 1];

	data = ctx.map_addr;
	data_size = pe_filesize(&ctx);

	output_open_document();

	if (options->all) {
		output_open_scope("file", OUTPUT_SCOPE_TYPE_OBJECT);
		output("filepath", ctx.path);
		print_basic_hash(data, data_size);
		output_close_scope(); // file
	}

	output_open_scope("headers", OUTPUT_SCOPE_TYPE_ARRAY);

	if (options->all || options->headers.all || options->headers.dos) {
		const IMAGE_DOS_HEADER *dos_hdr = pe_dos(&ctx);
		data = (const unsigned char *)dos_hdr;
		data_size = sizeof(IMAGE_DOS_HEADER);

		output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
		output("header_name", "IMAGE_DOS_HEADER");
		PRINT_HASH_OR_HASHES;
		output_close_scope(); // header
	}

	if (options->all || options->headers.all || options->headers.coff) {
		const IMAGE_COFF_HEADER *coff_hdr = pe_coff(&ctx);
		data = (const unsigned char *)coff_hdr;
		data_size = sizeof(IMAGE_COFF_HEADER);

		output_open_scope("header", OUTPUT_SCOPE_TYPE_OBJECT);
		output("header_name", "IMAGE_COFF_HEADER");
		PRINT_HASH_OR_HASHES;
		output_close_scope(); // header
	}

	if (options->all || options->headers.all || options->headers.optional) {
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
		PRINT_HASH_OR_HASHES;
		output_close_scope(); // header
	}

	output_close_scope(); // headers

	if (options->all) {
		output_open_scope("sections", OUTPUT_SCOPE_TYPE_ARRAY);
		for (unsigned int i=0; i<c; i++) {
			data_size = sections[i]->SizeOfRawData;
			data = LIBPE_PTR_ADD(ctx.map_addr, sections[i]->PointerToRawData);

			if (!pe_can_read(&ctx, data, data_size)) {
				EXIT_ERROR("Unable to read section data");
			}

			output_open_scope("section", OUTPUT_SCOPE_TYPE_OBJECT);
			output("section_name", (char *)sections[i]->Name);
			if (data_size) {
				PRINT_HASH_OR_HASHES;
			}
			output_close_scope(); // section
		}
		output_close_scope(); // sections
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
		char hash_value[EVP_MAX_MD_SIZE * 2 + 1];

		if (options->algorithms.all && options->all) {
			print_basic_hash(data, data_size);
		} else if (options->algorithms.alg_name != NULL) {
			calc_hash(options->algorithms.alg_name, data, data_size, hash_value);
			output(options->algorithms.alg_name, hash_value);
		} else {
			print_basic_hash(data, data_size);
		}
	}

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
