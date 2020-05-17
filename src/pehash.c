/*
	pev - the PE file analyzer toolkit

	pehash.c - calculate hashes of PE pieces

	Copyright (C) 2012 - 2020 pev authors

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
#include "plugins.h"

#define PROGRAM "pehash"

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

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s OPTIONS FILE\n"
		"Calculate hashes of PE pieces\n"
		"\nExample: %s -s '.text' winzip.exe\n"
		"\nOptions:\n"
		" -f, --format <%s> Change output format (default: text).\n"
		" -a, --all                             Hash file, sections and headers with md5, sha1, sha256, ssdeep and imphash.\n"
		" -c, --content                         Hash only the file content (default).\n"
		" -h, --header <dos|coff|optional>      Hash only the header with the specified name.\n"
		" -s, --section <section_name>          Hash only the section with the specified name.\n"
		" --section-index <section_index>       Hash only the section at the specified index (1..n).\n"
		" -V, --version                         Show version.\n"
		" --help                                Show this help.\n",
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

static void print_basic_hash(const unsigned char *data, size_t data_size)
{
	if (!data || !data_size)
		return;

	const char *basic_hashes[] = { "md5", "sha1", "sha256", "ssdeep" };
	const size_t hash_value_size = pe_hash_recommended_size();
	char *hash_value = malloc_s(hash_value_size);

	for (size_t i=0; i < sizeof(basic_hashes) / sizeof(char *); i++) {
		pe_hash_raw_data(hash_value, hash_value_size, basic_hashes[i], data, data_size);
		output(basic_hashes[i], hash_value);
	}

	free(hash_value);
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

		char *imphash = NULL;

		// imphash = pe_imphash(&ctx, LIBPE_IMPHASH_FLAVOR_MANDIANT);
		// output("imphash (Mandiant)", imphash);
		// free(imphash);

		imphash = pe_imphash(&ctx, LIBPE_IMPHASH_FLAVOR_PEFILE);
		
		if (imphash) {
			output("imphash", imphash);
			free(imphash);
		}
		
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
            LIBPE_WARNING("ROM image is not supported");
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
				LIBPE_WARNING("Unable to read section data");
			} else {
				output_open_scope("section", OUTPUT_SCOPE_TYPE_OBJECT);
				output("section_name", (char *)sections[i]->Name);
				if (data_size) {
					print_basic_hash(data, data_size);
				}
				output_close_scope(); // section
			}
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
			// fprintf(stderr, "map_addr = %p\n", ctx.map_addr);
			// fprintf(stderr, "section_data_ptr = %p\n", section_data_ptr);
			// fprintf(stderr, "SizeOfRawData = %u\n", section_ptr->SizeOfRawData);
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

	PEV_FINALIZE(&config);
	return EXIT_SUCCESS;
}
