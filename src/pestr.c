/*
	pev - the PE file analyzer toolkit

	pestr.c - search for strings in PE files.

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
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#define PROGRAM "pestr"
#define BUFSIZE 4
#define LINE_BUFFER 32768

typedef struct {
	unsigned short strsize;
	bool offset;
	bool section;
} options_t;

static void usage(void)
{
	printf("Usage: %s OPTIONS FILE\n"
		"Search for strings in PE files\n"
		"\nExample: %s acrobat.exe\n"
		"\nOptions:\n"
		" -n, --min-length                       Set minimum string length (default: 4).\n"
		" -o, --offset                           Show string offset in file.\n"
		" -s, --section                          Show string section, if exists.\n"
		" -V, --version                          Show version.\n"
		" --help                                 Show this help.\n",
		PROGRAM, PROGRAM);
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
	static const char short_options[] = "osn:V";

	static const struct option long_options[] = {
		{ "offset",          no_argument,        NULL, 'o' },
		{ "section",         no_argument,        NULL, 's' },
		{ "min-length",      required_argument,  NULL, 'n' },
		{ "help",            no_argument,        NULL,  1  },
		{ "version",         no_argument,        NULL, 'V' },
		{ NULL,              0,                  NULL,  0  }
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
			case 'o':
				options->offset = true;
				break;
			case 's':
				options->section = true;
				break;
			case 'n':
			{
				unsigned long value = strtoul(optarg, NULL, 0);
				if (value == ULONG_MAX && errno == ERANGE) {
					fprintf(stderr, "The original (nonnegated) value would overflow");
					exit(EXIT_FAILURE);
				}
				options->strsize = (unsigned char)value;
				break;
			}
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

// TODO Move it to libpe
static unsigned char *ofs2section(pe_ctx_t *ctx, uint64_t offset)
{
	IMAGE_SECTION_HEADER **sections = pe_sections(ctx);

	for (uint16_t i=0; i < ctx->pe.num_sections; i++) {
		uint32_t sect_offset = sections[i]->PointerToRawData;
		uint32_t sect_size = sections[i]->SizeOfRawData;

		if (offset >= sect_offset && offset <= (sect_offset + sect_size)) {
			return (unsigned char *)sections[i]->Name;
		}
	}

	return NULL;
}

static void printb(
	pe_ctx_t *ctx,
	const options_t *options,
	const uint8_t *bytes,
	size_t pos,
	size_t length,
	unsigned long offset
) {
	if (options->offset)
		printf("%#lx\t", (unsigned long) offset);

	if (options->section) {
		char *s = (char *) ofs2section(ctx, offset);
		printf("%s\t", s ? s : "[none]");
	}

	// print the string
	while (pos < length) {
		if (bytes[pos] == '\0') { // utf-8 printing
			pos++;
			continue;
		}
		putchar(bytes[pos++]);
	}

	putchar('\n');
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		exit(EXIT_FAILURE);
	}

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

	const uint64_t pe_size = pe_filesize(&ctx);
	const uint8_t *pe_raw_data = ctx.map_addr;
	uint64_t pe_raw_offset = 0;

	unsigned char buff[LINE_BUFFER];
	memset(buff, 0, LINE_BUFFER);
	uint64_t buff_index = 0;

	uint32_t ascii = 0;
	uint32_t utf = 0;

	while (pe_raw_offset < pe_size) {
		const uint8_t byte = pe_raw_data[pe_raw_offset];

		if (isprint(byte) && buff_index < LINE_BUFFER) {
			ascii++;
			buff[buff_index++] = byte;
			pe_raw_offset++;
			continue;
		} else if (ascii == 1 && byte == '\0' && buff_index < LINE_BUFFER) {
			utf++;
			buff[buff_index++] = byte;
			ascii = 0;
			pe_raw_offset++;
			continue;
		} else {
			if (ascii >= (options->strsize ? options->strsize : 4)) {
				printb(&ctx, options, buff, 0, ascii, pe_raw_offset - ascii);
			} else if (utf >= (options->strsize ? options->strsize : 4)) {
				printb(&ctx, options, buff, 0, utf*2, pe_raw_offset - utf*2);
			}
			ascii = utf = buff_index = 0;
			memset(buff, 0, LINE_BUFFER);
		}

		pe_raw_offset++;
	}

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
