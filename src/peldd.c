/*
	pev - the PE file analyzer toolkit

	peldd.c - shows library dependencies for a given PE file

	Copyright (C) 2018 - 2020 pev authors

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
#include "output.h"

#define PROGRAM "peldd"

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s FILE\n"
		"Display PE library dependencies\n"
		"\nExample: %s winzip.exe\n"
		"\nOptions:\n"
		" -f, --format <%s>  Change output format (default: text).\n"
		" -V, --version                          Show version.\n"
		" --help                                 Show help.\n",
		PROGRAM, PROGRAM, formats);
}

static void parse_options(int argc, char *argv[])
{

	/* Parameters for getopt_long() function */
	static const char short_options[] = "Vf:";

	static const struct option long_options[] = {
		{ "help",             no_argument,       NULL,  1  },
		{ "format",           required_argument, NULL, 'f' },
		{ "version",          no_argument,       NULL, 'V' },
		{  NULL,              0,                 NULL,  0  }
	};

	int c, ind;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1: // --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'V':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			case 'f':
				if (output_set_format_by_name(optarg) < 0)
					EXIT_ERROR("invalid format option");
				break;
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

}

static void print_dependencies(pe_ctx_t *ctx)
{
	output_open_scope("Dependencies", OUTPUT_SCOPE_TYPE_ARRAY);
	const pe_imports_t *imports = pe_imports(ctx);
	for (size_t i=0; i < imports->dll_count; i++) {
		const pe_imported_dll_t *dll = &imports->dlls[i];
		output(dll->name, NULL);
	}
	output_close_scope();
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

	parse_options(argc, argv);

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

	output_open_document();

	IMAGE_DATA_DIRECTORY **directories = pe_directories(&ctx);
	if (directories == NULL) {
		LIBPE_WARNING("directories not found");
	} else {
		print_dependencies(&ctx);
	}

	output_close_document();

	// free
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	PEV_FINALIZE(&config);

	return EXIT_SUCCESS;
}
