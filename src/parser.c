/*
	pev - the PE file analyzer

	Copyright (C) 2010 - 2012 Fernando Mercês

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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "include/parser.h"
#include "include/pev.h"

struct options config;
static int ind;

void usage()
{
	printf("Usage: pev OPTIONS FILE\n\n");
	printf("pev will get information about PE32 binaries and display \
it on standard output.\n\n");
	printf("Use -A or --all switch for full output.\n");
}

void parse_headers(const char *optarg)
{
	if (! strcmp(optarg, "dos"))
		config.dos = true;
	else if (! strcmp(optarg, "coff"))
		config.coff = true;
	else if (! strcmp(optarg, "optional"))
		config.opt = true;
	else
		EXIT_WITH_ERROR("invalid header option");
}

void parse_format(const char *optarg)
{
	if (! strcmp(optarg, "text"))
		config.format = FORMAT_TEXT;
	else if (! strcmp(optarg, "xml"))
		config.format = FORMAT_XML;
   else if (! strcmp(optarg, "csv"))
		config.format = FORMAT_CSV;
   else if (! strcmp(optarg, "html"))
		config.format = FORMAT_HTML;
	else
		EXIT_WITH_ERROR("invalid format option");
}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "AHSh:D:dEe:f:rvp";


	static const struct option long_options[] = {
		{"help",             no_argument,       NULL,  1 },
		{"all",              no_argument,       NULL, 'A'},
		{"all-headers",      no_argument,       NULL, 'H'},
		{"all-sections",     no_argument,       NULL, 'S'},
		{"header",           required_argument, NULL, 'h'},
		{"imports",          no_argument,       NULL, 'i'},
		{"exports",          no_argument,       NULL, 'e'},
		{"disasm",           required_argument, NULL, 'D'},
		{"dirs",             no_argument,       NULL, 'd'},
		{"extract-resource", required_argument, NULL, 'E'},
		{"format",           required_argument, NULL, 'f'},
		{"resources",        no_argument,       NULL, 'r'},
		{"product-version",  no_argument,       NULL, 'p'},
		{"version",          no_argument,       NULL, 'v'},
		{ NULL,              0,                 NULL,  0 }
	};

	// setting all fields to false
	memset(&config, false, sizeof(config));

	config.format = FORMAT_TEXT;

	if (argc == 2)
		config.all = true;

	while ((c = getopt_long(argc, argv, short_options,
			long_options, &ind)))
	{
		if (c < 0)
			break;


		switch (c)
		{
			case 1:		// --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'A':
				config.all = true; break;

			case 'H':
				config.all_headers = true; break;

			case 'c':
				config.coff = true; break;

			case 'd':
				config.dirs = true; break;

            case 'i':
                config.imports = true; config.exports = true; break;

			case 'o':
				config.opt = true; break;

			case 'S':
				config.all_sections = true; break;

			case 'r':
				config.resources = true; break; 	/* ─┬─ ├─ ─ */

			case 'p':
				config.product = true; break;

			case 'v':
				printf("pev %s\n", VERSION);
				exit(EXIT_SUCCESS);

			case 'h':
				parse_headers(optarg); break;

			case 'f':
				parse_format(optarg); break;

			default:
				fprintf(stderr, "pev: try '--help' for more information\n");
				exit(EXIT_FAILURE);
		}
	}
}
