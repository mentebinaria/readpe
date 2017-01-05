/*
	pev - PE information dump utility

	Copyright (C) 2010 - 2011 Coding 40°

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
#include "parser.h"
#include "defs.h"

struct options config;
static int ind;

void usage()
{
	printf("Usage: pev [-cdhops] <file>\n\n");
	printf("pev will get information about PE32 binaries and display \
it on standard output.\n\n");
	printf("All switches are optional, but --all is used by default.\n\n");
}

FILE * getfile(int argc, char * argv[])
{
	FILE * file_ptr = NULL;
	int i;
	
	if (argc <= 1)
	{
		fprintf(stderr, "%s: %s\n", PACKAGE, "no input file");
		exit(EXIT_FAILURE);
	}
	
	for (i=1; i<argc; i++)
	{
		file_ptr = fopen(argv[i], "rb");
		if (file_ptr != NULL)
			break;
	}

	if (file_ptr == NULL)
	{
		fprintf(stderr, "%s: file not found\n", argv[i-1]);
		exit(EXIT_FAILURE);
	}
	return file_ptr;
}

void parse_options(int argc, char *argv[])
{
	int c;
	
	/* Paramters for getopt_long() function */
	static const char short_options[] = "Adcosrphv";

	static const struct option long_options[] = {
		{"all", no_argument, NULL, (int)'A'},
		{"help", no_argument, NULL, (int)'h'},
		{"version", no_argument, NULL, (int)'v'},
		{"dos", no_argument, NULL, (int)'d'},
		{"coff", no_argument, NULL, (int)'c'},
		{"optional", no_argument, NULL, (int)'o'},
		{"sections", no_argument, NULL, (int)'s'},
		{"resources", no_argument, NULL, (int)'r'},
		{"product-version", no_argument, NULL, (int)'p'},
		{ NULL, no_argument, NULL, 0 } };
		
	config.all = 0;
	config.coff = 0;
	config.dos = 0;
	config.opt = 0;
	config.product = 0;
	config.resources = 0;
	config.sections = 0;
	
	if (argc == 2)
		config.all = 1;
		
	while ((c = getopt_long(argc, argv, short_options,
			long_options, &ind)))
	{
		if (c < 0)		
			break;

		switch (c)
		{
			case 0:
				break;
				
			case 'A':
				config.all = 1;
				break;
			
			case 'd':
				config.dos = 1;
				break;
				
			case 'c':
				config.coff = 1;
				break;
				
			case 'o':
				config.opt = 1;
				break;
				
			case 's':
				config.sections = 1;
				break;
				
			case 'r':
				/*printf("─┬─├─ ─\n");*/
				config.resources = 1;
				break;
				
			case 'p':
				config.product = 1;
				break;

			case 'v':
				printf("pev %s\n", VERSION);
				exit(EXIT_SUCCESS);

			case 'h':
				usage();
				exit(EXIT_SUCCESS);
				
			default:
				fprintf(stderr, "%s: %s\n", PACKAGE, "try '--help' for more information");
				exit(EXIT_FAILURE);
		}
	}
}
