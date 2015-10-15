/*
	pev - the PE file analyzer toolkit

	unlznt1.c - Decompress LZNT1 data

	Copyright (C) 2015 pev authors

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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#define PROGRAM "unlznt1"

static void usage(void)
{
	printf("Usage: %s FILE\n"
		"Decompress LZNT1 data\n"
		"\nExample: %s file.lznt1 > file\n"
		"\nOptions:\n"
		" -v, --version                          show version and exit\n"
		" --help                                 show this help and exit\n",
		PROGRAM, PROGRAM);
}

static void *parse_options(int argc, char *argv[])
{
	/* Parameters for getopt_long() function */
	static const char short_options[] = "o:v";

	static const struct option long_options[] = {
		{ "help",			no_argument,		NULL,	 1  },
		{ "version",		no_argument,		NULL,	'v' },
		{ NULL,				0,					NULL, 	 0  }
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
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	parse_options(argc, argv);

	const char *path = argv[argc-1];

	ssize_t aux = 0;
	int i;
	FILE *fp = fopen(path, "rb");
	fseek(fp, 0, SEEK_END);
	size_t siz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	char *data = malloc(siz);
	if (!data) {
		fprintf(stderr, "fatal: memory exhausted (malloc of %zu bytes)\n", siz);
		return EXIT_FAILURE;
	}

	if (fread(data, siz, 1, fp) != 1) {
		fprintf(stderr, "fatal: error when reading file content\n");
		return EXIT_FAILURE;
	}

	fclose(fp);
	aux = lznt1_decompress(data, siz, NULL);

	if (aux < 1) {
		fprintf(stderr, "fatal: data probably not LZNT1 compressed\n");
		return EXIT_FAILURE;
	}
	
	char *u = malloc(aux);
	if (!u) {
		fprintf(stderr, "fatal: buffer memory exhausted (malloc of %zu bytes)\n", aux);
		return EXIT_FAILURE;
	}

	memset(u, 0, aux);
	lznt1_decompress(data, siz, u);
	free(data);

	for (i=0; i<aux; i++)
		putchar(u[i]);

	free(u);
	
	return EXIT_SUCCESS;
}