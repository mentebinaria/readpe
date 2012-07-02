/*
	pev - the PE file analyzer toolkit
	
	pestr.c - search for encrypted strings in PE files

	Copyright (C) 2012 Fernando Mercês

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

#include "pestr.h"

struct options config;
static int ind;

void usage()
{
	printf("Usage: %s OPTIONS FILE\n"
	"Search for encrypted strings in PE files\n"
	"\nExample: %s acrobat.exe\n"
	"\nOptions:\n"
	" -n, --min-lenght                       set minimun string lenght (default: 4)\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "fosn:v";

	static const struct option long_options[] = {
		{"functions",       no_argument,        NULL, 'f'},
		{"offset",          no_argument,        NULL, 'o'},
		{"section",         no_argument,        NULL, 's'},
		{"min-lenght",      required_argument,  NULL,  1 },
		{"help",            no_argument,        NULL,  1 },
		{"version",         no_argument,        NULL, 'v'},
		{ NULL,             0,                  NULL,  0 }
	};

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

			case 'f':
				//config.functions = true;
				EXIT_ERROR("not implemented yee");
				break;

			case 'n':
				config.strsize = (unsigned char) strtoul(optarg, NULL, 0);
				break;
				
			case 'o':
				config.offset = true;
				break;
				
			case 's':
				config.section = true;
				break;
				
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

unsigned char *ofs2section(PE_FILE *pe, unsigned long offset)
{
	unsigned int i;
	unsigned long sect_size, sect_offset, aux=0;

	aux = ftell(pe->handle);

	pe_get_sections(pe);
	for (i=0; i < pe->num_sections; i++)
	{
		sect_offset = pe->sections_ptr[i]->PointerToRawData;
		sect_size = pe->sections_ptr[i]->SizeOfRawData;

		if (offset >= sect_offset && offset <= (sect_offset + sect_size))
		{
			fseek(pe->handle, aux, SEEK_SET);
			return pe->sections_ptr[i]->Name;
		}
	}
	fseek(pe->handle, aux, SEEK_SET);
	return NULL;
}

unsigned char *ref_functions(PE_FILE *pe, unsigned long offset)
{
	unsigned long buff, aux=0;
	unsigned char *str = (unsigned char *) xmalloc(sizeof(char) * 100);
	FILE *fp = pe->handle;

	aux = ftell(fp);
	rewind(fp);
	memset(str, 0, sizeof(str));

	while (fread(&buff, 1, sizeof(buff), fp))
	{
		snprintf(str, 100, "%#lx", ofs2rva(pe, offset));
		return str;
		if (buff == ofs2rva(pe, offset) + pe->imagebase)

		{
			fseek(fp, aux, SEEK_SET);
			return "aqui|";
		}

		// slow search
		//fseek(fp, - (sizeof(buff)-1), SEEK_CUR);
	}
	fseek(fp, aux, SEEK_SET);

	return NULL;
}

void printb(PE_FILE *pe, unsigned char *bytes, unsigned pos, unsigned lenght, unsigned long
offset)
{
	if (config.offset)
		printf("%#lx\t", (unsigned long) offset);

	if (config.section)
	{
		char *s = ofs2section(pe, offset);
		printf("%s\t", s ? s : "[none]");
	}

	if (config.functions)
	{
		char *s = ref_functions(pe, offset);

		printf("%s\t", s ? s : "[none]");
		free(s);
	}

	// print the string
	while (pos < lenght)
		putchar(bytes[pos++]);

	putchar('\n');
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	unsigned char buff[BUFSIZE];
	unsigned int c, i, ofs=0;

	memset(&config, 0, sizeof(config));
	parse_options(argc, argv); // opcoes

	if (argc < 2)
	{
		usage();
		exit(1);
	}

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	rewind(pe.handle);

	for (ofs=0; fread(&buff, 1, sizeof(buff), pe.handle); ofs++)
	{
		for (i=0; i<sizeof(buff); i++)
		{
			if (isprint(buff[i]))
			{
				if (i == BUFSIZE-1)
					printb(&pe, buff, i-c, i, ofs * sizeof(buff) + i-c);

				c++;
				continue;
			}
			else
			{
				if (c >= (config.strsize ? config.strsize : 4))
					printb(&pe, buff, i-c, i, ofs * sizeof(buff) + i-c);

				c=0;
			}
		}
		memset(&buff, 0, sizeof(buff));
	}
	
	// libera a memoria
	pe_deinit(&pe);
	
	return 0;
}
