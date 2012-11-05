/*
	pev - the PE file analyzer toolkit
	
	pestr.c - search for [encrypted] strings in PE files

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

#include "pestr.h"

struct options config;
static int ind;

static void usage()
{
	printf("Usage: %s OPTIONS FILE\n"
	"Search for [encrypted] strings in PE files\n"
	"\nExample: %s acrobat.exe\n"
	"\nOptions:\n"
	" -n, --min-length                       set minimun string length (default: 4)\n"
	" -o, --offset                           show string offset in file\n"
	" -s, --section                          show string section, if exists\n"
	" --net                                  show network-related strings (IPs, hostnames etc)\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
}

static void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "fosn:v";

	static const struct option long_options[] = {
		{"functions",       no_argument,        NULL, 'f'},
		{"offset",          no_argument,        NULL, 'o'},
		{"section",         no_argument,        NULL, 's'},
		{"min-length",      required_argument,  NULL, 'n'},
		{"help",            no_argument,        NULL,  1 },
		{"version",         no_argument,        NULL,  3 },
		{"net",           no_argument,          NULL,  2 },
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

			case 2:
				config.net = true;
				break;

			case 'f':
				//config.functions = true;
				EXIT_ERROR("not implemented yet");
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

static unsigned char *ofs2section(PE_FILE *pe, unsigned long offset)
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

static char *ref_functions(PE_FILE *pe, unsigned long offset)
{
	unsigned long buff, aux=0;
	char *str = (char *) xmalloc(sizeof(char) * 100);
	FILE *fp = pe->handle;

	aux = ftell(fp);
	rewind(fp);
	memset(str, 0, sizeof(str));

	while (fread(&buff, 1, sizeof(buff), fp))
	{
		snprintf(str, 100, "%#x", ofs2rva(pe, offset));
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

#define ASCII 0
#define UNICODE 1

static bool ishostname(const char *s, unsigned short encoding)
{
	pcre *re;
	const char *err;
	int rc, errofs, ovector[OVECCOUNT];
	unsigned i;
	char *patterns[] = {
		"^[a-zA-Z]{3,}://.*$", // protocol://
		"[1-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:?" // ipv4
	};

	char *domains[] = {
	".aero",	".asia",	".biz",	".com",	".cat",	".com",	".coop",
	".info",	".int",	".jobs",	".mobi",	".museum",	".name",	".net", ".br",
	".org",	".pro",	".tel",	".travel",	".xxx", ".edu", ".gov", ".mil",
	".jus",	
	};

	if (!isalnum((int) *s))
		return false;

	for (i=0; i < sizeof(domains) / sizeof(domains[0]); i++)
	{
		// TODO: unicode equivalent
		if (strcasestr(s, domains[i]))
			return true;
	}

	for (i=0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
	{
		re = pcre_compile(patterns[i], (encoding == UNICODE) ? PCRE_UCP : 0, &err, &errofs, NULL);

		if (!re)
			EXIT_ERROR("regex compilation failed");

		rc = pcre_exec(re, NULL, s, LINE_BUFFER, 0, 0, ovector, OVECCOUNT);
		pcre_free(re);

		if (rc > 0)
			return true;
	}

	return false;
}

static void printb(PE_FILE *pe, unsigned char *bytes, unsigned pos, unsigned length, unsigned long
offset)
{
	if (config.offset)
		printf("%#lx\t", (unsigned long) offset);

	if (config.section)
	{
		char *s = (char *) ofs2section(pe, offset);
		printf("%s\t", s ? s : "[none]");
	}

	if (config.functions)
	{
		char *s = ref_functions(pe, offset);

		printf("%s\t", s ? s : "[none]");
		free(s);
	}

	// print the string
	while (pos < length)
	{
	
		if (bytes[pos] == '\0') // unicode printing
		{
			pos++;
			continue;
		}
		putchar(bytes[pos++]);
	}

	putchar('\n');
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	unsigned char *buff, byte;
	unsigned int ascii, ofs, pos;
	unsigned int utf = 0;

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
	buff = (unsigned char *) xmalloc(LINE_BUFFER);
	memset(buff, 0, LINE_BUFFER);

	for (ofs=ascii=pos=0; fread(&byte, 1, 1, pe.handle);	ofs++)
	{
		if (isprint(byte))
		{
			ascii++;
			buff[pos++] = byte;
			continue;
		}
		else if (ascii == 1 && byte == '\0')
		{
			utf++;
			buff[pos++] = byte;
			ascii = 0;
			continue;
		}
		else
		{
			if (ascii >= (config.strsize ? config.strsize : 4))
			{
				if (config.net)
				{
					if (ishostname((char *) buff, ASCII))
						printb(&pe, buff, 0, ascii, ofs - ascii);
				}
				else
					printb(&pe, buff, 0, ascii, ofs - ascii);
					
			}
			else if (utf >= (config.strsize ? config.strsize : 4))
			{
				if (config.net)
				{
					if (ishostname((char *) buff, UNICODE))
						printb(&pe, buff, 0, utf*2, ofs - utf*2);
				}
				else
					printb(&pe, buff, 0, utf*2, ofs - utf*2);
					
			}
			ascii = utf = pos = 0;
			memset(buff, 0, LINE_BUFFER);
		}
	}
	free(buff);
	
	// libera a memoria
	pe_deinit(&pe);
	
	return 0;
}
