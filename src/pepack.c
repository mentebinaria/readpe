/*
	pev - the PE file analyzer toolkit
	
	pepack.c - search packers in PE files

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

#include "pepack.h"

struct options config;
static int ind;

void usage()
{
	printf("Usage: %s FILE\n"
	"Search for packers in PE files\n"
	"\nExample: %s putty.exe\n"
	"\nOptions:\n"
	" -d, --database <file>                  use database file (default: ./userdb.txt)\n"
	" -f, --format <text|csv|xml|html>       change output format (default: text)\n"	
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "d:f:v";

	static const struct option long_options[] = {
		{"database",         required_argument, NULL, 'd'},
		{"format",           required_argument, NULL, 'f'},
		{"help",             no_argument,       NULL,  1 },
		{"version",          no_argument,       NULL, 'v'},
		{ NULL,              0,                 NULL,  0 }
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
				
			case 'd':
				config.dbfile = optarg; break;
				
			case 'f':
				parse_format(optarg); break;
				
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

/* MEW Packer and others basically stores the entrypoint
   in a section marked only as readable (without
   executable and/or writable flags)
   Windows Loader still executes the binary
*/
bool genereic_packer(PE_FILE *pe, QWORD ep)
{
   unsigned char packer = '0';
	IMAGE_SECTION_HEADER *sec = pe_rva2section(pe, ep);

   // we count the flags for the section and if there is more than
   // 2 it means we don't have the mew_packer
   unsigned int invalid_flags[] =
	{0x20000000, 0x40000000, 0x80000000};

	if (!sec)
		return false;

	// MEW never leave EP in .text section
	if (!memcmp(sec->Name, ".text", 5))
		return false;

	for (unsigned int j=0; j < sizeof(invalid_flags) / sizeof(unsigned int); j++)
	{
		if (sec->Characteristics & invalid_flags[j])
			packer++;
	}

   return (packer < '3');
}

bool loaddb(FILE **fp)
{
	char *dbfile = config.dbfile ? config.dbfile : "userdb.txt";

	*fp = fopen(dbfile, "r");	
	return (*fp != NULL);
}

bool match_peid_signature(unsigned char data[], char *sig)
{
	unsigned char byte_str[3], byte;
	unsigned long int i=0;
	
	// add null terminator
	byte_str[2] = '\0';
	
	while (*sig)
	{
		// ignore '=' and blank spaces
		if (*sig == '=' || *sig == ' ')
		{
			sig++;
			continue;
		}

		// match "??"
		if (*sig == '?')
		{
			sig += 2;
			i++;
			continue;
		}

		memcpy(byte_str, sig, 2);
		byte = strtoul((char *) byte_str, NULL, 16);

		if (data[i++] != byte)
			return false;

		sig += 2; // next two characters of signature
	}
	
	return true;
}

bool compare_signature(unsigned char *data, QWORD ep_offset, FILE *dbfile, char *packer_name)
{
	char *buff = (char *) xmalloc(MAX_SIG_SIZE);
	size_t len;
	
	if (!dbfile || !data)
		return false;

	//memset(buff, 0, MAX_SIG_SIZE);
	while (fgets(buff, MAX_SIG_SIZE, dbfile))
	{
		// line lenght
		len = strlen(buff);
		
		// ifgore comments and blank lines
		if (*buff == ';' || *buff == '\n' || *buff == '\r')
			continue;
		
		// remove newline from buffer
		if (*(buff+len-1) == '\n')
			*(buff+len-1) = '\0';
		
		// removing carriage return, if present
		if (*(buff+len-2) == '\r')
		{
			*(buff+len-2) = '\0';
			//*(buff+len-1) = '\0';
			len--; // update line lenght
		}
		
		// line have [packer name]? Fill packer_name pointer
		if (*buff == '[' && *(buff+len-2) == ']')
		{
			*(buff+len-2) = '\0'; // remove square brackets
			strncpy(packer_name, buff+1, MAX_MSG);
		}
		
		// check if signature match
		if (!strncasecmp(buff, "signature", 9))
		{
			if (match_peid_signature(data + ep_offset, buff+9))
			{
				free(buff);
				return true;
			}
		}
	}
	packer_name = NULL;
	free(buff);
	return false;
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *dbfile = NULL, *fp = NULL;
	QWORD ep_offset, pesize;
	char value[MAX_MSG];
	unsigned char *pe_data;

	if (argc < 2)
	{
		usage();
		exit(1);
	}

	memset(&config, 0, sizeof(config));
	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("invalid PE file");

	if (!pe_get_optional(&pe))
		EXIT_ERROR("unable to read optional header");

   if (!(ep_offset = rva2ofs(&pe, pe.entrypoint)))
		EXIT_ERROR("unable to get entrypoint offset");
	
	pesize = pe_get_size(&pe);
	pe_data = (unsigned char *) xmalloc(pesize);
	
	//if (fseek(pe.handle, ep, SEEK_SET))
		//EXIT_ERROR("unable to seek to entrypoint offset");
	
	if (!fread(pe_data, pesize, 1, pe.handle))
		EXIT_ERROR("unable to read entrypoint data");
	
	if (!loaddb(&dbfile))
		fprintf(stderr, "warning: without valid database file, %s will search in generic mode only\n", PROGRAM);
	
	// packer by signature
	if (compare_signature(pe_data, ep_offset, dbfile, value));
	// genereic detection
	else if (genereic_packer(&pe, ep_offset))
		snprintf(value, MAX_MSG, "generic");
	else
		snprintf(value, MAX_MSG, "no packer found");
	
	free(pe_data);
	output("packer", value);

	if (dbfile)
		fclose(dbfile);
	pe_deinit(&pe);
	
	return 0;
}
