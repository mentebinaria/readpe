/*
	pev - the PE file analyzer toolkit
	
	pesteg.c - PE steganographer

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

#include "pesteg.h"

static int ind;
const char *datafile_path;

void usage()
{
	printf("Usage: %s -d DATAFILE [OPTIONS] FILE OUTFILE\n"
	"Creates OUTFILE, a copy of FILE with DATAFILE hidden\n"
	"\nExample: %s -d message.txt wordpad.exe out.exe\n"
	"\nOptions:\n"
	" -d, --data <filename>                  file to be hidden in\n"
	" -k, --key <key>                        data encription key\n"
	" -m, --method <1|2|3|4>                 set steganography method\n"
	"                                         1 - code section hole (default)\n"
	"                                         2 - non-code section hole\n"
	"                                         3 - unused headers area\n"
	"                                         4 - image page\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "d:m:k:v";

	static const struct option long_options[] = {
		{"data",             required_argument, NULL, 'd'},
		{"method",           required_argument, NULL, 'm'},
		{"key",              required_argument, NULL, 'k'},
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

			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

			case 'd':
				datafile_path = optarg;
				break;

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

// almost asshole :)
bool ishole(unsigned char *data, int max)
{
	for (max--; max >= 0 && data[max]; max--)
	{
		if (data[max] != 0)
			return false;
	}
	return true;
}

unsigned long get_hole(PE_FILE *pe, IMAGE_SECTION_HEADER *section)
{
	const size_t buff_size = 32;
	unsigned char *buff = xmalloc(buff_size);
	long start, end;
	unsigned long size = 0;

	//printf("de %#x a %#x\n", start, end);

	start = section->PointerToRawData;
	end = start + section->SizeOfRawData;
	fseek(pe->handle, start, SEEK_SET);

	while (start++ < end)
	{
		if (fread(buff, buff_size, 1, pe->handle) != 1)
			break;

		if (ishole(buff, buff_size))
		{
			//printf("hole at %#lx\n", ftell(pe->handle) - buff_size);
			//memset(&buff, 0, buff_size);
			if (!size)
				fseek(pe->handle, -buff_size+1, SEEK_CUR);

			size += buff_size;
		}
	}

	free(buff);
	return size;
}

bool find_section(PE_FILE *pe, IMAGE_SECTION_HEADER *sec, bool executable)
{
	rewind(pe->handle);
	if (!pe_get_sections(pe))
		return false;

	if (fseek(pe->handle, pe->addr_sections, SEEK_SET))
		return false;

	for (unsigned int i=0; i < pe->num_sections; i++)
	{
		fread(sec, sizeof(*sec), 1, pe->handle);
		if (executable && (sec->Characteristics & 0x20))
			return true;
	}
	return false;
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp, *datafile, *outfile;
	IMAGE_SECTION_HEADER section;
	unsigned long data_size, hole_size = 0;
	unsigned char *buff;

	fp = datafile = outfile = NULL;
	if (argc < 4)
	{
		usage();
		exit(1);
	}

	parse_options(argc, argv); // opcoes
	
	//if (!(outfile = fopen(argv[argc-1], "w")))
	//	EXIT_ERROR("unable to write outfile");

	if (!(fp = fopen(argv[argc-2], "r+b")))
		EXIT_ERROR("PE file not found or unreadable");

	if (!(datafile = fopen(datafile_path, "rb")))
		EXIT_ERROR("datafile not found or unreadable");

	pe_init(&pe, fp);

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	// switch method
	if (!find_section(&pe, &section, true))
		EXIT_ERROR("no code sections found");

	hole_size = get_hole(&pe, &section);

	if (!hole_size)
		EXIT_ERROR("no holes found");

	printf("hole size: %ld\n", hole_size);
	printf("hole addr: %ld\n", ftell(pe.handle));

	// <pev> </pev>

	fseek(datafile, 0L, SEEK_END);
	data_size = ftell(datafile);
	if (data_size + 11> hole_size)
		EXIT_ERROR("not enough space");

	rewind(datafile);
	buff = xmalloc(data_size);
	fread(buff, sizeof(buff), 1, datafile); // TODO: misleading sizeof? sizeof(pointer_type) == 4, or 8.

	//'fwrite(buff, sizeof(buff), 1, pe.handle);
	free(buff);
	
	fclose(fp); fclose(outfile); fclose(datafile);
	return 0;
}
