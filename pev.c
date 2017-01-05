/*
	pev - PE version dump utility

	Copyright (C) 2010 Coding 40°

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
#include <locale.h>
#include <string.h>
#include "pe.h"

#define PACKAGE "pev"
#define VER "0.22"

static void showError(char * msg)
{
	fprintf(stderr, "%s: %s\n", PACKAGE, msg);
	exit(EXIT_FAILURE);
}

static int getdata(FILE *fp)
{
	/* Structs declarations (from pe.h) */
	IMAGE_DOS_HEADER dos;
	IMAGE_FILE_HEADER coff;
	IMAGE_OPTIONAL_HEADER opt;
	IMAGE_RESOURCE_DIRECTORY dir;
	IMAGE_RESOURCE_DIRECTORY_ENTRY ent;
	IMAGE_RESOURCE_DATA_ENTRY data;
	VS_FIXEDFILEINFO info;
	
	/* Pointer to struct. Will be use as array. */
	PIMAGE_SECTION_HEADER sec;
	
	int i, found, sec_num;
	char rsrc[] = ".rsrc";

	/* Find e_lfanew field of DOS header, that points to PE signature
	and skip four bytes of signature: PE\0\0 */
	(void) fread(&dos, sizeof(IMAGE_DOS_HEADER), 1, fp);

	if ((int)dos.e_magic != 0x5a4d)
		showError("the file is not a valid PE32 binary");

	(void) fseek(fp, (int)dos.e_lfanew + 4, SEEK_SET);

	/* Read the COFF FILE HEADER to get the number of sections in executable */
	if (fread(&coff, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1)
		showError("unable to read the COFF file header");

	/* Read the OPTIONAL HEADER, just to forward to SECTION HEADER with
		file pointer. We'll ignore OPTION HEADER here. */
	if (fread(&opt, sizeof(IMAGE_OPTIONAL_HEADER), 1, fp) != 1)
			showError("unable to read the optional file header");

	/* Executables have different number of sections, so we'll create
		an array of SECTION HEADER's to loop into this futhermore. */
	sec = (PIMAGE_SECTION_HEADER) malloc(sizeof(IMAGE_SECTION_HEADER)
				* coff.NumberOfSections);

	if (sec == NULL)
		showError("memory allocation error");
	
	(void) fread(sec, sizeof(IMAGE_SECTION_HEADER)*coff.NumberOfSections,
						1, fp);

	/* It's time to loop into our array and find the .rsrc section */
	for (i=0, sec_num=0; i<(int)coff.NumberOfSections; i++)
	{
		if (memcmp(sec[i].Name, rsrc, 5) == 0)
		{
			/* If .rsrc section was found, we store the position
			   and forward the file pointer to offset in PointerToRawData
			   field specified in SECTION HEADER. */
			sec_num = i;
			(void) fseek(fp, (int) sec[i].PointerToRawData, SEEK_SET);
			break;
		}
	}

	if (sec_num == 0)
		showError("the file does not contain a valid resource section");

	/* Read the RESOURCE DIR struct to get the first entry */
	(void) fread(&dir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);

	/* Read the *root* RESOURCE DIR ENTRY by looping through
		all entries (named or not). */
	for (i=0, found=0; i < (int)
			(dir.NumberOfIdEntries+dir.NumberOfNamedEntries); i++)
	{
		(void) fread(&ent, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
		/* We look for version entry, specified by RT_VERSION in pe.h. */
		if (ent.DUMMYUNIONNAME.Name == (int)RT_VERSION)
		{
			/* The offset pointed by "OffsetToData" field will point to another
				DIRECTORY_ENTRY structure, signed by higher bit set to 1. The
				other 31 bits are the offset. We'll XOR it with 0x80000000. */
			(void) fseek(fp, (signed long)sec[sec_num].PointerToRawData +
			(ent.DUMMYUNIONNAME2.OffsetToData ^ 0x80000000), SEEK_SET);
			found = 1;
			break;
		}

	}

	if (found == 0)
		showError("the file does not contain version information");

	/* Read the first RT_VERSION child directory (commonly named "1"). */
	(void) fread(&dir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
	(void) fread(&ent, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
	(void) fseek(fp, (signed long) sec[sec_num].PointerToRawData +
	(ent.DUMMYUNIONNAME2.OffsetToData ^ 0x80000000), SEEK_SET);

	/* Read the second subdir, commonly an integer. This subdir does not
		point to another RESOURCE DIRECTORY, so we doest not need to XOR.
		This subdir points to a RESOURCE DARA ENTRY, that is our goal. */
	(void) fread(&dir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
	(void) fread(&ent, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
	(void) fseek(fp, (signed long)sec[sec_num].PointerToRawData +
	(int)ent.DUMMYUNIONNAME2.OffsetToData, SEEK_SET);

	/* Get and seek the offset to data beginning. Here we
		skip 32 bytes equivalent to the utf-16-le codified
		string "VS_VERSION_INFO". */
	(void) fread(&data, sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, fp);
	(void) fseek(fp, (signed long)data.OffsetToData -
						sec[sec_num].VirtualAddress +	sec[sec_num].PointerToRawData
						+ 32, SEEK_SET);

	free(sec);

	/* Finally, fill the version info struct and print version
		numbers. We need to make some operations to reverse and
		extract decimal values from little-endian bytes */
		
	if (fread(&info, sizeof(VS_FIXEDFILEINFO), 1, fp) == 1)
	{
		printf("%u.%u.%u.%u\n",
		(unsigned int)(info.dwProductVersionMS & 0xffff0000) >> 16,
		(unsigned int)info.dwProductVersionMS & 0x0000ffff,
		(unsigned int)(info.dwProductVersionLS & 0xffff0000) >> 16,
		(unsigned int)info.dwProductVersionLS & 0x0000ffff);
		
		return 1;
	}
	return 0;
}

/* Paramters for getopt_long() function */
static const char short_options[] = "hv";

static const struct option long_options[] = {
	{"help", no_argument, NULL, (int)'h'},
	{"version", no_argument, NULL, (int)'v'},
	{ NULL, no_argument, NULL, 0 } };
static int index;

int main(int argc, char *argv[])
{
	FILE *fp;
	int c;

	/* Set locale to use native user language */
	(void)setlocale(LC_ALL, "");

	/* Parsing arguments with getopt_long() */
	while ((c = getopt_long(argc, argv, short_options,
			long_options, &index)) != 0)
	{
		if (c < 0)
		break;

		switch (c)
		{
		case 0:
			break;

		case 'v':
			printf("PE Version utility (pev) %s\n", VER);
			exit(EXIT_SUCCESS);

		case 'h':
			printf("Usage: pev <file>\nExample:\n\tpev calc.exe\n");
			exit(EXIT_SUCCESS);
			
		default:
			fprintf(stderr, "Try '--help' for more information.\n");
			exit(EXIT_FAILURE);
		}
	}

	if (argv[1] == NULL)
	{
		fprintf(stderr, "%s: no input file\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	fp = fopen(argv[1], "rb");

	if (fp == NULL)
	{
		fprintf(stderr, "%s: file not found\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	/* Call to getdata() */
	if (getdata(fp) == 0)
	{
		fprintf(stderr, "%s: unable to locate binary version\n", PACKAGE);
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
