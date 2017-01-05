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
#include <string.h>
#include <time.h>
#include "pe.h"
#include "parser.h"
#include "defs.h"

extern struct options config;

static void exit_error(char * msg)
{
	fprintf(stderr, "%s: %s\n", PACKAGE, msg);
	exit(EXIT_FAILURE);
}

char * getmachinename(WORD Machine)
{
	char *machines[] = 
	{"Any machine type",
	 "Matsushita AM33",
	 "x86-64 (64-bits)",
	 "ARM little endian",
	 "ARMv7 (or higher) Thumb mode only",
	 "EFI byte code",
	 "Intel 386 and compatible (32-bits)",
	 "Intel Itanium",
	 "Mitsubishi M32R little endian",
	 "MIPS16",
	 "MIPS with FPU",
	 "MIPS16 with FPU",
	 "Power PC little endian",
	 "Power PC with floating point support",
	 "MIPS little endian",
	 "Hitachi SH3",
	};

	switch (Machine)
	{
		case 0x14c:
			return machines[6];
		default:
			return "Unkown";
	}

}

static void getdata(FILE *fp)
{
	/* Pointer to struct. Will be use as array. */
	PIMAGE_SECTION_HEADER sec;
	
	int i, found, sec_num;

	/* Find e_lfanew field of DOS header, that points to PE signature
	and skip four bytes of signature: PE\0\0 */
	{
		IMAGE_DOS_HEADER dos;
		(void) fread(&dos, sizeof(IMAGE_DOS_HEADER), 1, fp);

		if ((int)dos.e_magic != 0x5a4d)
			exit_error("the file is not a valid PE32 binary");

		(void) fseek(fp, (int)dos.e_lfanew + 4, SEEK_SET);
		
		if (config.dos || config.all)
		{
			printf("DOS header:\n");
			printf(" Magic number:\t\t\t%#x (%c%c)\n", dos.e_magic, dos.e_magic & 0xff, dos.e_magic >> 8);
			printf(" Bytes in last page:\t\t%d\n", dos.e_cblp);
			printf(" Pages in file:\t\t\t%d\n", dos.e_cp);
			printf(" Relocations:\t\t\t%d\n", dos.e_crlc);
			printf(" Size of header in paragraphs:\t%d\n", dos.e_cparhdr);
			printf(" Minimum extra paragraphs:\t%d\n", dos.e_minalloc);
			printf(" Maximum extra paragraphs:\t%d\n", dos.e_maxalloc);
			printf(" Initial (relative) SS value:\t%d\n", dos.e_ss);
			printf(" Initial SP value:\t\t%#x\n", dos.e_sp);
			printf(" Initial IP value:\t\t%#x\n", dos.e_ip);
			printf(" Initial (relative) CS value:\t%#x\n", dos.e_cs);
			printf(" Address of relocation table:\t%#x\n", dos.e_lfarlc);
			printf(" Overlay number:\t\t%#x\n", dos.e_ovno);
			printf(" OEM identifier:\t\t%#x\n", dos.e_oemid);
			printf(" OEM information:\t\t%#x\n", dos.e_oeminfo);
			printf(" PE header offset:\t\t%#x\n", (unsigned int)dos.e_lfanew);
			printf("\n");
		}
	}

	{
		IMAGE_FILE_HEADER coff;
		IMAGE_OPTIONAL_HEADER opt;
		
		/* Read the COFF FILE HEADER to get the number of sections in executable */
		if (fread(&coff, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1)
			exit_error("unable to read the COFF file header");
			
		if (config.coff || config.all)
		{
			char s[26];

			printf("COFF header:\n");
			printf(" Machine:\t\t\t%#x - %s\n", coff.Machine, getmachinename(coff.Machine));
			printf(" Number of sections:\t\t%d\n", coff.NumberOfSections);

			/* Time conversion */
			strftime(s, 26, "%m/%d/%Y at %I:%M:%S %p", gmtime((time_t *)&coff.TimeDateStamp));

			printf(" Date/time stamp:\t\t%d (%s)\n", (int)coff.TimeDateStamp, s);
			printf(" Symbol Table offset:\t\t%#x\n", (unsigned int)coff.PointerToSymbolTable);
			printf(" Number of symbols:\t\t%d\n", (int)coff.NumberOfSymbols);
			printf(" Size of optional header:\t%#x\n", coff.SizeOfOptionalHeader);
			printf(" Characteristics:\t\t%#x\n", coff.Characteristics);
			printf("\n");
		}

		/* Read the OPTIONAL HEADER, just to forward to SECTION HEADER with
			file pointer. We'll ignore OPTION HEADER here. */
		if (fread(&opt, sizeof(IMAGE_OPTIONAL_HEADER), 1, fp) != 1)
				exit_error("unable to read the optional file header");

		if (config.opt || config.all)
		{
			printf("Optional (PE) header:\n");
			printf(" Magic number:\t\t\t%#x\n", opt.Magic);
			printf(" Linker major version:\t\t%d\n", opt.MajorLinkerVersion);
			printf(" Linker minor version:\t\t%d\n", opt.MinorLinkerVersion);
			printf(" Size of CODE section:\t\t%#x\n", (unsigned int)opt.SizeOfCode);
			printf(" Size of DATA section:\t\t%#x\n", (unsigned int)opt.SizeOfInitializedData);
			printf(" Size of BSS section:\t\t%#x\n", opt.SizeOfUninitializedData);
			printf(" Entry point:\t\t\t%#x\n", opt.AddressOfEntryPoint);
			printf(" Address of CODE section:\t%#x\n", opt.BaseOfCode);
			printf(" Address of DATA section:\t%#x\n", opt.BaseOfData);
			printf(" Imagebase:\t\t\t%#x\n", opt.ImageBase);
			printf(" Alignment of sections:\t\t%#x\n", opt.SectionAlignment);
			printf(" Alignment factor:\t\t%d\n", opt.FileAlignment);
			printf(" Major version of required OS:\t%d\n", opt.MajorOperatingSystemVersion);
			printf(" Minor version of required OS:\t%d\n", opt.MinorOperatingSystemVersion);
			printf(" Major version of image:\t%d\n", opt.MajorImageVersion);
			printf(" Minor version of image:\t%d\n", opt.MinorImageVersion);
			printf(" Major version of subsystem:\t%d\n", opt.MajorSubsystemVersion);
			printf(" Minor version of subsystem:\t%d\n", opt.MinorSubsystemVersion);
			printf(" Size of image:\t\t\t%#x\n", opt.SizeOfImage);
			printf(" Size of headers:\t\t%#x\n", opt.SizeOfHeaders);
			printf(" Image file checksum:\t\t%#x\n", opt.CheckSum);
			printf(" Subsystem required:\t\t%#x\n", opt.Subsystem);
			printf(" DLL characteristics:\t\t%#x\n", opt.DllCharacteristics);
			printf(" Size of stack to reserve:\t%#x\n", opt.SizeOfStackReserve);
			printf(" Size of stack to commit:\t%#x\n", opt.SizeOfStackCommit);
			printf(" Size of heap space to reserve:\t%#x\n", opt.SizeOfHeapReserve);
			printf(" Size of heap space to commit:\t%#x\n", opt.SizeOfHeapCommit);
			printf(" Data-dictionary entries:\t%d\n", opt.NumberOfRvaAndSizes);
			printf("\n");
		}

		/* Executables have different number of sections, so we'll create
			an array of SECTION HEADER's to loop into this futhermore. */
		sec = 0;
		sec = (PIMAGE_SECTION_HEADER) malloc(sizeof(IMAGE_SECTION_HEADER)
					* coff.NumberOfSections);

		if (sec == NULL)
			exit_error("memory allocation error");

		(void) fread(sec, sizeof(IMAGE_SECTION_HEADER)*coff.NumberOfSections,
							1, fp);
							
		if (config.sections || config.all)
				printf("Sections:\n");

		/* It's time to loop into our array and find the .rsrc section */
		for (i=0, sec_num=0; i<(int)coff.NumberOfSections; i++)
		{
			if (config.sections || config.all)
			{
				printf(" Name:\t\t\t\t%s\n", sec[i].Name);
				printf(" Virtual size:\t\t\t%#x\n", sec[i].Misc.VirtualSize);
				printf(" Virtual address:\t\t%#x\n", sec[i].VirtualAddress);
				printf(" Data size:\t\t\t%#x\n", sec[i].SizeOfRawData);
				printf(" Data offset:\t\t\t%#x\n", sec[i].PointerToRawData);
				printf(" Characteristics:\t\t%#x\n", sec[i].Characteristics);
				printf("\n");
			}

			if (memcmp(sec[i].Name, ".rsrc", 5) == 0)
			{
				/* If .rsrc section was found, we store the position
					and forward the file pointer to offset in PointerToRawData
					field specified in SECTION HEADER. */
				sec_num = i;
				(void) fseek(fp, (int) sec[i].PointerToRawData, SEEK_SET);
				break;
			}
		}

	}
	
	if (config.product)
	{
		if (sec_num == 0)
			exit_error("the file does not contain a valid resource section");

		{
			IMAGE_RESOURCE_DIRECTORY dir;
			IMAGE_RESOURCE_DIRECTORY_ENTRY ent;
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
				exit_error("the file does not contain version information");

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
		}

		{
			IMAGE_RESOURCE_DATA_ENTRY data;
			/* Get and seek the offset to data beginning. Here we
				skip 32 bytes equivalent to the utf-16-le codified
				string "VS_VERSION_INFO". */
			(void) fread(&data, sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, fp);
			(void) fseek(fp, (signed long)data.OffsetToData -
								sec[sec_num].VirtualAddress +	sec[sec_num].PointerToRawData
								+ 32, SEEK_SET);
		}

		/* Finally, fill the version info struct and print version
			numbers. We need to make some operations to reverse and
			extract decimal values from little-endian bytes */
		{	
			VS_FIXEDFILEINFO info;
			if (fread(&info, sizeof(VS_FIXEDFILEINFO), 1, fp) == 1 && (config.product || config.all))
			{
				printf("Product Version:\t%u.%u.%u.%u\n",
				(unsigned int)(info.dwProductVersionMS & 0xffff0000) >> 16,
				(unsigned int)info.dwProductVersionMS & 0x0000ffff,
				(unsigned int)(info.dwProductVersionLS & 0xffff0000) >> 16,
				(unsigned int)info.dwProductVersionLS & 0x0000ffff);
			}
		}
	}
	free(sec);
}

int main(int argc, char *argv[])
{
	/* Call parse_options to populate the global
	 * config struct, defined in parser.c */
	parse_options(argc, argv);
	
	/* Try to get file pointer passed as argument.
	 * This function will exit program if no file
	 * is found or is not readable */
	FILE *fp = getfile(argc, argv);

	/* Just double-checking fp */
	if (fp != NULL)
		getdata(fp);

	exit(EXIT_SUCCESS);
}
