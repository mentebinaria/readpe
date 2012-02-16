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
#include "libpe.h"
#include "parser.h"
#include "defs.h"
/* modules */
#include "modules/tls.h"

extern struct options config;

char * dec2bin(unsigned int dec, char *bin, int bits)
{
	// by Gabriel Duarte <confusosk8@gmail.com>
	int i;

	for(i=0; i<bits; i++)
		bin[bits - i - 1] = (dec & (0x1 << i)) ? '1' : '0';

	bin[bits] = '\0';

	return bin;
}

/* Print machine type string from machine
 * type code provided by coff.Machine field */
static void print_machine_type(WORD Machine)
{
	unsigned int i;
	/* By default, machine is unknown */
	char *machine = "Unknown machine type";
	static const machine_type arch[] = 
	{
		{"Any machine type", 0x0},
		{"Matsushita AM33", 0x1d3},
		{"x86-64 (64-bits)", 0x8664},
		{"ARM little endian", 0x1c0},
		{"ARMv7 (or higher) Thumb mode only", 0x1c4},
		{"EFI byte code", 0xebc},
		{"Intel 386 and compatible (32-bits)",0x14c},
		{"Intel Itanium", 0x200},
		{"Mitsubishi M32R little endian", 0x9041},
		{"MIPS16", 0x266},
		{"MIPS with FPU", 0x366},
		{"MIPS16 with FPU", 0x466},
		{"Power PC little endian", 0x1f0},
		{"Power PC with floating point support", 0x1f1},
		{"MIPS little endian", 0x166},
		{"Hitachi SH3", 0x1a2}, 
		{"Hitachi SH3 DSP", 0x1a3},
		{"Hitachi SH4", 0x1a6},
		{"Hitachi SH5",  0x1a8},
		{"ARM or Thumb (\"interworking\")", 0x1c2},
		{"MIPS little-endian WCE v2", 0x169}
	};

	for(i=0; i<(sizeof(arch)/sizeof(machine_type)); i++)
	{
		if(Machine == arch[i].m_code)
		machine = (char*)arch[i].m_name;
	}

	puts(machine);
}

static void print_subsystem_type(WORD Subsystem)
{
	static const char *subs[] = {
		"Unknown subsystem",
		"System native",
		"Windows GUI",
		"Windows CLI",
		"Posix CLI",
		"Windows CE GUI",
		"EFI application",
		"EFI driver with boot",
		"EFI run-time driver",
		"EFI ROM",
		"XBOX"
	};
	
	/* needs to be between 0 and 10 */
	if (Subsystem <= 10)
		printf("(%s)\n", subs[Subsystem]);
}

static void print_coff_characteristics(WORD c)
{
	register unsigned int i, j;
	static const char *flags[] = {
	"base relocations stripped",
	"executable image",
	"line numbers removed (deprecated)",
	"local symbols removed (deprecated)",
	"aggressively trim (deprecated for Windows 2000 and later)",
	"can handle more than 2 GB addresses", "",
	"little-endian (deprecated)",
	"32-bit machine",
	"debugging information removed",
	"copy to swap if it's on removable media",
	"copy to swap if it's on network media",
	"system file",
	"DLL image",
	"uniprocessor machine",
	"big-endian (deprecated)"
	};

	for (i=0x1, j=0; i<0x8000; i<<=1, j++)
		if (c & i) printf("\t\t\t\t%s\n", flags[j]);
}

static void print_dll_characteristics(WORD c)
{
	register unsigned int i, j;
	static const char *flags[] = {
		"relocation at load time (ASLR)",
		"integrity checks enforced",
		"NX compatible (DEP)",
		"no isolation",
		"do not use Structured Exception Handling (SEH)",
		"no bind",
		"WDM driver", "",
		"Terminal Server aware"
	};

	for (i=0x40, j=0; i<0x8000; i<<=1, j++)
		if (c & i) printf("\t\t\t\t%s\n", flags[j]);
}

static void print_session_characteristics(DWORD d)
{
	/* Only important bits are tested here */
	if (d & 0x20) printf("\t\t\t\t%s\n", "contains executable code");
	if (d & 0x40) printf("\t\t\t\t%s\n", "contains initialized data");
	if (d & 0x80) printf("\t\t\t\t%s\n", "contains uninitialized data");
	if (d & 0x200) printf("\t\t\t\t%s\n", "contains comments/info");
	if (d & 0x8000) printf("\t\t\t\t%s\n", "contains data referenced through the GP");
	if (d & 0x01000000) printf("\t\t\t\t%s\n", "contains extended relocations");
	if (d & 0x02000000) printf("\t\t\t\t%s\n", "can be discarded as needed");
	if (d & 0x04000000) printf("\t\t\t\t%s\n", "cannot be cached");
	if (d & 0x08000000) printf("\t\t\t\t%s\n", "is not pageable");
	if (d & 0x10000000) printf("\t\t\t\t%s\n", "can be shared in memory");
	if (d & 0x20000000) printf("\t\t\t\t%s\n", "is executable");
	if (d & 0x40000000) printf("\t\t\t\t%s\n", "is readable");
	if (d & 0x80000000) printf("\t\t\t\t%s\n", "is writable");
}

void print_version_info(WORD version_ofs, DWORD rsrc_ofs, DWORD rsrc_va, int pos, FILE *fp)
{
	IMAGE_RESOURCE_DIRECTORY sdir;
	IMAGE_RESOURCE_DIRECTORY_ENTRY sent;
	
	/* The offset pointed by "OffsetToData" field will point to another
	DIRECTORY_ENTRY structure, signed by higher bit set to 1. The
	other 31 bits are the offset. We'll XOR it with 0x80000000. */
	fseek(fp, rsrc_ofs + version_ofs, SEEK_SET);

	/* read first RT_VERSION child directory (commonly named "1"). */
	fread(&sdir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
	fread(&sent, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
	fseek(fp, rsrc_ofs + (sent.u2.OffsetToData ^ 0x80000000), SEEK_SET);

	/* read the second subdir, commonly an integer. This subdir does not
		* point to another RESOURCE DIRECTORY, so we doesn't not need to XOR.
		* Instead, the subdir points to a RESOURCE DATA ENTRY, that is our goal. */
	fread(&sdir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
	fread(&sent, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
	
	fseek(fp, rsrc_ofs + sent.u2.OffsetToData, SEEK_SET);

	{
		IMAGE_RESOURCE_DATA_ENTRY data;
		/* get and seek the offset to data beginning. Here we
			*	skip 32 bytes equivalent to the utf-16-le codified
			* string "VS_VERSION_INFO". */
		fread(&data, sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, fp);
		fseek(fp, data.OffsetToData -
							rsrc_va + rsrc_ofs
							+ 32, SEEK_SET);
	}

	/* finally, fill the version info struct and print version
		* numbers. We need to make some operations to reverse and
		* extract decimal values from little-endian bytes */
	{	
		VS_FIXEDFILEINFO info;
		if (fread(&info, sizeof(VS_FIXEDFILEINFO), 1, fp) == 1)
		{
			if (!config.product || config.resources)
				printf("  Product Version:\t\t");
			
			printf("%u.%u.%u.%u\n",
			(unsigned int)(info.dwProductVersionMS & 0xffff0000) >> 16,
			(unsigned int)info.dwProductVersionMS & 0x0000ffff,
			(unsigned int)(info.dwProductVersionLS & 0xffff0000) >> 16,
			(unsigned int)info.dwProductVersionLS & 0x0000ffff);
		}
	}
	
	/* restoring original file pointer position */
	fseek(fp, pos, SEEK_SET);
}

static void getdata(FILE *fp)
{
	/* Pointer to struct. Will be used as array. */
	PIMAGE_SECTION_HEADER sec;
	
	register int i;
	int sec_num;

	/* find e_lfanew field of DOS header that points to PE signature */
	{
		IMAGE_DOS_HEADER dos;
		if (!fread(&dos, sizeof(IMAGE_DOS_HEADER), 1, fp)) EXIT_WITH_ERROR("unable to read data");

		if ((int)dos.e_magic != 0x5a4d)
			EXIT_WITH_ERROR("the argument is not a valid PE file");

		/* skip 4-byte PE signature */
		if (fseek(fp, (int)dos.e_lfanew + 4, SEEK_SET))
			EXIT_WITH_ERROR("impossible to seek through (corrupted?) file");
		
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
		IMAGE_OPTIONAL_HEADER_64 opt64;
		PIMAGE_DATA_DIRECTORY datadirs;
		WORD arch;
		int numdatadirs=0;
		long imagebase = 0;
		unsigned int tls_addr=0;
		
		/* read COFF file header to get number of sections */
		if (fread(&coff, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1)
			EXIT_WITH_ERROR("unable to read COFF file header");
			
		if (config.coff || config.all)
		{
			char binary_chars[17] = "";
			char formatted_date[33];

			printf("COFF header:\n");
			printf(" Machine:\t\t\t%#x - ", coff.Machine);
			print_machine_type(coff.Machine);
			printf(" Number of sections:\t\t%d\n", coff.NumberOfSections);

			strftime(formatted_date, 33, "%a, %d %b %Y %H:%M:%S UTC",
						gmtime((time_t *)&coff.TimeDateStamp));

			printf(" Date/time stamp:\t\t%d (%s)\n", (int)coff.TimeDateStamp, formatted_date);
			printf(" Symbol Table offset:\t\t%#x\n", (unsigned int)coff.PointerToSymbolTable);
			printf(" Number of symbols:\t\t%d\n", (int)coff.NumberOfSymbols);
			printf(" Size of optional header:\t%#x\n", coff.SizeOfOptionalHeader);
			printf(" Characteristics:\t\t%#x (%s)\n", coff.Characteristics,
						dec2bin(coff.Characteristics, binary_chars, 16));
			print_coff_characteristics(coff.Characteristics);
			printf("\n");
		}

		/* read magic number to discover architecture */
		if (fread(&arch, sizeof(WORD), 1, fp) != 1) EXIT_WITH_ERROR("unable to get file magic number");
		fseek(fp, -sizeof(WORD), SEEK_CUR);
			
		/* read optional header */
		if (arch == PE32)
		{
			if (fread(&opt, sizeof(IMAGE_OPTIONAL_HEADER), 1, fp) != 1)
						EXIT_WITH_ERROR("unable to read the optional file header");
		}
		else if (arch == PE64)
		{
			if (fread(&opt64, sizeof(IMAGE_OPTIONAL_HEADER_64), 1, fp) != 1)
						EXIT_WITH_ERROR("unable to read the optional file header");
		}
		else
			EXIT_WITH_ERROR("unable to detect PE format");
		
		if (config.opt || config.all)
		{
			char binary_chars[17] = "";

			printf("Optional (PE) header:\n");
			printf(" Magic number:\t\t\t%#x ", arch);
	
			/* print things */
			if (arch == PE32)
			{
				printf("(PE32)\n");
				printf(" Linker major version:\t\t%d\n", opt.MajorLinkerVersion);
				printf(" Linker minor version:\t\t%d\n", opt.MinorLinkerVersion);
				printf(" Size of .code section:\t\t%#x\n", (unsigned int)opt.SizeOfCode);
				printf(" Size of .data section:\t\t%#x\n", (unsigned int)opt.SizeOfInitializedData);
				printf(" Size of .bss section:\t\t%#x\n", opt.SizeOfUninitializedData);
				printf(" Entry point:\t\t\t%#x\n", opt.AddressOfEntryPoint);
				printf(" Address of .code section:\t%#x\n", opt.BaseOfCode);
				printf(" Address of .data section:\t%#x\n", opt.BaseOfData);
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
				printf(" Subsystem required:\t\t%d ", opt.Subsystem);
				print_subsystem_type(opt.Subsystem);
				printf(" DLL characteristics:\t\t%#x (%s)\n", opt.DllCharacteristics,
				dec2bin(opt.DllCharacteristics, binary_chars, 16));
				if (opt.DllCharacteristics > 0x0)
				{
					print_dll_characteristics(opt.DllCharacteristics);
					printf("\n");
				}
				printf(" Size of stack to reserve:\t%#x\n", opt.SizeOfStackReserve);
				printf(" Size of stack to commit:\t%#x\n", opt.SizeOfStackCommit);
				printf(" Size of heap space to reserve:\t%#x\n", opt.SizeOfHeapReserve);
				printf(" Size of heap space to commit:\t%#x\n", opt.SizeOfHeapCommit);
				printf(" Data-dictionary entries:\t%d\n", opt.NumberOfRvaAndSizes);
			}
			else if (arch == PE64)
			{
				printf("(PE32+)\n");
				printf(" Linker major version:\t\t%d\n", opt64.MajorLinkerVersion);
				printf(" Linker minor version:\t\t%d\n", opt64.MinorLinkerVersion);
				printf(" Size of .code section:\t\t%#x\n", (unsigned int)opt64.SizeOfCode);
				printf(" Size of .data section:\t\t%#x\n", (unsigned int)opt64.SizeOfInitializedData);
				printf(" Size of .bss section:\t\t%#x\n", opt64.SizeOfUninitializedData);
				printf(" Entry point:\t\t\t%#x\n", opt64.AddressOfEntryPoint);
				printf(" Address of .code section:\t%#x\n", opt64.BaseOfCode);
				/* there is no BaseOfData here */
				#if __WORDSIZE == 64
				printf(" Imagebase:\t\t\t%#lx\n", opt64.ImageBase);
				#else
				printf(" Imagebase:\t\t\t%#llx\n", opt64.ImageBase);
				#endif
				printf(" Alignment of sections:\t\t%#x\n", opt64.SectionAlignment);
				printf(" Alignment factor:\t\t%d\n", opt64.FileAlignment);
				printf(" Major version of required OS:\t%d\n", opt64.MajorOperatingSystemVersion);
				printf(" Minor version of required OS:\t%d\n", opt64.MinorOperatingSystemVersion);
				printf(" Major version of image:\t%d\n", opt64.MajorImageVersion);
				printf(" Minor version of image:\t%d\n", opt64.MinorImageVersion);
				printf(" Major version of subsystem:\t%d\n", opt64.MajorSubsystemVersion);
				printf(" Minor version of subsystem:\t%d\n", opt64.MinorSubsystemVersion);
				printf(" Size of image:\t\t\t%#x\n", opt64.SizeOfImage);
				printf(" Size of headers:\t\t%#x\n", opt64.SizeOfHeaders);
				printf(" Image file checksum:\t\t%#x\n", opt64.CheckSum);
				printf(" Subsystem required:\t\t%d ", opt64.Subsystem);
				print_subsystem_type(opt64.Subsystem);
				printf(" DLL characteristics:\t\t%#x (%s)\n", opt64.DllCharacteristics,
				dec2bin(opt64.DllCharacteristics, binary_chars, 16));
				if (opt64.DllCharacteristics > 0x0)
				{
					print_dll_characteristics(opt64.DllCharacteristics);
					printf("\n");
				}
				#if __WORDSIZE == 64
				printf(" Size of stack to reserve:\t%#lx\n", opt64.SizeOfStackReserve);
				printf(" Size of stack to commit:\t%#lx\n", opt64.SizeOfStackCommit);
				printf(" Size of heap space to reserve:\t%#lx\n", opt64.SizeOfHeapReserve);
				printf(" Size of heap space to commit:\t%#lx\n", opt64.SizeOfHeapCommit);
				#else
				printf(" Size of stack to reserve:\t%#llx\n", opt64.SizeOfStackReserve);
				printf(" Size of stack to commit:\t%#llx\n", opt64.SizeOfStackCommit);
				printf(" Size of heap space to reserve:\t%#llx\n", opt64.SizeOfHeapReserve);
				printf(" Size of heap space to commit:\t%#llx\n", opt64.SizeOfHeapCommit);
				#endif
				printf(" Data-dictionary entries:\t%d\n", opt64.NumberOfRvaAndSizes);
			}
		}
		
		/* need to set number of directories outside opt.config condition */
		if (arch == PE32)
		{
			numdatadirs = opt.NumberOfRvaAndSizes;
			imagebase = opt.ImageBase;
		}
		else
		{
			numdatadirs = opt64.NumberOfRvaAndSizes;
			imagebase = opt64.ImageBase;
		}
		
		/* read data directories */
		{
			static const char *dirnames[] = {
				"Export Table",
				"Import Table",
				"Resource Table",
				"Exception Table",
				"Certificate Table",
				"Base Relocation Table",
				"Debug",
				"Architecture",
				"Global Ptr",
				"Thread Local Storage (TLS) Table",
				"Load Config Table",
				"Bound Import",
				"Import Address Table (IAT)",
				"Delay Import Descriptor",
				"CLR Runtime Header", ""
			};
			/* data directories are defined by NumberOfRvaAndSizes property (commonly 16, but not fixed).
			 * we'll create a pointer to strcuts and loop into to print existent directories */
			datadirs = malloc(sizeof(IMAGE_DATA_DIRECTORY) * numdatadirs);
			
			if (datadirs == NULL) EXIT_WITH_ERROR("memory allocation error");
			
			/* read inconditionally to further support sections reading */
			fread(datadirs, sizeof(IMAGE_DATA_DIRECTORY), numdatadirs, fp);
			
			/* only print if requested */
			if (config.opt || config.all)
			{
				printf("\nData directories:\n");
				
				for (i=0; i<numdatadirs; i++)
				{
					if ( datadirs[i].Size > 0 && (config.opt || config.all) )
					{
						if (i == 9)
							tls_addr = datadirs[i].VirtualAddress;

						printf(" Name:\t\t\t\t%s\n", dirnames[i]);
						printf(" Virtual Address:\t\t%#x\n", datadirs[i].VirtualAddress);
						printf(" Size:\t\t\t\t%#x\n\n", datadirs[i].Size);
					}
				}
			}
			free(datadirs);
		}

		/* executables have different number of sections, so we'll create
			an array of SECTION HEADER's to loop into this. */
		sec = (PIMAGE_SECTION_HEADER) malloc(sizeof(IMAGE_SECTION_HEADER)
					* coff.NumberOfSections);

		if (sec == NULL) EXIT_WITH_ERROR("memory allocation error");

		fread(sec, sizeof(IMAGE_SECTION_HEADER) * coff.NumberOfSections, 1, fp);

		if (config.sections || config.all) printf("Sections:\n");

		/* it's time to loop through our array and find the .rsrc section */
		for (i=0, sec_num=-1; i<(int)coff.NumberOfSections; i++)
		{
			if (config.sections || config.all)
			{
				/* will store binary representation + null byte */
				char binary_chars[33] = "";

				printf(" Name:\t\t\t\t%s\n", sec[i].Name);
				printf(" Virtual size:\t\t\t%#x\n", sec[i].Misc.VirtualSize);
				printf(" Virtual address:\t\t%#x\n", sec[i].VirtualAddress);
				printf(" Data size:\t\t\t%#x\n", sec[i].SizeOfRawData);
				printf(" Data offset:\t\t\t%#x\n", sec[i].PointerToRawData);
				printf(" Characteristics:\t\t%#x (%s)\n", sec[i].Characteristics,
				dec2bin(sec[i].Characteristics, binary_chars, 32));
				print_session_characteristics(sec[i].Characteristics);
				printf("\n");
			}

			if (memcmp(sec[i].Name, ".rsrc", 5) == 0) sec_num = i;
			
			/* if RVA is in this section */
			if ( tls_addr > sec[i].VirtualAddress &&
			tls_addr < (sec[i].VirtualAddress + sec[i].SizeOfRawData) )
			{
				/* get_tls_callbacks(int rva, int sec_rva, int sec_offset, int imagebase, FILE *ptr) */
				get_tls_callbacks(tls_addr, sec[i].VirtualAddress, sec[i].PointerToRawData,
									imagebase, fp);
			}
			
			/* TODO tls callback detection 
			if (memcmp(sec[i].Name, ".tls", 4) == 0) */
				

		}

	}

	/* exploring resource section */
	if (config.product || config.resources || config.all)
	{
		if (sec_num == -1) EXIT_WITH_ERROR("the file does not contain a valid resource section");

		{
			IMAGE_RESOURCE_DIRECTORY dir;
			IMAGE_RESOURCE_DIRECTORY_ENTRY ent;
			unsigned int pos, j, found=0;
			
			static const res_type r[] = 
			{
				{"RT_CURSOR", 1},
				{"RT_BITMAP", 2},
				{"RT_ICON", 3},
				{"RT_MENU", 4},
				{"RT_DIALOG", 5},
				{"RT_STRING", 6},
				{"RT_FONTDIR", 7},
				{"RT_FONT", 8},
				{"RT_ACCELERATOR", 9},
				{"RT_RCDATA", 10},
				{"RT_MESSAGETABLE", 11},
				{"RT_GROUP_CURSOR", 12},
				{"RT_GROUP_ICON", 14},
				{"RT_VERSION", 16},
				{"RT_DLGINCLUDE", 17},
				{"RT_PLUGPLAY", 19},
				{"RT_VXD", 20},
				{"RT_ANICURSOR", 21},
				{"RT_ANIICON", 22},
				{"RT_HTML", 23},
				{"RT_MANIFEST", 24},
				{"RT_DLGINIT", 240},
				{"RT_TOOLBAR", 241}
			};
			
			fseek(fp, (int) sec[sec_num].PointerToRawData, SEEK_SET);
			
			/* read RESOURCE DIR struct to get the first entry */
			fread(&dir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
			
			if (config.resources || config.all)
				puts("Resources (.rsrc section):");

			/* read *root* RESOURCE DIR ENTRY by looping through
				all entries (named or not). */
			for (i=0, pos=0; i < (int)
					(dir.NumberOfIdEntries+dir.NumberOfNamedEntries); i++)
			{
				fread(&ent, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
				
				if (config.resources || config.all)
				{
					printf(" Type:\t\t\t\t");
					
					for (j=0; j<sizeof(r)/sizeof(res_type); j++)
					{
						if (ent.u1.Name == (unsigned int) r[j].r_code)
						{
							puts(r[j].r_name);
							found = 1;
							break;
						}
					}
					if (!found)
						printf("%d\n", ent.u1.Id);

					printf(" Offset:\t\t\t%#x\n", ent.u2.s2.OffsetToDirectory);
				}
				
				if (config.product || config.all)
				{
					/* We look for version entry, specified by RT_VERSION in pe.h. */
					if (ent.u1.Name == (int)RT_VERSION)
					{
						pos = ftell(fp);
						print_version_info(ent.u2.OffsetToData, sec[sec_num].PointerToRawData, 
												sec[sec_num].VirtualAddress, pos, fp);
					}
					if (!config.product) printf("\n");
				}
			}
		}
	}
	free(sec);
}

int main(int argc, char *argv[])
{
	FILE *fp;

	/* Call parse_options to fill global
	 * config struct defined in parser.c */
	parse_options(argc, argv);
	
	/* Try to get file pointer passed as argument.
	 * This function will exit program if no file
	 * is found or is not readable */
	fp = getfile(argc, argv);

	/* We can trust fp at this point 
	 * becaue getfile() function will
	 * terminate program if fp is null */
	 
	getdata(fp);

	fclose(fp);

	return EXIT_SUCCESS;
}
