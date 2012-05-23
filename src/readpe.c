/*
	pev - the PE file analyzer toolkit
	
	readpe.c - show PE file headers

	Copyright (C) 2012 Fernando Mercês
	Copyright (C) 2012 Gabriel Duarte

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

#include "readpe.h"

extern struct options config;
static int ind;

void usage()
{
	printf("Usage: %s OPTIONS FILE\n"
	"Show PE file headers\n"
	"\nExample: %s --header optional winzip.exe\n"
	"\nOptions:\n"
	" -A, --all                              full output (default)\n"
	" -H, --all-headers                      print all PE headers\n"
	" -S, --all-sections                     print all PE sections headers\n"
	" -h, --header <dos|coff|optional>       show sepecific header\n"
	" -d, --dirs                             show data directories\n"		
	" -f, --format <text|csv|xml|html>       change output format (default text)\n"
	" -v, --version                          show version and exit\n"
	" --help                                 show this help and exit\n",
	PROGRAM, PROGRAM);
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
		EXIT_ERROR("invalid header option");
}

void parse_options(int argc, char *argv[])
{
	int c;

	/* Parameters for getopt_long() function */
	static const char short_options[] = "AHSh:df:v";

	static const struct option long_options[] = {
		{"help",             no_argument,       NULL,  1 },
		{"all",              no_argument,       NULL, 'A'},
		{"all-headers",      no_argument,       NULL, 'H'},
		{"all-sections",     no_argument,       NULL, 'S'},
		{"header",           required_argument, NULL, 'h'},
		{"dirs",             no_argument,       NULL, 'd'},
		{"format",           required_argument, NULL, 'f'},
		{"version",          no_argument,       NULL, 'v'},
		{ NULL,              0,                 NULL,  0 }
	};

	// setting all fields to false
	memset(&config, false, sizeof(config));

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
				config.all = false;
				config.all_headers = true; break;

			case 'd':
				config.all = false;
				config.dirs = true; break;

			case 'S':
				config.all = false;
				config.all_sections = true; break;

			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);

			case 'h':
				config.all = false;
				parse_headers(optarg); break;

			case 'f':
				parse_format(optarg); break;

			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

char *dec2bin(unsigned int dec, char *bin, unsigned int bits)
{
	unsigned int i;
	
	for(i=0; i < bits; i++)
		bin[bits - i - 1] = (dec & (0x1 << i)) ? '1' : '0';

	bin[bits] = '\0';

	return bin;
}

void print_sections(PE_FILE *pe)
{
	char s[MAX_MSG];
	unsigned int i, j;

	char *flags[] = {
   "contains executable code",
   "contains initialized data",
   "contains uninitialized data",
   "contains data referenced through the GP",
   "contains extended relocations",
   "can be discarded as needed",
   "cannot be cached",
   "is not pageable",
   "can be shared in memory",
   "is executable",
   "is readable",
   "is writable" };

   // valid flags only for executables referenced in pecoffv8
   unsigned int valid_flags[] =
   { 0x20, 0x40, 0x80, 0x8000, 0x1000000, 0x2000000, 0x4000000,
     0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000 };

	output("Sections", NULL);

	if (pe->num_sections > 96)
		return;

	for (i=0; i < pe->num_sections; i++)
	{
		snprintf(s, MAX_MSG, "%s", pe->sections_ptr[i]->Name);
		output("Name", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->VirtualAddress);
		output("Virtual Address", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->Misc.PhysicalAddress);
		output("Physical Address", s);

		snprintf(s, MAX_MSG, "%#x (%d bytes)", pe->sections_ptr[i]->SizeOfRawData,
		pe->sections_ptr[i]->SizeOfRawData);
		output("Size", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->PointerToRawData);
		output("Pointer To Data", s);

		snprintf(s, MAX_MSG, "%d", pe->sections_ptr[i]->NumberOfRelocations);
		output("Relocations", s);

		snprintf(s, MAX_MSG, "%#x", pe->sections_ptr[i]->Characteristics);
		output("Characteristics", s);

		for (j=0; j < sizeof(valid_flags) / sizeof(unsigned int); j++)
		{
			if (pe->sections_ptr[i]->Characteristics & valid_flags[j])
			{
					snprintf(s, MAX_MSG, "%s", flags[j]);
					output("characteristics", s);
			}
		}
	}
}

void print_directories(PE_FILE *pe)
{
	char s[MAX_MSG];
	unsigned int i;

	static const char *directory_names[] =
	{
		"Export Table", // 0
		"Import Table",
		"Resource Table",
		"Exception Table",
		"Certificate Table",
		"Base Relocation Table",
		"Debug",
		"Architecture",
		"Global Ptr",
		"Thread Local Storage (TLS) Table", // 9
		"Load Config Table",
		"Bound Import",
		"Import Address Table (IAT)",
		"Delay Import Descriptor",
		"CLR Runtime Header", "" // 15
	};

	output("Data directories", NULL);

	if (! pe->directories_ptr)
		return;

	for (i=0; i < pe->num_directories && i < 16; i++)
	{
		if (pe->directories_ptr[i]->Size)
		{
			snprintf(s, MAX_MSG, "%#x (%d bytes)",
					pe->directories_ptr[i]->VirtualAddress,
					pe->directories_ptr[i]->Size);
			output((char *) directory_names[i], s);
		}
	}
}

void print_optional_header(PE_FILE *pe)
{
	char s[MAX_MSG];
	int subsystem;

	static const char *subs_desc[] = {
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
	"XBOX"};

	if (!pe->optional_ptr)
		return;

	output("Optional/Image header", NULL);

	if (pe->optional_ptr->_32)
	{
		snprintf(s, MAX_MSG, "%#x (%s)", pe->optional_ptr->_32->Magic, "PE32");
		output("Magic number", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorLinkerVersion);
		output("Linker major version", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorLinkerVersion);
		output("Linker minor version", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfCode);
		output("Size of .text section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfInitializedData);
		output("Size of .data section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfUninitializedData);
		output("Size of .bss section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->AddressOfEntryPoint);
		output("Entrypoint", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->BaseOfCode);
		output("Address of .text section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->BaseOfData);
		output("Address of .data section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->ImageBase);
		output("ImageBase", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SectionAlignment);
		output("Alignment of sections", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->FileAlignment);
		output("Alignment factor", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorOperatingSystemVersion);
		output("Major version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorOperatingSystemVersion);
		output("Minor version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorImageVersion);
		output("Major version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorImageVersion);
		output("Minor version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MajorSubsystemVersion);
		output("Major version of subsystem", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_32->MinorSubsystemVersion);
		output("Minor version of subsystem", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfImage);
		output("Size of image", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfHeaders);
		output("Size of headers", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->CheckSum);
		output("Checksum", s);

		subsystem = pe->optional_ptr->_32->Subsystem;
		snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem <= 10 ? subs_desc[subsystem] : "Unknown");
		output("Subsystem required", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->DllCharacteristics);
		output("DLL characteristics", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfStackReserve);
		output("Size of stack to reserve", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfStackCommit);
		output("Size of stack to commit", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfHeapReserve);
		output("Size of heap space to reserve", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_32->SizeOfHeapCommit);
		output("Size of heap space to commit", s);
	}
	else if (pe->optional_ptr->_64)
	{
		snprintf(s, MAX_MSG, "%#x (%s)", pe->optional_ptr->_64->Magic, "PE32+");
		output("Magic number", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorLinkerVersion);
		output("Linker major version", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorLinkerVersion);
		output("Linker minor version", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfCode);
		output("Size of .text section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfInitializedData);
		output("Size of .data section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfUninitializedData);
		output("Size of .bss section", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->AddressOfEntryPoint);
		output("Entrypoint", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->BaseOfCode);
		output("Address of .text section", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->ImageBase);
		output("ImageBase", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SectionAlignment);
		output("Alignment of sections", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->FileAlignment);
		output("Alignment factor", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorOperatingSystemVersion);
		output("Major version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorOperatingSystemVersion);
		output("Minor version of required OS", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorImageVersion);
		output("Major version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorImageVersion);
		output("Minor version of image", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MajorSubsystemVersion);
		output("Major version of subsystem", s);

		snprintf(s, MAX_MSG, "%d", pe->optional_ptr->_64->MinorSubsystemVersion);
		output("Minor version of subsystem", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfImage);
		output("Size of image", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->SizeOfHeaders);
		output("Size of headers", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->CheckSum);
		output("Checksum", s);

		subsystem = pe->optional_ptr->_64->Subsystem;
		snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem <= 10 ? subs_desc[subsystem] : "Unknown");
		output("Subsystem required", s);

		snprintf(s, MAX_MSG, "%#x", pe->optional_ptr->_64->DllCharacteristics);
		output("DLL characteristics", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfStackReserve);
		output("Size of stack to reserve", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfStackCommit);
		output("Size of stack to commit", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfHeapReserve);
		output("Size of heap space to reserve", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, pe->optional_ptr->_64->SizeOfHeapCommit);
		output("Size of heap space to commit", s);
	}
}

void print_coff_header(IMAGE_COFF_HEADER *header)
{
	char s[MAX_MSG];
	char time[40];
	register unsigned int i, j;
	char *machine = "Unknown machine type";

	static const char *flags[] =
	{
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

	static const MACHINE_ENTRY arch[] =
	{
		{"Any machine type", 0x0},
		{"Matsushita AM33", 0x1d3},
		{"x86-64 (64-bits)", 0x8664},
		{"ARM little endian", 0x1c0},
		{"ARMv7 (or higher) Thumb mode only", 0x1c4},
		{"EFI byte code", 0xebc},
		{"Intel 386 and compatible (32-bits)", 0x14c},
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

	output("COFF/File header", NULL);

	for(i=0; i<(sizeof(arch)/sizeof(MACHINE_ENTRY)); i++)
	{
		if(header->Machine == arch[i].code)
			machine = (char*)arch[i].name;
	}

	snprintf(s, MAX_MSG, "%#x %s", header->Machine, machine);
	output("Machine", s);

	snprintf(s, MAX_MSG, "%d", header->NumberOfSections);
	output("Number of sections", s);

	strftime(time, 40, "%a - %d %b %Y %H:%M:%S UTC", gmtime((time_t *) & header->TimeDateStamp));
	snprintf(s, MAX_MSG, "%d (%s)", header->TimeDateStamp, time);
	output("Date/time stamp", s);

	snprintf(s, MAX_MSG, "%#x", header->PointerToSymbolTable);
	output("Symbol Table offset", s);

	snprintf(s, MAX_MSG, "%d", header->NumberOfSymbols);
	output("Number of symbols", s);

	snprintf(s, MAX_MSG, "%#x", header->SizeOfOptionalHeader);
	output("Size of optional header", s);

	snprintf(s, MAX_MSG, "%#x", header->Characteristics);
	output("Characteristics", s);

	for (i=1, j=0; i<0x8000; i<<=1, j++)
	{
		if (header->Characteristics & i)
			output(NULL, (char*) flags[j]);
	}
}

void print_dos_header(IMAGE_DOS_HEADER *header)
{
	char s[MAX_MSG];

	output("DOS Header", NULL);

	snprintf(s, MAX_MSG, "%#x (MZ)", header->e_magic);
	output("Magic number", s);

	snprintf(s, MAX_MSG, "%d", header->e_cblp);
	output("Bytes in last page", s);

	snprintf(s, MAX_MSG, "%d", header->e_cp);
	output("Pages in file", s);

	snprintf(s, MAX_MSG, "%d", header->e_crlc);
	output("Relocations", s);

	snprintf(s, MAX_MSG, "%d", header->e_cparhdr);
	output("Size of header in paragraphs", s);

	snprintf(s, MAX_MSG, "%d", header->e_minalloc);
	output("Minimum extra paragraphs", s);

	snprintf(s, MAX_MSG, "%d", header->e_maxalloc);
	output("Maximum extra paragraphs", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ss);
	output("Initial (relative) SS value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_sp);
	output("Initial SP value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ip);
	output("Initial IP value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_cs);
	output("Initial (relative) CS value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_lfarlc);
	output("Address of relocation table", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ovno);
	output("Overlay number", s);

	snprintf(s, MAX_MSG, "%#x", header->e_oemid);
	output("OEM identifier", s);

	snprintf(s, MAX_MSG, "%#x", header->e_oeminfo);
	output("OEM information", s);

	snprintf(s, MAX_MSG, "%#x", header->e_lfanew);
	output("PE header offset", s);
}

int main(int argc, char *argv[])
{
	PE_FILE pe;
	FILE *fp = NULL;
	
	if (argc < 2)
	{
		usage();
		exit(1);
	}
	
	parse_options(argc, argv); // opcoes

	if ((fp = fopen(argv[argc-1], "rb")) == NULL)
		EXIT_ERROR("file not found or unreadable");

	pe_init(&pe, fp); // inicializa o struct pe

	if (!ispe(&pe))
		EXIT_ERROR("not a valid PE file");

	// dos header
	start_output();
	
	
	if (config.dos || config.all_headers || config.all)
	{
		IMAGE_DOS_HEADER dos;

		if (pe_get_dos(&pe, &dos))
			print_dos_header(&dos);
		else { EXIT_ERROR("unable to read DOS header"); }
	}

	// coff/file header
	if (config.coff || config.all_headers || config.all)
	{
		IMAGE_COFF_HEADER coff;

		if (pe_get_coff(&pe, &coff))
			print_coff_header(&coff);
		else { EXIT_ERROR("unable to read COFF file header"); }
	}

	// optional header
	if (config.opt || config.all_headers || config.all)
	{
		if (pe_get_optional(&pe))
			print_optional_header(&pe);
		else { EXIT_ERROR("unable to read Optional (Image) file header"); }
	}

	// sections
	if (config.all_sections || config.all)
	{
		if (pe_get_sections(&pe))
			print_sections(&pe);
		else { EXIT_ERROR("unable to read Section header"); }
	}
	
	// directories
	if (config.dirs || config.all)
	{
		if (pe_get_directories(&pe))
			print_directories(&pe);
		else { EXIT_ERROR("unable to read the Directories entry from Optional header"); }
	}
	
	end_output();
	// free
	pe_deinit(&pe);
	
	return 0;
}
