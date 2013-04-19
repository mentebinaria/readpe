/*
	pev - the PE file analyzer toolkit

	readpe.c - show PE file headers

	Copyright (C) 2012 - 2013 pev authors

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

static void usage(void)
{
	printf("Usage: %s OPTIONS FILE\n"
		"Show PE file headers\n"
		"\nExample: %s --header optional winzip.exe\n"
		"\nOptions:\n"
		" -A, --all                              full output (default)\n"
		" -H, --all-headers                      print all PE headers\n"
		" -S, --all-sections                     print all PE sections headers\n"
		" -f, --format <text|csv|xml|html>       change output format (default: text)\n"
		" -d, --dirs                             show data directories\n"
		" -h, --header <dos|coff|optional>       show sepecific header\n"
		" -i, --imports                          show imported functions\n"
		" -e, --exports                          show exported functions\n"
		" -v, --version                          show version and exit\n"
		" --help                                 show this help and exit\n",
		PROGRAM, PROGRAM);
}

static void parse_headers(const char *optarg)
{
	if (strcmp(optarg, "dos"))
		config.dos = true;
	else if (strcmp(optarg, "coff") == 0)
		config.coff = true;
	else if (strcmp(optarg, "optional") == 0)
		config.opt = true;
	else
		EXIT_ERROR("invalid header option");
}

void parse_options(int argc, char *argv[])
{
	/* Parameters for getopt_long() function */
	static const char short_options[] = "AHSh:dief:v";

	static const struct option long_options[] = {
		{ "help",             no_argument,       NULL,  1  },
		{ "all",              no_argument,       NULL, 'A' },
		{ "all-headers",      no_argument,       NULL, 'H' },
		{ "all-sections",     no_argument,       NULL, 'S' },
		{ "header",           required_argument, NULL, 'h' },
		{ "imports",          no_argument,       NULL, 'i' },
		{ "exports",          no_argument,       NULL, 'e' },
		{ "dirs",             no_argument,       NULL, 'd' },
		{ "format",           required_argument, NULL, 'f' },
		{ "version",          no_argument,       NULL, 'v' },
		{  NULL,              0,                 NULL,  0  }
	};

	// setting all fields to false
	memset(&config, false, sizeof(config));

	config.all = true;

	int c;
	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1: // --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'A':
				config.all = true;
				break;
			case 'H':
				config.all = false;
				config.all_headers = true;
				break;
			case 'd':
				config.all = false;
				config.dirs = true;
				break;
			case 'S':
				config.all = false;
				config.all_sections = true;
				break;
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
				break;
			case 'h':
				config.all = false;
				parse_headers(optarg);
				break;
			case 'i':
				config.all = false;
				config.imports = true;
				break;
			case 'e':
				config.all = false;
				config.exports = true;
				break;
			case 'f':
				parse_format(optarg);
				break;
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}
}

static void print_sections(pe_ctx_t *ctx)
{
	static const char * const flags[] = {
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
		"is writable"
	};

	// valid flags only for executables referenced in pecoffv8
	static const unsigned int valid_flags[]  = {
		0x20, 0x40, 0x80, 0x8000, 0x1000000, 0x2000000, 0x4000000,
		0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000
	};
	static const size_t flags_count = sizeof(valid_flags) / sizeof(unsigned int);

	output("Sections", NULL);

	const uint32_t num_sections = pe_sections_count(ctx);
	if (num_sections == 0 || num_sections > MAX_SECTIONS)
		return;

	IMAGE_SECTION_HEADER **sections = pe_sections(ctx);
	if (sections == NULL)
		return;

	char s[MAX_MSG];

	for (uint32_t i=0; i < num_sections; i++)
	{
		snprintf(s, MAX_MSG, "%s", sections[i]->Name);
		output("Name", s);

		snprintf(s, MAX_MSG, "%#x", sections[i]->VirtualAddress);
		output("Virtual Address", s);

		snprintf(s, MAX_MSG, "%#x", sections[i]->Misc.PhysicalAddress);
		output("Physical Address", s);

		snprintf(s, MAX_MSG, "%#x (%d bytes)", sections[i]->SizeOfRawData,
			sections[i]->SizeOfRawData);
		output("Size", s);

		snprintf(s, MAX_MSG, "%#x", sections[i]->PointerToRawData);
		output("Pointer To Data", s);

		snprintf(s, MAX_MSG, "%d", sections[i]->NumberOfRelocations);
		output("Relocations", s);

		snprintf(s, MAX_MSG, "%#x", sections[i]->Characteristics);
		output("Characteristics", s);

		for (size_t j=0; j < flags_count; j++) {
			if (sections[i]->Characteristics & valid_flags[j]) {
				snprintf(s, MAX_MSG, "%s", flags[j]);
				output(NULL, s);
			}
		}
	}
}

static void print_directories(pe_ctx_t *ctx)
{
	static const char * const directory_names[] = {
		"Export Table", // 0
		"Import Table",
		"Resource Table",
		"Exception Table",
		"Certificate Table",
		"Base Relocation Table",
		"Debug",
		"Architecture",
		"Global Ptr",
		"Thread Local Storage (TLS)", // 9
		"Load Config Table",
		"Bound Import",
		"Import Address Table (IAT)",
		"Delay Import Descriptor",
		"CLR Runtime Header", "" // 14
	};

	output("Data directories", NULL);

	const uint32_t num_directories = pe_directories_count(ctx);
	if (num_directories == 0 || num_directories > MAX_DIRECTORIES)
		return;

	IMAGE_DATA_DIRECTORY **directories = pe_directories(ctx);
	if (directories == NULL)
		return;

	char s[MAX_MSG];

	for (uint32_t i=0; i < num_directories && i < 16; i++) {
		if (directories[i]->Size) {
			snprintf(s, MAX_MSG, "%#x (%d bytes)",
					directories[i]->VirtualAddress,
					directories[i]->Size);
			output((char *)directory_names[i], s);
		}
	}
}

static void print_optional_header(IMAGE_OPTIONAL_HEADER *header)
{
	static const char * const subs_desc[] = {
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

	if (!header)
		return;

	output("Optional/Image header", NULL);

	char s[MAX_MSG];

	if (header->_32) {
		snprintf(s, MAX_MSG, "%#x (%s)", header->_32->Magic, "PE32");
		output("Magic number", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MajorLinkerVersion);
		output("Linker major version", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MinorLinkerVersion);
		output("Linker minor version", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfCode);
		output("Size of .text section", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfInitializedData);
		output("Size of .data section", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfUninitializedData);
		output("Size of .bss section", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->AddressOfEntryPoint);
		output("Entrypoint", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->BaseOfCode);
		output("Address of .text section", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->BaseOfData);
		output("Address of .data section", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->ImageBase);
		output("ImageBase", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SectionAlignment);
		output("Alignment of sections", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->FileAlignment);
		output("Alignment factor", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MajorOperatingSystemVersion);
		output("Major version of required OS", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MinorOperatingSystemVersion);
		output("Minor version of required OS", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MajorImageVersion);
		output("Major version of image", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MinorImageVersion);
		output("Minor version of image", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MajorSubsystemVersion);
		output("Major version of subsystem", s);

		snprintf(s, MAX_MSG, "%d", header->_32->MinorSubsystemVersion);
		output("Minor version of subsystem", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfImage);
		output("Size of image", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfHeaders);
		output("Size of headers", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->CheckSum);
		output("Checksum", s);

		uint16_t subsystem = header->_32->Subsystem;
		snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem <= 10 ? subs_desc[subsystem] : "Unknown");
		output("Subsystem required", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->DllCharacteristics);
		output("DLL characteristics", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfStackReserve);
		output("Size of stack to reserve", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfStackCommit);
		output("Size of stack to commit", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfHeapReserve);
		output("Size of heap space to reserve", s);

		snprintf(s, MAX_MSG, "%#x", header->_32->SizeOfHeapCommit);
		output("Size of heap space to commit", s);
	} else if (header->_64) {
		snprintf(s, MAX_MSG, "%#x (%s)", header->_64->Magic, "PE32+");
		output("Magic number", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MajorLinkerVersion);
		output("Linker major version", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MinorLinkerVersion);
		output("Linker minor version", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->SizeOfCode);
		output("Size of .text section", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->SizeOfInitializedData);
		output("Size of .data section", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->SizeOfUninitializedData);
		output("Size of .bss section", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->AddressOfEntryPoint);
		output("Entrypoint", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->BaseOfCode);
		output("Address of .text section", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, header->_64->ImageBase);
		output("ImageBase", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->SectionAlignment);
		output("Alignment of sections", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->FileAlignment);
		output("Alignment factor", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MajorOperatingSystemVersion);
		output("Major version of required OS", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MinorOperatingSystemVersion);
		output("Minor version of required OS", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MajorImageVersion);
		output("Major version of image", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MinorImageVersion);
		output("Minor version of image", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MajorSubsystemVersion);
		output("Major version of subsystem", s);

		snprintf(s, MAX_MSG, "%d", header->_64->MinorSubsystemVersion);
		output("Minor version of subsystem", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->SizeOfImage);
		output("Size of image", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->SizeOfHeaders);
		output("Size of headers", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->CheckSum);
		output("Checksum", s);

		uint16_t subsystem = header->_64->Subsystem;
		snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem <= 10 ? subs_desc[subsystem] : "Unknown");
		output("Subsystem required", s);

		snprintf(s, MAX_MSG, "%#x", header->_64->DllCharacteristics);
		output("DLL characteristics", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, header->_64->SizeOfStackReserve);
		output("Size of stack to reserve", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, header->_64->SizeOfStackCommit);
		output("Size of stack to commit", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, header->_64->SizeOfHeapReserve);
		output("Size of heap space to reserve", s);

		snprintf(s, MAX_MSG, "%#"PRIx64, header->_64->SizeOfHeapCommit);
		output("Size of heap space to commit", s);
	}
}

static void print_coff_header(IMAGE_COFF_HEADER *header)
{
	static const char * const flags[] = {
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

	static const MACHINE_ENTRY arch[] = {
		{ "Any machine type", 0x0 },
		{ "Matsushita AM33", 0x1d3 },
		{ "x86-64 (64-bits)", 0x8664 },
		{ "ARM little endian", 0x1c0 },
		{ "ARMv7 (or higher) Thumb mode only", 0x1c4 },
		{ "EFI byte code", 0xebc },
		{ "Intel 386 and compatible (32-bits)", 0x14c },
		{ "Intel Itanium", 0x200 },
		{ "Mitsubishi M32R little endian", 0x9041 },
		{ "MIPS16", 0x266 },
		{ "MIPS with FPU", 0x366 },
		{ "MIPS16 with FPU", 0x466 },
		{ "Power PC little endian", 0x1f0 },
		{ "Power PC with floating point support", 0x1f1 },
		{ "MIPS little endian", 0x166 },
		{ "Hitachi SH3", 0x1a2 },
		{ "Hitachi SH3 DSP", 0x1a3 },
		{ "Hitachi SH4", 0x1a6 },
		{ "Hitachi SH5",  0x1a8 },
		{ "ARM or Thumb (\"interworking\")", 0x1c2 },
		{ "MIPS little-endian WCE v2", 0x169 }
	};
	static const size_t archs_count = sizeof(arch) / sizeof(MACHINE_ENTRY);

	output("COFF/File header", NULL);

	const char *machine = "Unknown machine type";
	for (size_t i=0; i < archs_count; i++) {
		if (header->Machine == arch[i].code)
			machine = arch[i].name;
	}

	char s[MAX_MSG];

	snprintf(s, MAX_MSG, "%#x %s", header->Machine, machine);
	output("Machine", s);

	snprintf(s, MAX_MSG, "%d", header->NumberOfSections);
	output("Number of sections", s);

	char timestr[40];
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S UTC",
		gmtime((time_t *) &header->TimeDateStamp));
	snprintf(s, MAX_MSG, "%d (%s)", header->TimeDateStamp, timestr);
	output("Date/time stamp", s);

	snprintf(s, MAX_MSG, "%#x", header->PointerToSymbolTable);
	output("Symbol Table offset", s);

	snprintf(s, MAX_MSG, "%d", header->NumberOfSymbols);
	output("Number of symbols", s);

	snprintf(s, MAX_MSG, "%#x", header->SizeOfOptionalHeader);
	output("Size of optional header", s);

	snprintf(s, MAX_MSG, "%#x", header->Characteristics);
	output("Characteristics", s);

	for (uint16_t i=1, j=0; i<0x8000; i <<= 1, j++) {
		if (header->Characteristics & i)
			output(NULL, flags[j]);
	}
}

static void print_dos_header(IMAGE_DOS_HEADER *header)
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

static void print_imported_functions(pe_ctx_t *ctx, long offset)
{
#if 0
	uint32_t fptr = 0; // pointer to functions
	long aux2, aux = ftell(pe->handle);
	uint16_t hint = 0; // function number
	char c;
	char fname[MAX_FUNCTION_NAME];
	char hintstr[16];
	unsigned int i;

	if (fseek(pe->handle, offset, SEEK_SET))
		return;

	memset(&fname, 0, sizeof(fname));
	memset(&hintstr, 0, sizeof(hintstr));

	while (1)
	{
		if (!fread(&fptr, (pe->architecture == PE64)
				? sizeof(uint64_t)
				: sizeof(uint32_t), 1, pe->handle))
			return;

		if (!fptr)
			break;

		// function without name (test msb)
		if (fptr & ((pe->architecture == PE64) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32))
			snprintf(hintstr, 15, "%"PRIu64, fptr & 0x0fffffff);
		else
		{
			// save file pointer in functions array
			aux2 = ftell(pe->handle);

			if (fseek(pe->handle, rva2ofs(pe, fptr), SEEK_SET))
				return;

			// follow function pointer
			if (!fread(&hint, sizeof(hint), 1, pe->handle))
				return;

			for (i=0; i<MAX_FUNCTION_NAME; i++)
			{
				if (!fread(&c, sizeof(c), 1, pe->handle))
					return;

				if (!isprint((int)c)) // 0 and non-printable
					break;

				fname[i] = c;
			}
			snprintf(hintstr, 15, "%d", hint);

			// restore file pointer to functions array
			if (fseek(pe->handle, aux2, SEEK_SET))
				return;
		}

		// print things
		output(hintstr, fname);
		memset(&fname, 0, sizeof(fname));
		memset(&hintstr, 0, sizeof(hintstr));
	}

	fseek(pe->handle, aux, SEEK_SET);
#endif
}

static void print_exports(pe_ctx_t *ctx)
{
#if 0
	uint64_t va;
	IMAGE_EXPORT_DIRECTORY exp;
	uint32_t rva, aux, faddr = 0;

	IMAGE_DATA_DIRECTORY *directory = pe_get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (!directory)
		EXIT_ERROR("export directory not found")

	va = directory->VirtualAddress;
	if (!va)
	{
		fprintf(stderr, "export directory not found\n");
		return;
	}

	if (fseek(pe->handle, rva2ofs(pe, va), SEEK_SET))
		EXIT_ERROR("unable to seek until export directory");

	if (!fread(&exp, sizeof(exp), 1, pe->handle))
		EXIT_ERROR("unable to read export directory");

	if (fseek(pe->handle, rva2ofs(pe, exp.AddressOfNames), SEEK_SET))
		EXIT_ERROR("unable to seek");

	if (!fread(&rva, sizeof(rva), 1, pe->handle))
		EXIT_ERROR("unable to read");

	if (fseek(pe->handle, rva2ofs(pe, rva), SEEK_SET))
		EXIT_ERROR("unable to seek");

	output("Exported functions", NULL);
	for (unsigned i=0; i<exp.NumberOfNames; i++)
	{
		char c=1, addr[30], fun[300];

		aux = ftell(pe->handle);
		fseek(pe->handle, exp.AddressOfFunctions + sizeof(uint32_t) * i, SEEK_SET);
		fread(&faddr, sizeof(faddr), 1, pe->handle);
		fseek(pe->handle, aux, SEEK_SET);
		memset(&fun, 0, sizeof(fun));
		memset(&addr, 0, sizeof(addr));
		snprintf(addr, 30, "%#x", faddr);

		for (unsigned j=0; c; j++)
		{
			fread(&c, sizeof(c), 1, pe->handle);
			fun[j] = c;
		}
		output(addr, fun);
	}
#endif
}

static void print_imports(pe_ctx_t *ctx)
{
#if 0
	uint64_t va; // store temporary addresses
	long aux;
	IMAGE_IMPORT_DESCRIPTOR id;
	char c = 0;
	char dllname[MAX_DLL_NAME];
	unsigned int i;

	IMAGE_DATA_DIRECTORY *directory = pe_get_data_directory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (!directory)
		EXIT_ERROR("import directory not found")

	va = directory->VirtualAddress;
	if (!va)
		EXIT_ERROR("import directory not found");

	if (fseek(pe->handle, rva2ofs(pe, va), SEEK_SET))
		EXIT_ERROR("error seeking file");

	memset(&id, 0, sizeof(id));
	memset(&dllname, 0, sizeof(dllname));

	output("Imported functions", NULL);
	while (1)
	{
		if (!fread(&id, sizeof(id), 1, pe->handle))
			return;

		if (!id.u1.OriginalFirstThunk)
			break;

		aux = ftell(pe->handle);
		va = rva2ofs(pe, id.Name);

		if (!va)
			return;

		// shortcut to read DLL name
		if (fseek(pe->handle, va, SEEK_SET))
			return;

		// print dll name
		for (i=0; i < MAX_DLL_NAME; i++)
		{
			fread(&c, sizeof(c), 1, pe->handle);

			if (!c)
				break;

			dllname[i] = c;
		}

		output(dllname, NULL);
		memset(&dllname, 0, sizeof(dllname));

		if (fseek(pe->handle, aux, SEEK_SET)) // restore file pointer
			return;

		// search for dll imported functions
		va = rva2ofs(pe, id.u1.OriginalFirstThunk);

		if (!va)
			return;

		print_imported_functions(pe, va);
	}
#endif
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		exit(1);
	}

	parse_options(argc, argv); // Opcoes

	pe_ctx_t ctx;

	pe_err_e err = pe_load(&ctx, argv[argc-1]);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	err = pe_parse(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	if (!pe_is_pe(&ctx))
		EXIT_ERROR("not a valid PE file");

	// dos header
	if (config.dos || config.all_headers || config.all) {
		if (ctx.pe.dos_hdr)
			print_dos_header(ctx.pe.dos_hdr);
		else { EXIT_ERROR("unable to read DOS header"); }
	}

	// coff/file header
	if (config.coff || config.all_headers || config.all) {
		if (ctx.pe.coff_hdr)
			print_coff_header(ctx.pe.coff_hdr);
		else { EXIT_ERROR("unable to read COFF file header"); }
	}

	// optional header
	if (config.opt || config.all_headers || config.all) {
		if (ctx.pe.optional_hdr)
			print_optional_header(ctx.pe.optional_hdr);
		else { EXIT_ERROR("unable to read Optional (Image) file header"); }
	}

	// directories
	if (config.dirs || config.all) {
		if (ctx.pe.directories != NULL)
			print_directories(&ctx);
		else { EXIT_ERROR("unable to read the Directories entry from Optional header"); }
	}

	// imports
	if (config.imports || config.all) {
		if (ctx.pe.directories != NULL)
			print_imports(&ctx);
		else { EXIT_ERROR("unable to read the Directories entry from Optional header"); }
	}

	// exports
	if (config.exports || config.all) {
		if (ctx.pe.directories != NULL)
			print_exports(&ctx);
		else { EXIT_ERROR("unable to read directories from optional header"); }
	}

	// sections
	if (config.all_sections || config.all) {
		if (ctx.pe.sections != NULL)
			print_sections(&ctx);
		else { EXIT_ERROR("unable to read sections"); }
	}

	// free
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
