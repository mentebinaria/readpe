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
	static const size_t max_flags = LIBPE_SIZEOF_ARRAY(valid_flags);

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

		for (size_t j=0; j < max_flags; j++) {
			if (sections[i]->Characteristics & valid_flags[j]) {
				snprintf(s, MAX_MSG, "%s", flags[j]);
				output(NULL, s);
			}
		}
	}
}

static void print_directories(pe_ctx_t *ctx)
{
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
	typedef struct {
		ImageDirectoryEntry entry;
		const char * const name;
	} ImageDirectoryEntryName;
	static const ImageDirectoryEntryName directoryEntryNames[] = {
		{ IMAGE_DIRECTORY_ENTRY_EXPORT,			"Export Table"				}, // "Export directory",
		{ IMAGE_DIRECTORY_ENTRY_IMPORT,			"Import Table"				}, // "Import directory",
		{ IMAGE_DIRECTORY_ENTRY_RESOURCE,		"Resource Table"			}, // "Resource directory",
		{ IMAGE_DIRECTORY_ENTRY_EXCEPTION,		"Exception Table"			}, // "Exception directory",
		{ IMAGE_DIRECTORY_ENTRY_SECURITY,		"Certificate Table"			}, // "Security directory",
		{ IMAGE_DIRECTORY_ENTRY_BASERELOC,		"Base Relocation Table"		}, // "Base relocation table",
		{ IMAGE_DIRECTORY_ENTRY_DEBUG,			"Debug"						}, // "Debug directory",
		{ IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,	"Architecture"				}, // "Architecture-specific data",
		{ IMAGE_DIRECTORY_ENTRY_GLOBALPTR,		"Global Ptr"				}, // "Global pointer",
		{ IMAGE_DIRECTORY_ENTRY_TLS,			"Thread Local Storage (TLS)"}, // "Thread local storage (TLS) directory",
		{ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,	"Load Config Table"			}, // "Load configuration directory",
		{ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,	"Bound Import"				}, // "Bound import directory",
		{ IMAGE_DIRECTORY_ENTRY_IAT,			"Import Address Table (IAT)"}, // "Import address table (IAT)",
		{ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,	"Delay Import Descriptor"	}, // "Delay import table",
		{ IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,	"CLR Runtime Header"		}, // "COM descriptor table"
		{ IMAGE_DIRECTORY_RESERVED,				""							}  // "Reserved"
	};
	//static const size_t max_directory_entry = LIBPE_SIZEOF_ARRAY(names);
#endif
	output("Data directories", NULL);

	const uint32_t num_directories = pe_directories_count(ctx);
	if (num_directories == 0 || num_directories > MAX_DIRECTORIES)
		return;

	IMAGE_DATA_DIRECTORY **directories = pe_directories(ctx);
	if (directories == NULL)
		return;

	char s[MAX_MSG];

	for (uint32_t i=0; i < num_directories; i++) {
		if (directories[i]->Size) {
			snprintf(s, MAX_MSG, "%#x (%d bytes)",
					directories[i]->VirtualAddress,
					directories[i]->Size);
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			output(directoryEntryNames[i].name, s);
#else
			output(pe_directory_name(i), s);
#endif
		}
	}
}

static void print_optional_header(IMAGE_OPTIONAL_HEADER *header)
{
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
	typedef struct {
		WindowsSubsystem subsystem;
		const char * const name;
	} WindowsSubsystemName;
	static const WindowsSubsystemName subsystemNames[] = {
		{ IMAGE_SUBSYSTEM_UNKNOWN,					"Unknown subsystem"		},
		{ IMAGE_SUBSYSTEM_NATIVE,					"System native"			},
		{ IMAGE_SUBSYSTEM_WINDOWS_GUI,				"Windows GUI"			},
		{ IMAGE_SUBSYSTEM_WINDOWS_CUI,				"Windows CLI"			},
		{ IMAGE_SUBSYSTEM_POSIX_CUI,				"Posix CLI"				},
		{ IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,			"Windows CE GUI"		},
		{ IMAGE_SUBSYSTEM_EFI_APPLICATION, 			"EFI application"		},
		{ IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,	"EFI driver with boot"	},
		{ IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,		"EFI run-time driver"	},
		{ IMAGE_SUBSYSTEM_EFI_ROM, 					"EFI ROM"				},
		{ IMAGE_SUBSYSTEM_XBOX,			 			"XBOX"					},
	};
	static const size_t max_subsystem = LIBPE_SIZEOF_ARRAY(subsystemNames);
#endif

	if (!header)
		return;

	output("Optional/Image header", NULL);

	char s[MAX_MSG];

	switch (header->type)
	{
		case MAGIC_PE32:
		{
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
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			const char *subsystem_name = "Unknown";
			for (size_t i=0; i < max_subsystem; i++) {
				if (subsystem == subsystemNames[i].subsystem)
					subsystem_name = subsystemNames[i].name;
			}
#else
			const char *subsystem_name = pe_windows_subsystem_name(subsystem);
			if (subsystem_name == NULL)
				subsystem_name = "Unknown";
#endif
			snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem_name);
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
			break;
		}
		case MAGIC_PE64:
		{
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
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			const char *subsystem_name = "Unknown";
			for (size_t i=0; i < max_subsystem; i++) {
				if (subsystem == subsystemNames[i].subsystem)
					subsystem_name = subsystemNames[i].name;
			}
#else
			const char *subsystem_name = pe_windows_subsystem_name(subsystem);
			if (subsystem_name == NULL)
				subsystem_name = "Unknown";
#endif
			snprintf(s, MAX_MSG, "%#x (%s)", subsystem, subsystem_name);
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
			break;
		}
	}
}

static void print_coff_header(IMAGE_COFF_HEADER *header)
{
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
	typedef struct {
		ImageCharacteristics characteristic;
		const char * const name;
	} ImageCharacteristicsName;
	static const ImageCharacteristicsName characteristicsTable[] = {
		{ IMAGE_FILE_RELOCS_STRIPPED,			"base relocations stripped"					},
		{ IMAGE_FILE_EXECUTABLE_IMAGE,			"executable image"							},
		{ IMAGE_FILE_LINE_NUMS_STRIPPED,		"line numbers removed (deprecated)"			},
		{ IMAGE_FILE_LOCAL_SYMS_STRIPPED,		"local symbols removed (deprecated)"		},
		{ IMAGE_FILE_AGGRESSIVE_WS_TRIM,		"aggressively trim (deprecated for Windows 2000 and later)" },
		{ IMAGE_FILE_LARGE_ADDRESS_AWARE,		"can handle more than 2 GB addresses"		},
		{ IMAGE_FILE_RESERVED,					""											},
		{ IMAGE_FILE_BYTES_REVERSED_LO,			"little-endian (deprecated)"				},
		{ IMAGE_FILE_32BIT_MACHINE,				"32-bit machine"							},
		{ IMAGE_FILE_DEBUG_STRIPPED,			"debugging information removed"				},
		{ IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,	"copy to swap if it's on removable media"	},
		{ IMAGE_FILE_NET_RUN_FROM_SWAP,			"copy to swap if it's on network media"		},
		{ IMAGE_FILE_SYSTEM,					"system file"								},
		{ IMAGE_FILE_DLL,						"DLL image"									},
		{ IMAGE_FILE_UP_SYSTEM_ONLY,			"uniprocessor machine"						},
		{ IMAGE_FILE_BYTES_REVERSED_HI,			"big-endian (deprecated)"					}
	};

	typedef struct {
		MachineType type;
		const char * const name;
	} MachineTypeName;
	static const MachineTypeName machineTypeTable[] = {
		{ IMAGE_FILE_MACHINE_UNKNOWN,	"Any machine type"					},
		{ IMAGE_FILE_MACHINE_AM33,		"Matsushita AM33"					},
		{ IMAGE_FILE_MACHINE_AMD64,		"x86-64 (64-bits)"					},
		{ IMAGE_FILE_MACHINE_ARM,		"ARM little endian"					},
		{ IMAGE_FILE_MACHINE_ARMV7,		"ARMv7 (or higher) Thumb mode only" },
		{ IMAGE_FILE_MACHINE_CEE,		"clr pure MSIL (object only)"		},
		{ IMAGE_FILE_MACHINE_EBC,		"EFI byte code"						},
		{ IMAGE_FILE_MACHINE_I386,		"Intel 386 and compatible (32-bits)"},
		{ IMAGE_FILE_MACHINE_IA64,		"Intel Itanium"						},
		{ IMAGE_FILE_MACHINE_M32R,		"Mitsubishi M32R little endian"		},
		{ IMAGE_FILE_MACHINE_MIPS16,	"MIPS16"							},
		{ IMAGE_FILE_MACHINE_MIPSFPU,	"MIPS with FPU"						},
		{ IMAGE_FILE_MACHINE_MIPSFPU16,	"MIPS16 with FPU"					},
		{ IMAGE_FILE_MACHINE_POWERPC,	"Power PC little endian"			},
		{ IMAGE_FILE_MACHINE_POWERPCFP,	"Power PC with floating point support" },
		{ IMAGE_FILE_MACHINE_R4000,		"MIPS little endian"				},
		{ IMAGE_FILE_MACHINE_SH3,		"Hitachi SH3"						},
		{ IMAGE_FILE_MACHINE_SH3DSP,	"Hitachi SH3 DSP"					},
		{ IMAGE_FILE_MACHINE_SH4,		"Hitachi SH4"						},
		{ IMAGE_FILE_MACHINE_SH5,		"Hitachi SH5"						},
		{ IMAGE_FILE_MACHINE_THUMB,		"ARM or Thumb (\"interworking\")"	},
		{ IMAGE_FILE_MACHINE_WCEMIPSV2,	"MIPS little-endian WCE v2"			}
	};
	static const size_t max_machine_type = LIBPE_SIZEOF_ARRAY(machineTypeTable);
#endif

	output("COFF/File header", NULL);

#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
	const char *machine = "Unknown machine type";
	for (size_t i=0; i < max_machine_type; i++) {
		if (header->Machine == machineTypeTable[i].type)
			machine = machineTypeTable[i].name;
	}
#else
	const char *machine = pe_machine_type_name(header->Machine);
	if (machine == NULL)
		machine = "Unknown machine type";
#endif

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
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			output(NULL, characteristicsTable[j].name);
#else
			output(NULL, pe_image_characteristic_name(j));
#endif
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
	IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dir == NULL)
		EXIT_ERROR("export directory not found")

	uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "export directory not found\n");
		return;
	}

	uint64_t ofs;

	ofs = pe_rva2ofs(ctx, va);
	IMAGE_EXPORT_DIRECTORY *exp = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (LIBPE_IS_PAST_THE_END(ctx, exp, IMAGE_EXPORT_DIRECTORY)) {
		// TODO: Should we report something?
		printf("DEBUGME\n");
		return;
	}

	ofs = pe_rva2ofs(ctx, exp->AddressOfNames);
	uint32_t *rva_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (LIBPE_IS_PAST_THE_END(ctx, rva_ptr, uint32_t)) {
		// TODO: Should we report something?
		return;
	}
	uint32_t rva = *rva_ptr;

	ofs = pe_rva2ofs(ctx, rva);

	output("Exported functions", NULL);
	for (uint32_t i=0; i < exp->NumberOfNames; i++) {
		uint64_t aux = ofs; // Store current ofs

		ofs = exp->AddressOfFunctions + sizeof(uint32_t) * i;
		uint32_t *faddr_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (LIBPE_IS_PAST_THE_END(ctx, faddr_ptr, uint32_t)) {
			// TODO: Should we report something?
			break;
		}
		uint32_t faddr = *faddr_ptr;

		ofs = aux; // Restore previous ofs

		char addr[30];
		snprintf(addr, 30, "%#x", faddr);

		const char *fname = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		// TODO: Validate if it's ok to read fname+N
		// TODO: How can we guarantee we're reading a string from a
		// valid range of ctx->map?
		char fun[300];
		strncpy(fun, fname, sizeof(fun)-1);

		output(addr, fun);
	}
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
		IMAGE_DOS_HEADER *header_ptr = pe_dos(&ctx);
		if (header_ptr)
			print_dos_header(header_ptr);
		else { EXIT_ERROR("unable to read DOS header"); }
	}

	// coff/file header
	if (config.coff || config.all_headers || config.all) {
		IMAGE_COFF_HEADER *header_ptr = pe_coff(&ctx);
		if (header_ptr)
			print_coff_header(header_ptr);
		else { EXIT_ERROR("unable to read COFF file header"); }
	}

	// optional header
	if (config.opt || config.all_headers || config.all) {
		IMAGE_OPTIONAL_HEADER *header_ptr = pe_optional(&ctx);
		if (header_ptr)
			print_optional_header(header_ptr);
		else { EXIT_ERROR("unable to read Optional (Image) file header"); }
	}

	// directories
	if (config.dirs || config.all) {
		if (pe_directories(&ctx) != NULL)
			print_directories(&ctx);
		else { EXIT_ERROR("unable to read the Directories entry from Optional header"); }
	}

	// imports
	if (config.imports || config.all) {
		if (pe_directories(&ctx) != NULL)
			print_imports(&ctx);
		else { EXIT_ERROR("unable to read the Directories entry from Optional header"); }
	}

	// exports
	if (config.exports || config.all) {
		if (pe_directories(&ctx) != NULL)
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
