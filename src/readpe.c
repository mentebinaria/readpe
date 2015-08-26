/*
	pev - the PE file analyzer toolkit

	readpe.c - show PE file headers

	Copyright (C) 2013 - 2015 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"
#include <time.h>
#include <ctype.h>
#include "plugins.h"

#define PROGRAM "readpe"
#define MAX_DLL_NAME 256
#define MAX_FUNCTION_NAME 512

typedef struct {
	bool all;
	bool dos;
	bool coff;
	bool opt;
	bool dirs;
	bool imports;
	bool exports;
	bool all_headers;
	bool all_sections;
} options_t;

static void usage(void)
{
	static char formats[255];
	output_available_formats(formats, sizeof(formats), '|');
	printf("Usage: %s OPTIONS FILE\n"
		"Show PE file headers\n"
		"\nExample: %s --header optional winzip.exe\n"
		"\nOptions:\n"
		" -A, --all                              full output (default)\n"
		" -H, --all-headers                      print all PE headers\n"
		" -S, --all-sections                     print all PE sections headers\n"
		" -f, --format <%s>  change output format (default: text)\n"
		" -d, --dirs                             show data directories\n"
		" -h, --header <dos|coff|optional>       show specific header\n"
		" -i, --imports                          show imported functions\n"
		" -e, --exports                          show exported functions\n"
		" -v, --version                          show version and exit\n"
		" --help                                 show this help and exit\n",
		PROGRAM, PROGRAM, formats);
}

static void parse_headers(options_t *options, const char *optarg)
{
	if (!strcmp(optarg, "dos"))
		options->dos = true;
	else if (!strcmp(optarg, "coff"))
		options->coff = true;
	else if (!strcmp(optarg, "optional"))
		options->opt = true;
	else
		EXIT_ERROR("invalid header option");
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

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

	options->all = true;

	int c, ind;

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
				options->all = true;
				break;
			case 'H':
				options->all = false;
				options->all_headers = true;
				break;
			case 'd':
				options->all = false;
				options->dirs = true;
				break;
			case 'S':
				options->all = false;
				options->all_sections = true;
				break;
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			case 'h':
				options->all = false;
				parse_headers(options, optarg);
				break;
			case 'i':
				options->all = false;
				options->imports = true;
				break;
			case 'e':
				options->all = false;
				options->exports = true;
				break;
			case 'f':
				if (output_set_format_by_name(optarg) < 0)
					EXIT_ERROR("invalid format option");
				break;
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	return options;
}

static void print_sections(pe_ctx_t *ctx)
{
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
	static const char * const flags_name[] = {
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
#endif
	// valid flags only for executables referenced in pecoffv8
	static const unsigned int valid_flags[] = {
		IMAGE_SCN_CNT_CODE,
		IMAGE_SCN_CNT_INITIALIZED_DATA,
		IMAGE_SCN_CNT_UNINITIALIZED_DATA,
		IMAGE_SCN_GPREL,
		IMAGE_SCN_LNK_NRELOC_OVFL,
		IMAGE_SCN_MEM_DISCARDABLE,
		IMAGE_SCN_MEM_NOT_CACHED,
		IMAGE_SCN_MEM_NOT_PAGED,
		IMAGE_SCN_MEM_SHARED,
		IMAGE_SCN_MEM_EXECUTE,
		IMAGE_SCN_MEM_READ,
		IMAGE_SCN_MEM_WRITE
	};
	static const size_t max_flags = LIBPE_SIZEOF_ARRAY(valid_flags);

	output_open_scope("Sections", OUTPUT_SCOPE_TYPE_ARRAY);

	const uint32_t num_sections = pe_sections_count(ctx);
	if (num_sections == 0 || num_sections > MAX_SECTIONS)
		return;

	IMAGE_SECTION_HEADER **sections = pe_sections(ctx);
	if (sections == NULL)
		return;

	char s[MAX_MSG];

	for (uint32_t i=0; i < num_sections; i++)
	{
		output_open_scope("Section", OUTPUT_SCOPE_TYPE_OBJECT);

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

		output_open_scope("Characteristic Names", OUTPUT_SCOPE_TYPE_ARRAY);

		for (size_t j=0; j < max_flags; j++) {
			if (sections[i]->Characteristics & valid_flags[j]) {
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
				snprintf(s, MAX_MSG, "%s", flags_name[j]);
				output(NULL, s);
#else
				output(NULL, pe_section_characteristic_name(valid_flags[j]));
#endif
			}
		}

		output_close_scope(); // Characteristic Names

		output_close_scope(); // Section
	}

	output_close_scope(); // Sections
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
	output_open_scope("Data directories", OUTPUT_SCOPE_TYPE_ARRAY);

	const uint32_t num_directories = pe_directories_count(ctx);
	if (num_directories == 0 || num_directories > MAX_DIRECTORIES)
		return;

	IMAGE_DATA_DIRECTORY **directories = pe_directories(ctx);
	if (directories == NULL)
		return;

	char s[MAX_MSG];

	for (uint32_t i=0; i < num_directories; i++) {
		if (directories[i]->Size) {
			output_open_scope("Directory", OUTPUT_SCOPE_TYPE_OBJECT);
			snprintf(s, MAX_MSG, "%#x (%d bytes)",
					directories[i]->VirtualAddress,
					directories[i]->Size);
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			output(directoryEntryNames[i].name, s);
#else
			output(pe_directory_name(i), s);
#endif
			output_close_scope(); // Directory
		}
	}

	output_close_scope(); // Data directories
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
		{ IMAGE_SUBSYSTEM_UNKNOWN,					"Unknown subsystem"		},
		{ IMAGE_SUBSYSTEM_UNKNOWN,					"Unknown subsystem"		},
		{ IMAGE_SUBSYSTEM_UNKNOWN,					"Unknown subsystem"		},
		{ IMAGE_SUBSYSTEM_POSIX_CUI,				"Posix CLI"				},
		{ IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,			"Windows CE GUI"		},
		{ IMAGE_SUBSYSTEM_EFI_APPLICATION, 			"EFI application"		},
		{ IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,	"EFI driver with boot"	},
		{ IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,		"EFI run-time driver"	},
		{ IMAGE_SUBSYSTEM_EFI_ROM, 					"EFI ROM"				},
		{ IMAGE_SUBSYSTEM_XBOX,			 			"XBOX"					},
		{ IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,	"Boot application"		}
	};
	static const size_t max_subsystem = LIBPE_SIZEOF_ARRAY(subsystemNames);
#endif

	if (!header)
		return;

	char s[MAX_MSG];

	output_open_scope("Optional/Image header", OUTPUT_SCOPE_TYPE_OBJECT);

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

			const uint16_t subsystem = header->_32->Subsystem;
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

#ifndef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			output_open_scope("DLL characteristics names", OUTPUT_SCOPE_TYPE_ARRAY);

			for (uint16_t i=0, flag=0x0001; i < 16; i++, flag <<= 1) {
				if (header->_32->DllCharacteristics & flag)
					output(NULL, pe_image_dllcharacteristic_name(flag));
			}

			output_close_scope(); // DLL characteristics names
#endif

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

			const uint16_t subsystem = header->_64->Subsystem;
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

#ifndef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			output_open_scope("DLL characteristics names", OUTPUT_SCOPE_TYPE_ARRAY);

			for (uint16_t i=0, flag=0x0001; i < 16; i++, flag <<= 1) {
				if (header->_64->DllCharacteristics & flag)
					output(NULL, pe_image_dllcharacteristic_name(flag));
			}

			output_close_scope(); // DLL characteristics names
#endif

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

	output_close_scope(); // Optional/Image heade
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

	output_open_scope("COFF/File header", OUTPUT_SCOPE_TYPE_OBJECT);

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

	output_open_scope("Characteristics names", OUTPUT_SCOPE_TYPE_ARRAY);

	for (uint16_t i=0, flag=0x0001; i < 16; i++, flag <<= 1) {
		if (header->Characteristics & flag)
#ifdef LIBPE_ENABLE_OUTPUT_COMPAT_WITH_V06
			output(NULL, characteristicsTable[i].name);
#else
			output(NULL, pe_image_characteristic_name(flag));
#endif
	}

	output_close_scope(); // Characteristics names

	output_close_scope(); // COFF/File header
}

static void print_dos_header(IMAGE_DOS_HEADER *header)
{
	char s[MAX_MSG];

	output_open_scope("DOS Header", OUTPUT_SCOPE_TYPE_OBJECT);

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

	output_close_scope(); // DOS Header
}

static void print_imported_functions(pe_ctx_t *ctx, uint64_t offset)
{
	uint64_t ofs = offset;

	char hint_str[16];
	char fname[MAX_FUNCTION_NAME];
	bool is_ordinal;

	memset(hint_str, 0, sizeof(hint_str));
	memset(fname, 0, sizeof(fname));

	while (1) {
		switch (ctx->pe.optional_hdr.type) {
			case MAGIC_PE32:
			{
				const IMAGE_THUNK_DATA32 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32))) {
					// TODO: Should we report something?
					return;
				}

				// Type punning
				const uint32_t thunk_type = *(uint32_t *)thunk;
				if (thunk_type == 0)
					return;

				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG32) != 0;

				if (is_ordinal) {
					snprintf(hint_str, sizeof(hint_str)-1, "%"PRIu32,
						thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
				} else {
					const uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						// TODO: Should we report something?
						return;
					}

					snprintf(hint_str, sizeof(hint_str)-1, "%d", imp_name->Hint);
					strncpy(fname, (char *)imp_name->Name, sizeof(fname)-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[sizeof(fname) - 1] = '\0';
					//size_t fname_len = strlen(fname);
				}
				ofs += sizeof(IMAGE_THUNK_DATA32);
				break;
			}
			case MAGIC_PE64:
			{
				const IMAGE_THUNK_DATA64 *thunk = LIBPE_PTR_ADD(ctx->map_addr, ofs);
				if (!pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64))) {
					// TODO: Should we report something?
					return;
				}

				// Type punning
				const uint64_t thunk_type = *(uint64_t *)thunk;
				if (thunk_type == 0)
					return;

				is_ordinal = (thunk_type & IMAGE_ORDINAL_FLAG64) != 0;

				if (is_ordinal) {
					snprintf(hint_str, sizeof(hint_str)-1, "%"PRIu64,
						thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG64);
				} else {
					uint64_t imp_ofs = pe_rva2ofs(ctx, thunk->u1.AddressOfData);
					const IMAGE_IMPORT_BY_NAME *imp_name = LIBPE_PTR_ADD(ctx->map_addr, imp_ofs);
					if (!pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME))) {
						// TODO: Should we report something?
						return;
					}

					snprintf(hint_str, sizeof(hint_str)-1, "%d", imp_name->Hint);
					strncpy(fname, (char *)imp_name->Name, sizeof(fname)-1);
					// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
					fname[sizeof(fname) - 1] = '\0';
					//size_t fname_len = strlen(fname);
				}
				ofs += sizeof(IMAGE_THUNK_DATA64);
				break;
			}
		}

		output_open_scope("Function", OUTPUT_SCOPE_TYPE_OBJECT);

		if (is_ordinal)
			output("Ordinal", hint_str);
		else
			output("Name", fname);

		output_close_scope(); // Function
	}
}

static void print_exports(pe_ctx_t *ctx)
{
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dir == NULL)
		EXIT_ERROR("export directory not found")

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "export directory not found\n");
		return;
	}

	uint64_t ofs;

	ofs = pe_rva2ofs(ctx, va);
	const IMAGE_EXPORT_DIRECTORY *exp = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
		// TODO: Should we report something?
		return;
	}

	ofs = pe_rva2ofs(ctx, exp->AddressOfNames);
	const uint32_t *rva_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
	if (!pe_can_read(ctx, rva_ptr, sizeof(uint32_t))) {
		// TODO: Should we report something?
		return;
	}
	const uint32_t rva = *rva_ptr;

	ofs = pe_rva2ofs(ctx, rva);

	output_open_scope("Exported functions", OUTPUT_SCOPE_TYPE_ARRAY);
	// If `NumberOfNames == 0` then all functions are exported by ordinal.
	// Otherwise `NumberOfNames` must be equal to `NumberOfFunctions`
	if (exp->NumberOfNames != 0 && exp->NumberOfNames != exp->NumberOfFunctions) {
		fprintf(stderr, "NumberOfFunctions differs from NumberOfNames\n");
		output_close_scope(); // Exported functions
	}

	uint64_t offset_to_AddressOfFunctions = pe_rva2ofs(ctx, exp->AddressOfFunctions);
	uint64_t offset_to_AddressOfNames = pe_rva2ofs(ctx, exp->AddressOfNames);
	uint64_t offset_to_AddressOfNameOrdinals = pe_rva2ofs(ctx, exp->AddressOfNameOrdinals);

	//
	// The format of IMAGE_EXPORT_DIRECTORY can be seen in http://i.msdn.microsoft.com/dynimg/IC60608.gif
	//

	// We want to use `NumberOfFunctions` for looping as it's the total number of functions/symbols
	// exported by the module. On the other hand, `NumberOfNames` is the number of
	// functions/symbols exported by name only.
	for (uint32_t i=0; i < exp->NumberOfFunctions; i++) {
		uint64_t entry_ordinal_list_ptr = offset_to_AddressOfNameOrdinals + sizeof(uint16_t) * i;
		uint16_t *entry_ordinal_list = LIBPE_PTR_ADD(ctx->map_addr, entry_ordinal_list_ptr);

		uint64_t entry_va_list_ptr = offset_to_AddressOfFunctions + sizeof(uint32_t) * i;
		uint32_t *entry_va_list = LIBPE_PTR_ADD(ctx->map_addr, entry_va_list_ptr);

		uint64_t entry_name_list_ptr = offset_to_AddressOfNames + sizeof(uint32_t) * i;
		uint32_t *entry_name_list = LIBPE_PTR_ADD(ctx->map_addr, entry_name_list_ptr);

		// printf("ctx->map_addr = %p\n", ctx->map_addr);
		// printf("ctx->map_end = %p\n", ctx->map_end);
		// printf("entry_ordinal_list = %p\n", entry_ordinal_list);
		// printf("entry_va_list = %p\n", entry_va_list);
		// printf("entry_name_list = %p\n", entry_name_list);

		if (!pe_can_read(ctx, entry_ordinal_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		if (!pe_can_read(ctx, entry_va_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		if (!pe_can_read(ctx, entry_name_list, sizeof(uint32_t))) {
			// TODO: Should we report something?
			break;
		}

		// Add `Base` to the element of `AddressOfNameOrdinals` array to get the correct ordinal..
		//const uint16_t entry_ordinal = exp->Base + *entry_ordinal_list;
		const uint32_t entry_va = *entry_va_list;
		const uint32_t entry_name_rva = *entry_name_list;
		const uint64_t entry_name_ofs = pe_rva2ofs(ctx, entry_name_rva);
		const char *entry_name = LIBPE_PTR_ADD(ctx->map_addr, entry_name_ofs);

		// Validate whether it's ok to access at least 1 byte after entry_name.
		// It might be '\0', for example.
		if (!pe_can_read(ctx, entry_name, 1)) {
			// TODO: Should we report something?
			break;
		}

		//printf("ord=%d, va=%x, name=%s\n", entry_ordinal, entry_va, entry_name);

		// Declared as 11 bytes so that it can store the hexadecimal representation of the maximum
		// possible value of an uint32_t variable, 0xFFFFFFFF.
		char addr[11] = { 0 };
		sprintf(addr, "%#x", entry_va);

		char fname[300] = { 0 };
		strncpy(fname, entry_name, sizeof(fname)-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		fname[sizeof(fname) - 1] = '\0';

		output_open_scope("Function", OUTPUT_SCOPE_TYPE_OBJECT);

		// Check whether the exported function is forwarded.
		// It's forwarded if its RVA is inside the exports section.
		if (entry_va >= va && entry_va <= va + dir->Size)
		{
			// When a symbol is forwarded, its RVA points to a string containing
			// the name of the DLL and symbol to which it is forwarded.
			const uint64_t fw_entry_name_ofs = pe_rva2ofs(ctx, entry_va);
			const char *fw_entry_name = LIBPE_PTR_ADD(ctx->map_addr, fw_entry_name_ofs);

			// Validate whether it's ok to access at least 1 byte after fw_entry_name.
			// It might be '\0', for example.
			if (!pe_can_read(ctx, fw_entry_name, 1)) {
				// TODO: Should we report something?
				break;
			}

			char fname_forwarded[sizeof(fname) * 2 + 4] = { 0 }; // Twice the size plus " -> ".
			snprintf(fname_forwarded, sizeof(fname_forwarded)-1, "%s -> %s", fname, fw_entry_name);

			output(addr, fname_forwarded);
		}
		else
		{
			output(addr, fname);
		}

		output_close_scope(); // Function
	}

	output_close_scope(); // Exported functions
}

static void print_imports(pe_ctx_t *ctx)
{
	const IMAGE_DATA_DIRECTORY *dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir == NULL)
		EXIT_ERROR("import directory not found")

	const uint64_t va = dir->VirtualAddress;
	if (va == 0) {
		fprintf(stderr, "import directory not found\n");
		return;
	}
	uint64_t ofs = pe_rva2ofs(ctx, va);

	output_open_scope("Imported functions", OUTPUT_SCOPE_TYPE_ARRAY);

	while (1) {
		IMAGE_IMPORT_DESCRIPTOR *id = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		if (!pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			// TODO: Should we report something?
			output_close_scope();
			return;
		}

		if (!id->u1.OriginalFirstThunk && !id->FirstThunk)
			break;

		ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		const uint64_t aux = ofs; // Store current ofs

		ofs = pe_rva2ofs(ctx, id->Name);
		if (ofs == 0)
			break;

		const char *dll_name_ptr = LIBPE_PTR_ADD(ctx->map_addr, ofs);
		// Validate whether it's ok to access at least 1 byte after dll_name_ptr.
		// It might be '\0', for example.
		if (!pe_can_read(ctx, dll_name_ptr, 1)) {
			// TODO: Should we report something?
			break;
		}

		char dll_name[MAX_DLL_NAME];
		strncpy(dll_name, dll_name_ptr, sizeof(dll_name)-1);
		// Because `strncpy` does not guarantee to NUL terminate the string itself, this must be done explicitly.
		dll_name[sizeof(dll_name) - 1] = '\0';

		output_open_scope("Library", OUTPUT_SCOPE_TYPE_OBJECT);
		output("Name", dll_name);

		ofs = pe_rva2ofs(ctx, id->u1.OriginalFirstThunk ? id->u1.OriginalFirstThunk : id->FirstThunk);
		if (ofs == 0) {
			output_close_scope(); // Library
			break;
		}

		output_open_scope("Functions", OUTPUT_SCOPE_TYPE_ARRAY);

		// Search for DLL imported functions
		print_imported_functions(ctx, ofs);

		output_close_scope(); // Functions

		ofs = aux; // Restore previous ofs

		output_close_scope(); // Library
	}

	output_close_scope(); // Imported functions
}

int main(int argc, char *argv[])
{
	pev_config_t config;
	PEV_INITIALIZE(&config);

	if (argc < 2) {
		usage();
		return EXIT_FAILURE;
	}

	output_set_cmdline(argc, argv);

	options_t *options = parse_options(argc, argv); // opcoes

	pe_ctx_t ctx;

	pe_err_e err = pe_load_file(&ctx, argv[argc-1]);
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

	output_open_document();

	// dos header
	if (options->dos || options->all_headers || options->all) {
		IMAGE_DOS_HEADER *header_ptr = pe_dos(&ctx);
		if (header_ptr)
			print_dos_header(header_ptr);
		else { EXIT_ERROR("unable to read DOS header"); }
	}

	// coff/file header
	if (options->coff || options->all_headers || options->all) {
		IMAGE_COFF_HEADER *header_ptr = pe_coff(&ctx);
		if (header_ptr)
			print_coff_header(header_ptr);
		else { EXIT_ERROR("unable to read COFF file header"); }
	}

	// optional header
	if (options->opt || options->all_headers || options->all) {
		IMAGE_OPTIONAL_HEADER *header_ptr = pe_optional(&ctx);
		if (header_ptr)
			print_optional_header(header_ptr);
		else { EXIT_ERROR("unable to read Optional (Image) file header"); }
	}

	IMAGE_DATA_DIRECTORY **directories = pe_directories(&ctx);
	bool directories_warned = false;

	// directories
	if (options->dirs || options->all) {
		if (directories != NULL)
			print_directories(&ctx);
		else if (!directories_warned) {
			fprintf(stderr, "directories not found\n");
			directories_warned = true;
		}
	}

	// imports
	if (options->imports || options->all) {
		if (directories != NULL)
			print_imports(&ctx);
		else if (!directories_warned) {
			fprintf(stderr, "directories not found\n");
			directories_warned = true;
		}
	}

	// exports
	if (options->exports || options->all) {
		if (directories != NULL)
			print_exports(&ctx);
		else if (!directories_warned) {
			fprintf(stderr, "directories not found\n");
			directories_warned = true;
		}
	}

	// sections
	if (options->all_sections || options->all) {
		if (pe_sections(&ctx) != NULL)
			print_sections(&ctx);
		else { EXIT_ERROR("unable to read sections"); }
	}

	output_close_document();

	// libera a memoria
	free_options(options);

	// free
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	PEV_FINALIZE(&config);

	return EXIT_SUCCESS;
}
