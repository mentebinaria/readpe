#ifndef LIBPE_H
#define LIBPE_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define PE32 0x10b
#define PE64 0x20b
#define ROM 0x107

typedef unsigned int DWORD;
typedef int LONG;
typedef unsigned char BYTE;
typedef unsigned short WORD;

#if __WORDSIZE == 64
typedef unsigned long QWORD;
#else
typedef unsigned long long QWORD;
#endif

// section name size
#define IMAGE_SIZEOF_SHORT_NAME 8

// resources types
#define RT_CURSOR         1    // cursor image
#define RT_BITMAP         2    // bitmap (.bmp)
#define RT_ICON           3    // icon
#define RT_MENU           4    // menu
#define RT_DIALOG         5    // dialog window
#define RT_STRING         6    // unicode string
#define RT_FONTDIR        7    // font directory
#define RT_FONT           8    // font
#define RT_ACCELERATOR	  9    // hot keys
#define RT_RCDATA         10   // data
#define RT_MESSAGETABLE	  11   // string table
#define RT_GROUP_CURSOR	  12   // cursor group
#define RT_GROUP_ICON     14   // icon group
#define RT_VERSION        16   // version information
#define RT_DLGINCLUDE     17   // names of header files for dialogs (*.h) used by compiler
#define RT_PLUGPLAY       19   // data determined by application
#define RT_VXD            20   // vxd info
#define RT_ANICURSOR      21   // animated cursor
#define RT_ANIICON        22   // animated icon
#define RT_HTML           23   // html page
#define RT_MANIFEST       24   // manifest of Windows XP build
#define RT_DLGINIT        240  // strings used for initiating some controls in dialogs
#define RT_TOOLBAR        241  // configuration of toolbars

typedef struct _RESOURCE_ENTRY
{
	char name[20];
	int code;
} RESOURCE_ENTRY;



typedef struct _MACHINE_ENTRY
{
	char name[40];
	WORD code;
} MACHINE_ENTRY;

typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, IMAGE_COFF_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER_32 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData;					/* only PE32 */
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Reserved1;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	/*IMAGE_DATA_DIRECTORY DataDirectory[];*/
} IMAGE_OPTIONAL_HEADER_32;

/* note that some fields are quad-words */
typedef struct _IMAGE_OPTIONAL_HEADER_64 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	QWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Reserved1;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	QWORD SizeOfStackReserve;
	QWORD SizeOfStackCommit;
	QWORD SizeOfHeapReserve;
	QWORD SizeOfHeapCommit;
	DWORD LoaderFlags;				/* must be zero */
	DWORD NumberOfRvaAndSizes;
	/* IMAGE_DATA_DIRECTORY DataDirectory[]; */
} IMAGE_OPTIONAL_HEADER_64;

typedef struct _IMAGE_OPTIONAL_HEADER {
    IMAGE_OPTIONAL_HEADER_32 *_32;
    IMAGE_OPTIONAL_HEADER_64 *_64;
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;     // same value as next field
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;   // always zero in executables
	DWORD PointerToLinenumbers;   // deprecated
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;     // deprecated
	DWORD Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	WORD NumberOfNamedEntries;
	WORD NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
	union {
		struct {
			DWORD NameOffset:31;
			DWORD NameIsString:1;
		} s1;
		DWORD Name;
		WORD Id;
	} u1;
	union {
		DWORD OffsetToData;
		struct {
			DWORD OffsetToDirectory:31;
			DWORD DataIsDirectory:1;
		} s2;
	} u2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
	DWORD OffsetToData;
	DWORD Size;
	DWORD CodePage;
	DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY;

typedef struct tagVS_FIXEDFILEINFO {
	DWORD dwSignature;
	DWORD dwStrucVersion;
	DWORD dwFileVersionMS;
	DWORD dwFileVersionLS;
	DWORD dwProductVersionMS;
	DWORD dwProductVersionLS;
	DWORD dwFileFlagsMask;
	DWORD dwFileFlags;
	DWORD dwFileOS;
	DWORD dwFileType;
	DWORD dwFileSubtype;
	DWORD dwFileDateMS;
	DWORD dwFileDateLS;
} VS_FIXEDFILEINFO;

typedef struct _IMAGE_TLS_DIRECTORY32 {
	DWORD StartAddressOfRawData;
	DWORD EndAddressOfRawData;
	DWORD AddressOfIndex;         /* PDWORD */
	DWORD AddressOfCallBacks;     /* PIMAGE_TLS_CALLBACK */
	DWORD SizeOfZeroFill;
	DWORD Characteristics;        /* Reserved for future use */
} IMAGE_TLS_DIRECTORY32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
	QWORD StartAddressOfRawData;
	QWORD EndAddressOfRawData;
	QWORD AddressOfIndex;
	QWORD AddressOfCallBacks;
	DWORD SizeOfZeroFill;
	DWORD Characteristics;
} IMAGE_TLS_DIRECTORY64;

typedef struct _PE_FILE
{
	FILE *handle;
	
	int e_lfanew;
	int architecture;
	
	int num_sections;
	int num_directories;
	
	int addr_sections;
	int addr_directories;
	int addr_dos;
	int addr_optional;
	int addr_coff;
	
	// pointers (will be freed if needed)
	IMAGE_OPTIONAL_HEADER *optional_ptr;
	IMAGE_SECTION_HEADER *sections_ptr;
	IMAGE_DATA_DIRECTORY *directories_ptr;
	IMAGE_TLS_DIRECTORY32 *tls_ptr;
	
} PE_FILE;

static const char *DIRECTORY_NAMES[] =
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

static const RESOURCE_ENTRY RESOURCE_TYPES[] = 
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

// basic functions
bool ispe(PE_FILE *pe);
void pe_clear(PE_FILE *pe);

// header functions
bool pe_init(PE_FILE *pe, FILE *handle);
bool pe_get_sections(PE_FILE *pe);
bool pe_get_directories(PE_FILE *pe);
bool pe_get_optional(PE_FILE *pe);//, PE_OPTIONAL_HEADER *header);
bool pe_get_coff(PE_FILE *pe, IMAGE_COFF_HEADER *header);
int  pe_get_dos(PE_FILE *pe, IMAGE_DOS_HEADER *header);

bool pe_get_tls_callbacks(PE_FILE *pe);
bool pe_get_resource_directory(PE_FILE *pe, IMAGE_RESOURCE_DIRECTORY *dir);

#endif
