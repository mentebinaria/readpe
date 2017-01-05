/*
	pev - PE information dump utility

	Copyright (C) 2010 - 2011 Coding 40° <www.mentebinaria.com.br>

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

#ifndef PE_H
#define PE_H

/* Definitions of PE structure */
#define IMAGE_SIZEOF_SHORT_NAME 8

/* Resource types */
#define RT_CURSOR			1		/* Cursor images */
#define RT_BITMAP			2		/* Raster images */
#define RT_ICON 3			3		/* Icon images */
#define RT_MENU 4			4		/* Menus */
#define RT_DIALOG			5		/* Dialogs */
#define RT_STRING			6		/* Strings, Unicode */
#define RT_FONTDIR			7		/* Font directory */
#define RT_FONT				8		/* Fonts */
#define RT_ACCELERATOR		9		/* Accelerators (combinations of hot keys) */
#define RT_RCDATA			10		/* Various data */
#define RT_MESSAGETABLE		11		/* Strings */
#define RT_GROUP_CURSOR		12		/* Cursor group */
#define RT_GROUP_ICON		14		/* Icon groups */
#define RT_VERSION			16		/* Version information */
#define RT_DLGINCLUDE		17		/* Names of header files for dialogs (*.h). They are used by the compiler. */
#define RT_PLUGPLAY			19		/* Type of data is determined by application */
#define RT_VXD				20
#define RT_ANICURSOR		21		/* Animated cursors */
#define RT_ANIICON			22		/* Animated icons */
#define RT_HTML				23		/* HTML pages */
#define RT_MANIFEST			24		/* Manifest of Windows XP build */
#define RT_DLGINIT			240		/* Strings, used for initiating some controls in dialogs */
#define RT_TOOLBAR			241		/* Configuration of toolbars */

typedef struct _res_type
{
	char r_name[20];
	int r_code;
} res_type;

typedef unsigned int DWORD;
typedef int LONG;
typedef unsigned char BYTE;
typedef unsigned short WORD;

#if __WORDSIZE == 64
typedef unsigned long QWORD;
#else
typedef unsigned long long QWORD;
#endif

typedef struct _machine_type
{
  char m_name[40];
  WORD m_code;
} machine_type; 

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
} IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
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
} IMAGE_OPTIONAL_HEADER,*PIMAGE_OPTIONAL_HEADER;

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
} IMAGE_OPTIONAL_HEADER_64,*PIMAGE_OPTIONAL_HEADER_64;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;		/* same value as next field */
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;		/* always zero in executables */
	DWORD PointerToLinenumbers;		/* deprecated */
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;		/* deprecated */
	DWORD Characteristics;
} IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	WORD NumberOfNamedEntries;
	WORD NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY,*PIMAGE_RESOURCE_DIRECTORY;

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
} IMAGE_RESOURCE_DIRECTORY_ENTRY,*PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
	DWORD OffsetToData;
	DWORD Size;
	DWORD CodePage;
	DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY,*PIMAGE_RESOURCE_DATA_ENTRY;

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
	DWORD AddressOfIndex;			/* PDWORD */
	DWORD AddressOfCallBacks;		/* PIMAGE_TLS_CALLBACK */
	DWORD SizeOfZeroFill;
	DWORD Characteristics;			/* Reserved for future use */
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
	QWORD StartAddressOfRawData;
	QWORD EndAddressOfRawData;
	QWORD AddressOfIndex;
	QWORD AddressOfCallBacks;
	DWORD SizeOfZeroFill;
	DWORD Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

#endif /* PE_H */
