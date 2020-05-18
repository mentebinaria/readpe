/*
    libpe - the PE library

    Copyright (C) 2010 - 2017 libpe authors
    
    This file is part of libpe.

    libpe is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libpe is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libpe.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef LIBPE_DIR_RESOURCES_H
#define LIBPE_DIR_RESOURCES_H

#include <stdint.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IMAGE_RESOURCE_NAME_IS_STRING		0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY	0x80000000

// REFERENCE: https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types
typedef enum {
	RT_CURSOR			= 1, // cursor image
	RT_BITMAP			= 2, // bitmap (.bmp)
	RT_ICON				= 3, // icon
	RT_MENU				= 4, // menu
	RT_DIALOG			= 5, // dialog window
	RT_STRING			= 6, // unicode string
	RT_FONTDIR			= 7, // font directory
	RT_FONT				= 8, // font
	RT_ACCELERATOR		= 9, // hot keys
	RT_RCDATA			= 10, // data
	RT_MESSAGETABLE		= 11, // string table
	RT_GROUP_CURSOR		= 12, // cursor group
	RT_GROUP_ICON		= 14, // icon group
	RT_VERSION			= 16, // version information
	RT_DLGINCLUDE		= 17, // names of header files for dialogs (*.h) used by compiler
	RT_PLUGPLAY			= 19, // data determined by application
	RT_VXD				= 20, // vxd info
	RT_ANICURSOR		= 21, // animated cursor
	RT_ANIICON			= 22, // animated icon
	RT_HTML				= 23, // html page
	RT_MANIFEST			= 24, // manifest of Windows XP build
	RT_DLGINIT			= 240, // strings used for initiating some controls in dialogs
	RT_TOOLBAR			= 241 // configuration of toolbars
} ResourceType;

#pragma pack(push, 1)

typedef struct {
	uint32_t Characteristics;
	uint32_t TimeDateStamp;
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint16_t NumberOfNamedEntries;
	uint16_t NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY;

typedef struct {
	union {
		struct {
			uint32_t NameOffset:31;
			uint32_t NameIsString:1;
		} data;
		uint32_t Name;
        uint16_t Id;
	} u0;
	union {
		uint32_t OffsetToData;
		struct {
			uint32_t OffsetToDirectory:31;
			uint32_t DataIsDirectory:1;
		} data;
	} u1;
} IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct {
	uint16_t Length;
	char String[1];
} IMAGE_RESOURCE_DATA_STRING;

typedef struct {
	uint16_t Length; // Number of Unicode characters
	wchar_t String[1];
} IMAGE_RESOURCE_DATA_STRING_U;

typedef struct {
	uint32_t OffsetToData;
	uint32_t Size;
	uint32_t CodePage;
	uint32_t Reserved;
} IMAGE_RESOURCE_DATA_ENTRY;

typedef struct {
   uint32_t dwSignature;
   uint32_t dwStrucVersion;
   uint32_t dwFileVersionMS;
   uint32_t dwFileVersionLS;
   uint32_t dwProductVersionMS;
   uint32_t dwProductVersionLS;
   uint32_t dwFileFlagsMask;
   uint32_t dwFileFlags;
   uint32_t dwFileOS;
   uint32_t dwFileType;
   uint32_t dwFileSubtype;
   uint32_t dwFileDateMS;
   uint32_t dwFileDateLS;
} VS_FIXEDFILEINFO;

#pragma pack(pop)

#ifdef __cplusplus
} // extern "C"
#endif

#endif
