/*
	libpe - the PE library

	Copyright (C) 2010 - 2013 libpe authors

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

#ifndef LIBPE_HDR_OPTIONAL_H
#define LIBPE_HDR_OPTIONAL_H

#include <inttypes.h>

typedef enum {
	// An unknown subsystem
	IMAGE_SUBSYSTEM_UNKNOWN					= 0,
	// Device drivers and native Windows processes
	IMAGE_SUBSYSTEM_NATIVE					= 1,
	// The Windows graphical user interface (GUI) subsystem
	IMAGE_SUBSYSTEM_WINDOWS_GUI				= 2,
	// The Windows character subsystem
	IMAGE_SUBSYSTEM_WINDOWS_CUI				= 3,
	// The Posix character subsystem
	IMAGE_SUBSYSTEM_POSIX_CUI				= 7,
	// Windows CE
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI			= 9,
	// An Extensible Firmware Interface (EFI) application
	IMAGE_SUBSYSTEM_EFI_APPLICATION			= 10,
	// An EFI driver with boot services
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
	// An EFI driver with run-time services
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER		= 12,
	// An EFI ROM image
	IMAGE_SUBSYSTEM_EFI_ROM					= 13,
	// XBOX
	IMAGE_SUBSYSTEM_XBOX					= 14
} WindowsSubsystem;

typedef enum {
	MAGIC_ROM	= 0x107,
	MAGIC_PE32	= 0x10b,
	MAGIC_PE64	= 0x20b // PE32+
} opt_type_e;

#pragma pack(push, 1)

typedef struct {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData; // only in PE32
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Reserved1;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem; // WindowsSubsystem
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_32;

typedef struct {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Reserved1;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem; // WindowsSubsystem
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags; /* must be zero */
	uint32_t NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_64;

typedef struct {
	uint16_t type; // opt_type_e
	size_t length;
	IMAGE_OPTIONAL_HEADER_32 *_32;
	IMAGE_OPTIONAL_HEADER_64 *_64;
} IMAGE_OPTIONAL_HEADER;

#pragma pack(pop)

#endif
