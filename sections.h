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

#ifndef LIBPE_SECTIONS_H
#define LIBPE_SECTIONS_H

#include <inttypes.h>

#define SECTION_NAME_SIZE 8

// Quoting pecoff_v8.docx: "Entries in the section table are numbered starting from one (1)".
typedef struct {
	uint8_t Name[SECTION_NAME_SIZE]; // TODO: Should we use char instead?
	union {
		uint32_t PhysicalAddress; // same value as next field
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations; // always zero in executables
	uint32_t PointerToLinenumbers; // deprecated
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers; // deprecated
	uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#endif
