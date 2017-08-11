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

#ifndef LIBPE_PERES
#define LIBPE_PERES

#include <stdint.h>
#include "error.h"
#include "dir_resources.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RDT_LEVEL1 = 1,
	RDT_LEVEL2 = 2,
	RDT_LEVEL3 = 3
} NODE_LEVEL_PERES;

typedef enum {
	RDT_RESOURCE_DIRECTORY = 1,
	RDT_DIRECTORY_ENTRY = 2,
	RDT_DATA_STRING = 3,
	RDT_DATA_ENTRY = 4
} NODE_TYPE_PERES;

typedef struct _NODE_PERES {
	NODE_TYPE_PERES nodeType;
	NODE_LEVEL_PERES nodeLevel;
	union {
		IMAGE_RESOURCE_DIRECTORY *resourceDirectory; // nodeType == 1
		IMAGE_RESOURCE_DIRECTORY_ENTRY *directoryEntry; // nodeType == 2
		IMAGE_RESOURCE_DATA_STRING *dataString; // nodeType == 3
		IMAGE_RESOURCE_DATA_ENTRY *dataEntry; // nodeType == 4
	} resource;
	struct _NODE_PERES *nextNode;
	struct _NODE_PERES *lastNode;
	struct _NODE_PERES *rootNode;
} NODE_PERES;

typedef struct {
	int NodeType;
	int Characteristics;
	int TimeDateStamp;
	int MajorVersion;
	int MinorVersion;
	int NumberOfNamedEntries;
	int NumberOfIdEntries;
} type_RDT_RESOURCE_DIRECTORY;

typedef struct {
	int NodeType;
	int NameOffset;
	int NameIsString;
	int OffsetIsDirectory;
	int DataIsDirectory;
} type_RDT_DIRECTORY_ENTRY;

typedef struct {
	int NodeType;
	int Strlen;
	int String;
} type_RDT_DATA_STRING;

typedef struct {
	int NodeType;
	int OffsetToData;
	int Size;
	int CodePage;
	int Reserved;
} type_RDT_DATA_ENTRY;

typedef struct {
	NODE_TYPE_PERES kind;
	union {
		type_RDT_RESOURCE_DIRECTORY resourcesDirectory;
		type_RDT_DIRECTORY_ENTRY directoryEntry;
		type_RDT_DATA_STRING dataString;
		type_RDT_DATA_ENTRY dataEntry;
	}node_type;

} output_node_t;

// counting
typedef struct {
	int resourcesDirectory;
	int directoryEntry;
	int dataString;
	int dataEntry;
} pe_resources_count_t;

typedef struct {
	NODE_TYPE_PERES kind;
} count_output_node_t;

typedef struct {
	pe_err_e err;
	type_RDT_RESOURCE_DIRECTORY *resourcesDirectory;
	type_RDT_DIRECTORY_ENTRY *directoryEntry;
	type_RDT_DATA_STRING *dataString;
	type_RDT_DATA_ENTRY *dataEntry;
} pe_final_output_t;

#ifdef __cplusplus
} // extern "C"
#endif

#endif
