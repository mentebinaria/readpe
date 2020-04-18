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
	LIBPE_RDT_LEVEL1 = 1,
	LIBPE_RDT_LEVEL2 = 2,
	LIBPE_RDT_LEVEL3 = 3
} LIBPE_RESOURCE_LEVEL;

typedef enum {
	LIBPE_RDT_RESOURCE_DIRECTORY = 1,
	LIBPE_RDT_DIRECTORY_ENTRY = 2,
	LIBPE_RDT_DATA_STRING = 3,
	LIBPE_RDT_DATA_ENTRY = 4
} LIBPE_RESOURCE_NODE_TYPE;

typedef struct libpe_resource_node {
	LIBPE_RESOURCE_NODE_TYPE nodeType;
	LIBPE_RESOURCE_LEVEL nodeLevel;
	union {
		IMAGE_RESOURCE_DIRECTORY *resourceDirectory; // nodeType == 1
		IMAGE_RESOURCE_DIRECTORY_ENTRY *directoryEntry; // nodeType == 2
		IMAGE_RESOURCE_DATA_STRING *dataString; // nodeType == 3
		IMAGE_RESOURCE_DATA_ENTRY *dataEntry; // nodeType == 4
	} resource;
	struct libpe_resource_node *nextNode;
	struct libpe_resource_node *lastNode;
	struct libpe_resource_node *rootNode;
} libpe_resource_node_t;

#ifdef __cplusplus
} // extern "C"
#endif

#endif
