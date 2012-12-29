/*
	pev - the PE file analyzer toolkit
	
	peres.h - definitions for peres.c

	Copyright (C) 2012 pev authors

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

#ifndef PERES_H
#define PERES_H

#include "common.h"
#include <string.h>

#define PROGRAM "peres"

struct options {
	bool exportAll;
	bool infoAll;
	bool exportType;
	bool infoType;
};

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

typedef struct _NODE_PERES
{
	NODE_TYPE_PERES nodeType;
	NODE_LEVEL_PERES nodeLevel;
	union
	{
		IMAGE_RESOURCE_DIRECTORY resourceDirectory; // nodeType == 1
		IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry; // nodeType == 2
		IMAGE_RESOURCE_DATA_STRING dataString; // nodeType == 3
		IMAGE_RESOURCE_DATA_ENTRY dataEntry; // nodeType == 4
	} node;
	struct NODE_PERES *nextNode;
	struct NODE_PERES *lastNode;
} NODE_PERES;

struct options config;

#endif
