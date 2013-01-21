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
	bool all;
	bool extract;
	bool info;
	bool statistics;
	bool version;
	bool help;
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
	struct NODE_PERES *rootNode;
} NODE_PERES;

char *resourceDir = "resources";

static const RESOURCE_ENTRY resourceTypes[] =
{
	{"RT_CURSOR", 1, ".cur", "cursors"},
	{"RT_BITMAP", 2, ".bmp", "bitmaps"},
	{"RT_ICON", 3, ".ico", "icons"},
	{"RT_MENU", 4, ".rc", "menus"},
	{"RT_DIALOG", 5, ".dlg", "dialogs"},
	{"RT_STRING", 6, ".rc", "strings"},
	{"RT_FONTDIR", 7, ".fnt", "fontdirs"},
	{"RT_FONT", 8, ".fnt", "fonts"},
	{"RT_ACCELERATOR", 9, ".rc", "accelerators"},
	{"RT_RCDATA", 10, ".rc", "rcdatas"},
	{"RT_MESSAGETABLE", 11, ".mc", "messagetables"},
	{"RT_GROUP_CURSOR", 12, ".cur", "groupcursors"},
	{"RT_GROUP_ICON", 14, ".ico", "groupicons"},
	{"RT_VERSION", 16, ".rc", "versions"},
	{"RT_DLGINCLUDE", 17, ".rc", "dlgincludes"},
	{"RT_PLUGPLAY", 19, ".rc", "plugplays"},
	{"RT_VXD", 20, ".rc", "xvds"},
	{"RT_ANICURSOR", 21, ".rc", "anicursors"},
	{"RT_ANIICON", 22, ".rc", "aniicons"},
	{"RT_HTML", 23, ".html", "htmls"},
	{"RT_MANIFEST", 24, ".xml", "manifests"},
	{"RT_DLGINIT", 240, ".rc", "dlginits"},
	{"RT_TOOLBAR", 241, ".rc", "toolbars"}
};

struct options config;

#endif
