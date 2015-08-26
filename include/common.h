/*
	pev - the PE file analyzer toolkit

	common.h - common defitions for the pev toolkit.

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

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>

#include <pe.h>
#include "config.h"
#include "output.h"
#include "plugins.h"

#define UNUSED(x)      (void)(sizeof((x)))

#define EXIT_ERROR(msg) \
{ \
	fprintf(stderr, "%s\n", msg); \
	exit(1); \
}

#define MAX_MSG 80
#define VERSION "0.80"
#define TOOLKIT "from pev " VERSION " <http://pev.sf.net> toolkit"
#define COPY \
"License GPLv2+: GNU GPL version 2 or later <https://www.gnu.org/licenses/gpl-2.0.txt>.\n" \
"This is free software: you are free to change and redistribute it.\n" \
"There is NO WARRANTY, to the extent permitted by law."

void *malloc_s(size_t size);

#define PEV_INITIALIZE(config) \
	do { \
		memset(config, 0, sizeof(*config)); \
		pev_load_config(config); \
		int ret = plugins_load_all(config); \
		if (ret < 0) \
			exit(EXIT_FAILURE); \
		output_init(); /* Requires plugin for text output. */ \
	} while (0)

#define PEV_FINALIZE(config) \
	do { \
		output_term(); \
		plugins_unload_all(); \
		pev_cleanup_config(config); \
	} while (0)
