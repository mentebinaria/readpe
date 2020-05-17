/*
	pev - the PE file analyzer toolkit

	common.h - common defitions for the pev toolkit.

	Copyright (C) 2013 - 2020 pev authors

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

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <ctype.h>

#include <libpe/pe.h>
#include "config.h"
#include "output.h"
#include "plugins.h"

#define UNUSED(x)      (void)(sizeof((x)))

#define EXIT_ERROR(msg) \
{ \
	fprintf(stderr, "ERROR: %s [at %s:%d]\n", msg, __FILE__, __LINE__); \
	exit(1); \
}

#define MAX_MSG 80
#define MAX_PATH 256
#define VERSION "0.81"
#define TOOLKIT "from pev " VERSION " <https://github.com/merces/pev/> toolkit"
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
