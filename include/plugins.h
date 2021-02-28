/*
	pev - the PE file analyzer toolkit

	plugins.h - Symbols and definitions for the plugins subsystem.

	Copyright (C) 2012 - 2014 pev authors

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

#include "config.h"
#include "plugin.h"
#include "dylib.h"
#include "common.h"
#include "compat/sys/queue.h"
#include <libpe/utils.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include "config.h"
#include "pev_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _plugins_entry {
	dylib_t library;
	plugin_loaded_fn_t plugin_loaded_fn;
	plugin_initialize_fn_t plugin_initialize_fn;
	plugin_shutdown_fn_t plugin_shutdown_fn;
	plugin_unloaded_fn_t plugin_unloaded_fn;
	SLIST_ENTRY(_plugins_entry) entries;
} plugins_entry_t;

static SLIST_HEAD(_plugins_t_list, _plugins_entry) g_loaded_plugins = SLIST_HEAD_INITIALIZER(g_loaded_plugins);

int plugins_load(const char *path);
int plugins_load_all(pev_config_t *config);
int plugins_load_all_from_directory(const char *path);
void plugins_unload_all(void);
plugins_entry_t* get_plugins_entry();

#ifdef __cplusplus
}
#endif
