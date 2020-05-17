/*
	pev - the PE file analyzer toolkit

	plugins.c - Implementation for the plugins subsystem.

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

#include "plugins.h"
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

typedef struct _plugins_entry {
	dylib_t library;
	plugin_loaded_fn_t plugin_loaded_fn;
	plugin_initialize_fn_t plugin_initialize_fn;
	plugin_shutdown_fn_t plugin_shutdown_fn;
	plugin_unloaded_fn_t plugin_unloaded_fn;
	SLIST_ENTRY(_plugins_entry) entries;
} plugins_entry_t;

static SLIST_HEAD(_plugins_t_list, _plugins_entry) g_loaded_plugins = SLIST_HEAD_INITIALIZER(g_loaded_plugins);

int plugins_load(const char *path) {
	plugins_entry_t *entry = malloc(sizeof *entry);
	if (entry == NULL) {
		fprintf(stderr, "plugin: allocation failed for entry\n");
		return -1;
	}

	memset(entry, 0, sizeof *entry);
	dylib_t *library = &entry->library;

	//fprintf(stdout, "plugins: Loading '%s'... ", path);
	int ret = dylib_load(library, path);
	//fprintf(stdout, "%s.\n", ret < 0 ? "failed" : "ok");
	if (ret < 0) {
		free(entry);
		return -2;
	}

	*(void **)(&entry->plugin_loaded_fn) = dylib_get_symbol(library, "plugin_loaded");
	*(void **)(&entry->plugin_initialize_fn) = dylib_get_symbol(library, "plugin_initialize");
	*(void **)(&entry->plugin_shutdown_fn) = dylib_get_symbol(library, "plugin_shutdown");
	*(void **)(&entry->plugin_unloaded_fn) = dylib_get_symbol(library, "plugin_unloaded");

	// Only plugin_initialize_fn and plugin_shutdown_fn are required.
	if (entry->plugin_initialize_fn == NULL || entry->plugin_shutdown_fn == NULL) {
		fprintf(stderr, "plugins: %s is incompatible with this version.\n", path);
		dylib_unload(library);
		free(entry);
		return -3;
	}

	if (entry->plugin_loaded_fn != NULL) {
		const int loaded = entry->plugin_loaded_fn();
		if (loaded < 0) {
			fprintf(stderr, "plugins: plugin didn't load correctly\n");
			dylib_unload(library);
			free(entry);
			return -4;
		}
	}

	const pev_api_t *pev_api = pev_api_ptr();
	const int initialized = entry->plugin_initialize_fn(pev_api);
	if (initialized < 0) {
		fprintf(stderr, "plugins: plugin didn't initialize correctly\n");
		dylib_unload(library);
		free(entry);
		return -5;
	}

	SLIST_INSERT_HEAD(&g_loaded_plugins, entry, entries);
	return 0;
}

static void plugin_unload_without_removal(plugins_entry_t *entry) {
	dylib_t *library = &entry->library;

	entry->plugin_shutdown_fn();

	if (entry->plugin_unloaded_fn != NULL) {
		entry->plugin_unloaded_fn();
	}

	int ret = dylib_unload(library);
	if (ret < 0) {
		// TODO(jweyrich): What should we do?
	}
}

#if 0
static void plugin_unload(plugins_entry_t *entry) {
	plugin_unload_without_removal(entry);
	SLIST_REMOVE(&g_loaded_plugins, entry, _plugins_entry, entries);
	free(entry);
}
#endif

int plugins_load_all_from_directory(const char *path) {
	DIR *dir = opendir(path);
	if (dir == NULL) {
		fprintf(stderr, "plugins: could not open directory '%s' -- %s\n",
			path, strerror(errno));
		return -1;
	}

	long path_max = pathconf(path, _PC_PATH_MAX);
	char *relative_path = malloc(path_max);
	if (relative_path == NULL) {
		fprintf(stderr, "plugins: allocation failed for relative path\n");
		closedir(dir);
		return -2;
	}

	size_t load_count = 0;
	struct dirent *dir_entry;
	// print all the files and directories within directory

	// SECURITY: Don't use readdir_r because it will introduce a
	// race condition between the opendir and pathconf calls.
	// MORE: http://womble.decadent.org.uk/readdir_r-advisory.html
	// NOTE: readdir is not thread-safe.
	while ((dir_entry = readdir(dir)) != NULL) {

		switch (dir_entry->d_type) {
			default: // Unhandled
				break;

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
			case DT_UNKNOWN:
#endif
			case DT_REG: // Regular file
			{
				const char *filename = dir_entry->d_name;

				// TODO(jweyrich): Use macro conditions for each system: .so, .dylib, .dll
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
				const bool possible_plugin = pe_utils_str_ends_with(filename, ".so") != 0;
#elif defined(__APPLE__)
				const bool possible_plugin = pe_utils_str_ends_with(filename, ".dylib") != 0;
#elif defined(__CYGWIN__)
				const bool possible_plugin = pe_utils_str_ends_with(filename, ".dll") != 0;
#else
#error Not supported
#endif
				if (!possible_plugin)
					break;

				snprintf(relative_path, path_max, "%s/%s", path, filename);
				//printf("relative_path = %s\n", relative_path);

				int ret = plugins_load(relative_path);
				if (ret < 0) {
					free(relative_path);
					closedir(dir);
					return ret;
				}
				load_count++;
				break;
			}
			case DT_DIR: // Directory
				break;
		}
	}

	free(relative_path);
	closedir(dir);

	return load_count;
}

int plugins_load_all(pev_config_t *config) {
	return plugins_load_all_from_directory(config->plugins_path);
}

void plugins_unload_all(void) {
	while (!SLIST_EMPTY(&g_loaded_plugins)) {
		plugins_entry_t *entry = SLIST_FIRST(&g_loaded_plugins);
		plugin_unload_without_removal(entry);
		SLIST_REMOVE_HEAD(&g_loaded_plugins, entries);
		free(entry);
	}
}
