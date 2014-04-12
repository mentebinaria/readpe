/*
	The MIT License (MIT)

	Copyright (c) 2014, Jardel Weyrich <jweyrich at gmail dot com>

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

#include "plugins.h"
#include "plugin.h"
#include "dylib.h"
#include "common.h"
#include "compat/sys/queue.h"
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include "config.h"

// TODO(jweyrich): Move to a proper translation unit.
int str_ends_with(const char *str, const char *suffix) {
	if (str == NULL || suffix == NULL)
		return 0;

	size_t len_str = strlen(str);
	size_t len_suffix = strlen(suffix);
	if (len_suffix > len_str)
		return 0;

	return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

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

	const int initialized = entry->plugin_initialize_fn();
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
			case DT_REG: // Regular file
			{
				const char *filename = dir_entry->d_name;

				// TODO(jweyrich): Use macro conditions for each system: .so, .dylib, .dll
#if defined(__linux__)
				const bool possible_plugin = str_ends_with(filename, ".so") != 0;
#elif defined(__APPLE__)
				const bool possible_plugin = str_ends_with(filename, ".dylib") != 0;
#elif defined(__CYGWIN__)
				const bool possible_plugin = str_ends_with(filename, ".dll") != 0;
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

int plugins_load_all(void) {
	const char *plugins_path = pev_plugins_path();
	return plugins_load_all_from_directory(plugins_path);
}

void plugins_unload_all(void) {
	while (!SLIST_EMPTY(&g_loaded_plugins)) {
		plugins_entry_t *entry = SLIST_FIRST(&g_loaded_plugins);
		plugin_unload_without_removal(entry);
		SLIST_REMOVE_HEAD(&g_loaded_plugins, entries);
		free(entry);
	}
}
