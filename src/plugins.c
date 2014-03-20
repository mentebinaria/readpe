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

// static int plugin_registered(const char *name) {
// 	printf("Plugin registered: %s\n", name);
// }

static const char *g_libraries[] = {
	"src/plugins/csv.dylib",
	"src/plugins/html.dylib",
	"src/plugins/text.dylib",
	"src/plugins/xml.dylib"
};

typedef struct _plugins_entry {
	dylib_t library;
	plugin_loaded_fn_t plugin_loaded_fn;
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

	entry->plugin_loaded_fn = (plugin_loaded_fn_t)dylib_get_symbol(library, "plugin_loaded");
	entry->plugin_unloaded_fn = (plugin_unloaded_fn_t)dylib_get_symbol(library, "plugin_unloaded");
	if (entry->plugin_loaded_fn == NULL || entry->plugin_unloaded_fn == NULL) {
		fprintf(stderr, "plugins: incompatible library?\n");
		dylib_unload(library);
		free(entry);
		return -3;
	}

	int loaded = entry->plugin_loaded_fn();
	if (loaded < 0) {
		fprintf(stderr, "plugins: plugin didn't load correctly\n");
		dylib_unload(library);
		return -4;
	}

	SLIST_INSERT_HEAD(&g_loaded_plugins, entry, entries);
	return 0;
}

static void plugin_unload_without_removal(plugins_entry_t *entry) {
	dylib_t *library = &entry->library;

	entry->plugin_unloaded_fn();

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

int plugins_load_all(void) {
	size_t load_count = 0;
	for (size_t i = 0; i < (sizeof(g_libraries) / sizeof(g_libraries[0])); i++) {
		const char *path = g_libraries[i];
		int ret = plugins_load(path);
		if (ret < 0)
			return ret;
		load_count++;
	}
	
	return load_count;
}

void plugins_unload_all(void) {
	while (!SLIST_EMPTY(&g_loaded_plugins)) {
		plugins_entry_t *entry = SLIST_FIRST(&g_loaded_plugins);
		plugin_unload_without_removal(entry);
		SLIST_REMOVE_HEAD(&g_loaded_plugins, entries);
		free(entry);
	}
}
