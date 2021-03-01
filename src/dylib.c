/* vim: set ts=4 sw=4 noet: */
/*
	The MIT License (MIT)

	Copyright (c) 2013, Jardel Weyrich <jweyrich at gmail dot com>

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

#include "dylib.h"
#include "common.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

// FIX: Don't need to export.
//inline const char *dylib_error(dylib_t *lib) {
//	  UNUSED(lib);
//	  return dlerror();
//}
#define dylib_error(...) dlerror()

int dylib_load(dylib_t *lib, const char *path) {

	// debug check sanitizer
	PEV_ASSERT(lib && path && *path);

	if (lib->handle) {
		PEV_WARN("Can't load library because it's already loaded: %s", lib->path);
		return -1;
	}

	lib->handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
	if (!lib->handle) {
		PEV_WARN("Failed to load library %s: %s", path, dylib_error(lib));
		return -1;
	}

	lib->path = pev_strdup(path);
	return 0;
}

int dylib_unload(dylib_t *lib) {
	PEV_ASSERT(lib);

	if (!lib->handle) {
		PEV_WARN("Can't unload library '%s' because it's not loaded", lib->path);
		return -1;
	}

	int ret = dlclose(lib->handle);
	if (ret != 0) {
		PEV_WARN("Failed to unload library %s: %s", lib->path, dylib_error(lib));
		return -1;
	}

	lib->handle = NULL;
	free(lib->path);
	lib->path = NULL;

	return 0;
}

void* dylib_get_symbol(dylib_t* lib, const char* symbol) {
	PEV_ASSERT(lib && symbol && *symbol);

	void* addr = dlsym(lib->handle, symbol);
	if (!addr)
		PEV_WARN("Symbol \"%s\" not found in \"%s\": %s", symbol, lib->path, dylib_error(lib));

	return addr;
}

int dylib_has_symbol(dylib_t *lib, const char *symbol) {
	return !!dylib_get_symbol(lib, symbol);
}