/*
	pev - the PE file analyzer toolkit

	config.c

	Copyright (C) 2013 - 2014 pev authors

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

#include "config.h"
#include "error.h" // from libpe
#include "utils.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <linux/limits.h>
#elif defined(__APPLE__)
#include <sys/syslimits.h>
#elif defined(__CYGWIN__)
#include <limits.h>
#endif
#include <pwd.h>
#include <unistd.h>

#define DEFAULT_CONFIG_FILENAME	"pev.conf"

#if defined(__CYGWIN__) // Set current directory as default
#define DEFAULT_CONFIG_PATH		DEFAULT_CONFIG_FILENAME
#define DEFAULT_PLUGINS_PATH	"plugins"
#else
#define DEFAULT_CONFIG_PATH		".config/" DEFAULT_CONFIG_FILENAME
#define DEFAULT_PLUGINS_PATH	"/usr/lib/pev/plugins"
#endif

static const char *g_plugins_path = NULL;

const char *pev_plugins_path(void) {
	if (g_plugins_path == NULL)
		g_plugins_path = strdup(DEFAULT_PLUGINS_PATH);
	return g_plugins_path;
}

// IMPORTANT: This is not thread-safe - not reentrant.
static const char *get_homedir(void) {
	const char *homedir = getenv("HOME");
	if (homedir != NULL)
		return homedir;

	errno = 0;
	struct passwd *pwd = getpwuid(getuid());

	return pwd == NULL ? NULL : pwd->pw_dir;
}

static void pev_load_config_cb(const char *name, const char *value) {
	//printf("%s=%s\n", name, value);
	if (!strcmp("plugins_dir", name)) {
		// FIXME memory leak
		g_plugins_path = strdup(value);
	}
}

int pev_load_config(void) {
	char buff[PATH_MAX];

	int ret = utils_is_file_readable(DEFAULT_CONFIG_FILENAME);
	if (ret == LIBPE_E_OK) {
		return utils_load_config(DEFAULT_CONFIG_FILENAME, pev_load_config_cb);
	}

	snprintf(buff, sizeof(buff), "%s/%s", get_homedir(), DEFAULT_CONFIG_PATH);
	ret = utils_is_file_readable(buff);

	if (ret == LIBPE_E_OK) {
		return utils_load_config(buff, pev_load_config_cb);
	}

	return -1;
}
