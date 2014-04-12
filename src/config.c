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
#include "utils.h" // from libpe
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslimits.h>
#include <pwd.h>
#include <unistd.h>

#define DEFAULT_CONFIG_PATH		".config/pev.conf"
#define DEFAULT_PLUGINS_PATH	"/usr/lib/pev/plugins"

static const char *g_plugins_path = DEFAULT_PLUGINS_PATH;

const char *pev_plugins_path(void) {
	return g_plugins_path;
}

static void pev_load_config_cb(const char *name, const char *value) {
	// FIXME memory leak
	if (!strcmp("plugins_dir", name))
		g_plugins_path = strdup(value);
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

int pev_load_config(void) {
	char buff[PATH_MAX];

	int ret = pe_is_file_readable("pev.conf");
	if (ret == LIBPE_E_OK) {
		return pe_load_config("pev.conf", pev_load_config_cb);
	}

	snprintf(buff, sizeof(buff), "%s/%s", get_homedir(), DEFAULT_CONFIG_PATH);
	ret = pe_is_file_readable(buff);

	if (ret == LIBPE_E_OK) {
		return pe_load_config(buff, pev_load_config_cb);
	}

	return -1;
}

