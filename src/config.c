/*
	pev - the PE file analyzer toolkit

	config.c

	Copyright (C) 2013 - 2014 pev authors

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

#include "config.h"
#include <libpe/utils.h>
#include <libpe/error.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <linux/limits.h>
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__CYGWIN__)
#include <limits.h>
#endif

#define DEFAULT_CONFIG_FILENAME "pev.conf"

#if defined(__CYGWIN__) // Set current directory as default
#define DEFAULT_CONFIG_PATH DEFAULT_CONFIG_FILENAME
#define DEFAULT_PLUGINS_PATH "plugins"
#else
#define DEFAULT_CONFIG_PATH ".config/pev" DEFAULT_CONFIG_FILENAME
#define DEFAULT_PLUGINS_PATH PLUGINSDIR // PLUGINSDIR is defined via CPPFLAGS in the Makefile
#endif

static bool _load_config_cb(pev_config_t * const config, const char *name, const char *value) {
	//fprintf(stderr, "DEBUG: %s=%s\n", name, value);

	if (!strcmp("plugins_dir", name)) {
		config->plugins_path = strdup(value);
		return true;
	}

	return false;
}

static int _load_config_and_parse(pev_config_t * const config, const char *path, pev_config_parse_callback_t pev_cb) {
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	char line[1024];

	while (fgets(line, sizeof(line), fp) != NULL) {
		// comments
		if (*line == '#')
			continue;

		// remove newline
		for (size_t i=0; i < sizeof(line); i++) {
			if (line[i] == '\n' || i == sizeof(line) - 1) {
				line[i] = '\0';
				break;
			}
		}

		char *param = strtok(line, "=");
		char *value = strtok(NULL, "=");
		const char *trimmed_param = pe_utils_str_inplace_trim(param);
		const char *trimmed_value = pe_utils_str_inplace_trim(value);

		//fprintf(stderr, "DEBUG: '%s'='%s'\n", trimmed_param, trimmed_value);
		const bool processed = pev_cb(config, trimmed_param, trimmed_value);

		if (!processed && config->user_defined.parse_callback != NULL)
			config->user_defined.parse_callback(config->user_defined.data, trimmed_param, trimmed_value);
	}

	fclose(fp);

	return 0;
}

int pev_load_config(pev_config_t * const config) {
	char buff[PATH_MAX];

	int ret = pe_utils_is_file_readable(DEFAULT_CONFIG_FILENAME);
	if (ret == LIBPE_E_OK) {
		ret = _load_config_and_parse(config, DEFAULT_CONFIG_FILENAME, _load_config_cb);
		if (ret < 0)
			return ret;
	}

	snprintf(buff, sizeof(buff), "%s/%s", pe_utils_get_homedir(), DEFAULT_CONFIG_PATH);
	ret = pe_utils_is_file_readable(buff);

	if (ret == LIBPE_E_OK) {
		ret = _load_config_and_parse(config, buff, _load_config_cb);
		if (ret < 0)
			return ret;
	}

	//
	// Default values
	//
	if (config->plugins_path == NULL)
		config->plugins_path = strdup(DEFAULT_PLUGINS_PATH);

	return 0;
}

void pev_cleanup_config(pev_config_t * const config) {
	if (config == NULL)
		return;

	if (config->user_defined.data != NULL) {
		if (config->user_defined.cleanup_callback != NULL)
			config->user_defined.cleanup_callback(config->user_defined.data);
	}

	if (config->plugins_path != NULL) {
		free(config->plugins_path);
		config->plugins_path = NULL;
	}
}
