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
*/

#include "config.h"
#include "error.h" // from libpe
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <linux/limits.h>
#elif defined(__NetBSD__)
#include <limits.h>
#elif defined(__APPLE__)
#include <sys/syslimits.h>
#elif defined(__CYGWIN__)
#include <limits.h>
#endif

#define DEFAULT_CONFIG_FILENAME "pev.conf"

#if defined(__CYGWIN__) // Set current directory as default
#define DEFAULT_CONFIG_PATH DEFAULT_CONFIG_FILENAME
#define DEFAULT_PLUGINS_PATH "plugins"
#else
#define DEFAULT_CONFIG_PATH ".config/pev" DEFAULT_CONFIG_FILENAME
#define DEFAULT_PLUGINS_PATH "/usr/local/lib/pev/plugins"
#endif

static bool _load_config_cb(pev_config_t * const config, const char *name, const char *value) {
	//printf("%s=%s\n", name, value);

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
		const char *trimmed_param = utils_str_inplace_trim(param);
		const char *trimmed_value = utils_str_inplace_trim(value);

		//printf("DEBUG: '%s'='%s'\n", trimmed_param, trimmed_value);
		const bool processed = pev_cb(config, trimmed_param, trimmed_value);

		if (!processed && config->user_defined.parse_callback != NULL)
			config->user_defined.parse_callback(config->user_defined.data, trimmed_param, trimmed_value);
	}

	fclose(fp);

	return 0;
}

int pev_load_config(pev_config_t * const config) {
	char buff[PATH_MAX];

	int ret = utils_is_file_readable(DEFAULT_CONFIG_FILENAME);
	if (ret == LIBPE_E_OK) {
		ret = _load_config_and_parse(config, DEFAULT_CONFIG_FILENAME, _load_config_cb);
		if (ret < 0)
			return ret;
	}

	snprintf(buff, sizeof(buff), "%s/%s", utils_get_homedir(), DEFAULT_CONFIG_PATH);
	ret = utils_is_file_readable(buff);

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
