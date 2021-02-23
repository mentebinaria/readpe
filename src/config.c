/* vim: set ts=4 sw=4 noet: */
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

#include <libpe/utils.h>
#include <libpe/error.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "config.h"
#include "../include/common.h"

#if defined(__linux__)
	#include <linux/limits.h>	// FIXME: Why?
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__CYGWIN__)
	#include <limits.h>
#endif

#define DEFAULT_CONFIG_FILENAME "pev.conf"

#if defined(__CYGWIN__) // Set current directory as default
#define DEFAULT_CONFIG_PATH DEFAULT_CONFIG_FILENAME
#define DEFAULT_PLUGINS_PATH "plugins"
#else
#define DEFAULT_CONFIG_PATH ".config/pev/" DEFAULT_CONFIG_FILENAME
// PLUGINSDIR is defined via CPPFLAGS in the Makefile
#define DEFAULT_PLUGINS_PATH PLUGINSDIR
#endif

#ifndef PEV_VA_COPY
	#if (__STDC_VERSION__ >= 199901L) || defined(_MSC_VER)
		#define PEV_VA_COPY(dest, src) va_copy(dest, src)
	#else
		#define PEV_VA_COPY(dest, src) (dest) = (src)
	#endif
#endif

static bool _load_config_cb(pev_config_t * const config, const char *name, const char *value) {
	//fprintf(stderr, "DEBUG: %s=%s\n", name, value);

	if (!strcmp("plugins_dir", name)) {
		config->plugins_path = pev_strdup(value);
		return true;
	}

	return false;
}

// FIX: Now the lines of config can have any size!
static int _load_config_and_parse(pev_config_t * const config, const char *path, pev_config_parse_callback_t pev_cb) {
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
		return 0;

	if (ferror(fp))
	{
		pev_fclose(fp, false); // (on_exit = false) -> print only the warning
		return 0;
	}

	char *p, *line = NULL;
	size_t size = 0;

	while ( getline( &line, &size, fp ) != -1 )
	{
		// remove newline
		if ( p = strrchr( line, '\n' ) ) *p = 0;

		p = pe_utils_str_inplace_trim(line);

		// if not a comment line...
		if (*p != '#')
		{
			char *param = strtok(p, "=");
			char *value = strtok(NULL, "=");
			const char *trimmed_param = pe_utils_str_inplace_trim(param);
			const char *trimmed_value = pe_utils_str_inplace_trim(value);

			//fprintf(stderr, "DEBUG: '%s'='%s'\n", trimmed_param, trimmed_value);
			const bool processed = pev_cb(config, trimmed_param, trimmed_value);

			if (!processed && config->user_defined.parse_callback != NULL)
				config->user_defined.parse_callback(config->user_defined.data, trimmed_param, trimmed_value);
		}

		free( line );
		line = NULL;
		size = 0;
	}

	fclose(fp);

	return 1;
}

#ifdef USE_MY_ASPRINTF
int asprintf(char** ppstr, const char* fmt, ...)
{
	PEV_ASSERT(ppstr && fmt);

	va_list args;
	va_list args2;
	bool failed = false;

	va_start(args, fmt);

	PEV_VA_COPY(args2, args);
	int size = vsnprintf(NULL, 0, fmt, args2);
	va_end(args2);

	if (size < 0)
	{
		va_end(args);
		return -1;
	}

	if (*ppstr)
	{
		size_t len = strlen(*ppstr);
		if (len < (size_t)size)
		{
			char* temp = (char*) realloc(*ppstr, size + 1);

			if (!temp)
			{
				failed = true;
				free(*ppstr);
			}
			else
				*ppstr = temp;
		}
	}
	else
	{
		if (!(*ppstr = (char*) malloc(size + 1)))
			failed = true;
	}

	if (failed)
	{
		errno = ENOMEM;
		va_end(args);
		return -1;
	}

	int writted = vsprintf(*ppstr, fmt, args);
	PEV_ASSERT(writted == size);

	*(ppstr + size) = 0;
	va_end(args);

	return size;
}
#endif

// FIX: To avoid using fixed size PATH names we can use asprintf().
int pev_load_config(pev_config_t * const config) {
	char *buff;

	int ret = pe_utils_is_file_readable(DEFAULT_CONFIG_FILENAME);
	if (ret == LIBPE_E_OK)
		if ( ! _load_config_and_parse(config, DEFAULT_CONFIG_FILENAME, _load_config_cb) )
			return -1;

	// OBS: If asprintf isn't available to your system, use the definition above
	//		using -DUSE_MY_ASPRINTF at compile time.
	if ( asprintf(&buff, "%s/" DEFAULT_CONFIG_PATH, pe_utils_get_homedir()) < 0 )
		return -1;

	ret = pe_utils_is_file_readable(buff);
	if (ret == LIBPE_E_OK)
		if ( ! _load_config_and_parse(config, buff, _load_config_cb) )
		{
			free( buff );
			return -1;
		}

	free( buff );

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

	if ( config->user_defined.cleanup_callback &&
		 config->user_defined.data )
		config->user_defined.cleanup_callback(config->user_defined.data);

	free(config->plugins_path);
	config->plugins_path = NULL;
}
