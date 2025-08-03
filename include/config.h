/* vim: set ts=4 sw=4 noet: */
/*
	pev - the PE file analyzer toolkit

	config.h

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

#pragma once

#include <stdbool.h>

struct _pev_config_t; // Forward declaration.
typedef bool (*pev_config_parse_callback_t)(struct _pev_config_t * const config, const char *name, const char *value);
typedef void (*pev_config_cleanup_callback_t)(void *data);

typedef struct _pev_config_t {
	char *plugins_path;
	struct {
		pev_config_parse_callback_t parse_callback;
		pev_config_cleanup_callback_t cleanup_callback;
		void *data;
	} user_defined;
} pev_config_t;

const char *pev_plugins_path(void);

int pev_load_config(pev_config_t * const config);
void pev_cleanup_config(pev_config_t * const config);

#ifdef USE_MY_ASPRINTF
int asprintf( char **, char *, ... );
#endif
