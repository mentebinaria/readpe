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
