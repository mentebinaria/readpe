/*
	pev - the PE file analyzer toolkit

	plugin.h - Plugin API that every plugin MUST implement.

	Copyright (C) 2012 - 2014 pev authors

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

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _pev_api_t;

typedef int (*plugin_loaded_fn_t)(void);
typedef int (*plugin_initialize_fn_t)(const struct _pev_api_t *api);
typedef void (*plugin_shutdown_fn_t)(void);
typedef void (*plugin_unloaded_fn_t)(void);

int plugin_loaded(void);
int plugin_initialize(const struct _pev_api_t *api);
void plugin_shutdown(void);
void plugin_unloaded(void);

#ifdef __cplusplus
} //extern "C"
#endif
