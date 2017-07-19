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
