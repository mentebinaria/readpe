/*
	pev - the PE file analyzer toolkit

	pev_api.h - Symbols and APIs to be used by all plugins.

	Copyright (C) 2014 pev authors

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

#ifdef __cplusplus
extern "C" {
#endif

struct _output_plugin_api; // from output_plugin.h

typedef struct _pev_api_t {
	struct _output_plugin_api *output;
} pev_api_t;

pev_api_t *pev_api_ptr(void);

#ifdef __cplusplus
} //extern "C"
#endif


