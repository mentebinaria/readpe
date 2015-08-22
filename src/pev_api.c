/*
	pev - the PE file analyzer toolkit

	pev_api.c - Symbols and APIs to be used by all plugins.

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

#include "pev_api.h"
#include "output_plugin.h"
#include <stdbool.h>
#include <string.h>

pev_api_t *pev_api_ptr(void) {
	static bool initialized = false;
	static pev_api_t api;

	if (!initialized) {
		initialized = true;
		memset(&api, 0, sizeof(api));
		api.output = output_plugin_api_ptr();
	}

	return &api;
}
