/* vim: set ts=4 sw=4 noet: */
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

#include "pev_api.h"
#include "output_plugin.h"
#include "general_plugin.h"
#include <stdbool.h>
#include <string.h>

pev_api_t *pev_api_ptr(void) {
	static bool initialized = false;
	static pev_api_t api;		// Garanteed to be zeroed.

	if (!initialized) {
		initialized = true;
		memset(&api, 0, sizeof(api));
		api.output_plugin = output_plugin_api_ptr();
		api.plugin = general_plugin_api_ptr();

		api.output_open_document = output_open_document;
		api.output_close_document = output_close_document;
		api.output_open_scope = output_open_scope;
		api.output_close_scope = output_close_scope;
		api.output = output;
		api.output_keyval = output_keyval;

	}

	return &api;
}
