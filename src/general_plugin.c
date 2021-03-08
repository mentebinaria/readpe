/*
	pev - the PE file analyzer toolkit

	output_plugin.c - Symbols and APIs to be used by output plugins.

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

#include "general_plugin.h"

// Run all plugins that exports a scan function
void scan_plugins_run_scan(pe_ctx_t* pe_ctx)
{
	plugins_entry_t* entry = get_plugins_entry();
	// Overwrite current stdder value, dylib by default use stderr to warning if a symbol is not exported
	// In our case, we only want a plugin that exports "scan_pe" function
	FILE* _stderr = stderr;
	
	while (entry != NULL) {
		stderr = stdin;
		void ( * scan_pe ) = dylib_get_symbol(&entry->library, PLUGIN_SCAN_FUNCTION);
		stderr = _stderr;

		if (scan_pe) {
			( (void(*) () ) scan_pe)(pe_ctx);
		}

		entry = SLIST_NEXT(entry, entries);
	}

}

// Build the general_plugin_api struct functions
general_plugin_api *general_plugin_api_ptr(void) {
	static general_plugin_api general_plugin_spec;
	
	return &general_plugin_spec;
}

