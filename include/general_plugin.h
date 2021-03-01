/*
	pev - the PE file analyzer toolkit

	output_plugin.h - Symbols and APIs to be used by output plugins.

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

#pragma once

#include "plugin.h"
#include "common.h"
#include <stdlib.h>
#include <search.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum general plugins that can be loaded
#define MAX_PLUGINS_NAMESPACE 100
#define MAX_PLUGINS_FUNCTIONS 100
#define PLUGIN_SCAN_FUNCTION "plugin_scan"

// Namespace holding plugins names as key and plugins_functions(hsearch_data) as key 
// Hashtable holding <function_name, function>
struct hsearch_data plugins_namespace;

typedef struct _plugin_handle {
	struct hsearch_data* plugins_functions;
	int ( * execute ) (char *func_name, void* data, void* p_handle );
} plugin_handle;

plugin_handle* get_plugin_handle(char *namespace_name);
int execute_function( char* func_name, void* data, void* p_handle );

//
// Public API specific for general plugins
//
typedef struct _general_plugin_api {
	char * plugin_name;
	void ( * general_plugin_register_function ) ( char* namespace, char* func_name, int* func  );
	void ( * general_plugin_unregister_namespace ) ( char* namespace );

} general_plugin_api;

general_plugin_api *general_plugin_api_ptr(void);

void scan_plugins_run_scan();
void general_plugin_destroy_namespace();

#ifdef __cplusplus
}
#endif


