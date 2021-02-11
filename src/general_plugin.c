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



// Register each function name of a given namespace in a hashtable
void general_plugin_register_function(char* namespace, char* func_name, void *func ) 
{
	ENTRY namespace_name = { namespace, NULL };
	ENTRY* namespace_found;
	ENTRY* dummy_entry;
	ENTRY function_entry = { func_name, func };

	hsearch_r(namespace_name, FIND, &namespace_found, &plugins_namespace);


	if (namespace_found) {
		struct hsearch_data* plugins_func = (struct hsearch_data*) namespace_found->data;
		hsearch_r(function_entry, ENTER, &dummy_entry, plugins_func);

	} else {

		ENTRY namespace_entry = { namespace, (void*) &plugins_functions };

		hsearch_r(function_entry, ENTER, &dummy_entry, &plugins_functions);
		dummy_entry = NULL;
	
		hsearch_r(namespace_entry, ENTER, &dummy_entry, &plugins_namespace);
	}
}


plugin_handle* get_plugin_handle(char* plugin_namespace) 
{
	ENTRY namespace_name = { plugin_namespace, NULL };
	ENTRY* namespace_found;

	hsearch_r(namespace_name, FIND, &namespace_found, &plugins_namespace);

	if (namespace_found) {
		plugin_handle* plugin = malloc(sizeof(plugin_handle*));
		plugin->plugins_functions = namespace_found->data;
		plugin->execute = execute_function;

		return plugin;
	}

	return (plugin_handle*) NULL;
}

// Execute a function from a given plugin_handle
int execute_function( char* func_name, void* data, void* p_handle ) 
{
	ENTRY search = { func_name, NULL };
	ENTRY* func_found;
	plugin_handle* handle = (plugin_handle*) p_handle;

	hsearch_r(search, FIND, &func_found, handle->plugins_functions);
	if (func_found) {
		( ( void(*) (void *) ) func_found->data) (data);
	}
}

// Build the general_plugin_api struct functions
general_plugin_api *general_plugin_api_ptr(void) {
	static general_plugin_api general_plugin_spec = {
		.general_plugin_register_function = general_plugin_register_function
	};

	hcreate_r(MAX_PLUGINS_NAMESPACE, &plugins_namespace);
	hcreate_r(MAX_PLUGINS_FUNCTIONS, &plugins_functions);

	return &general_plugin_spec;
}

