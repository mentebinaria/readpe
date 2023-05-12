/* vim :set ts=4 sw=4 sts=4 et : */
/*
    readpe - the PE file analyzer toolkit

    plugin.h - Plugin API that every plugin MUST implement.

    Copyright (C) 2012 - 2025 readpe authors

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
#ifndef READPE_PLUGIN_H
#define READPE_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

// enum readpe_plugin_type_id {
#define readpe_plugin_type_generic 0
#define readpe_plugin_type_output  1
// };

struct readpe_api;
struct readpe_output_api;

typedef int (*plugin_loaded_fn_t)(void);
typedef int (*plugin_initialize_fn_t)(const struct readpe_api *api);
typedef void (*plugin_shutdown_fn_t)(void);
typedef void (*plugin_unloaded_fn_t)(void);

/* This is the api that is provided by readpe and thus contains symbols
 * and functions that plugins can call from the main executable.
 */
struct readpe_api {
    struct readpe_output_api *output;
};

/* Every plugin shared object should export a structure like this.
 * The C standard does not allow for dynamic loading of functions
 * Hence why dylib_get_symbol does not return a void(*)(void) but a void*!
 *
 * Every plugin type shall include this struct as its first element.
 * This allows that the memory address pointing to the struct
 * is also pointing to the plugin type enum.
 * This can then be used to cast up a generic plugin back to
 * it's specific type if need should arise.
 */
struct readpe_plugin {
    int                    type_id;
    plugin_loaded_fn_t     loaded;
    plugin_initialize_fn_t initialize;
    plugin_shutdown_fn_t   shutdown;
    plugin_unloaded_fn_t   unloaded;
};

struct readpe_api *readpe_api_ptr(void);

#ifdef __cplusplus
} // extern "C"
#endif
#endif // READPE_PLUGIN_H

