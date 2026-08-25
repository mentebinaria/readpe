/* vim: set ts=4 sw=4 noet: */
/*
        readpe - the PE file analyzer toolkit

        Copyright (C) 2025 - 2026 readpe authors

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
#ifndef READPE_SETTINGS_H
#define READPE_SETTINGS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct readpe_settings_certificates {
    void *output_path;
    void *format;
};

struct readpe_settings_resource {
    bool info;
    bool names;
    bool statistics;
    bool tree;
};

struct readpe_settings_section {
    char        *name;
    unsigned int index;
};

struct readpe_settings_string {
    int min_length;
    int offset;
    int section;
};

struct readpe_settings {
    char *plugins_path;
    char *format;

    bool all;
    bool file_version;
    bool list;
    bool verbose;

    int mode;
    int context;

    struct readpe_settings_certificates *certificates;
    struct readpe_settings_resource     *resource;
    struct readpe_settings_section      *section;
    struct readpe_settings_string       *string;

    // TODO: Add functionality
    // Plugins should be able to register a settings struct
    void *plugins[];
};

// Plugins should use these so changes to the structs don't lead to page errors
char *readpe_get_plugins_path(void);
char *readpe_get_format(void);
bool  readpe_get_all(void);
bool  readpe_get_file_version(void);
bool  readpe_get_list(void);
bool  readpe_get_verbose(void);
int   readpe_get_mode(void);
int   readpe_get_context(void);

void *readpe_get_certificates_output_path(void);
void *readpe_get_certificates_format(void);

bool readpe_get_resource_info_enabled(void);
bool readpe_get_resource_names_enabled(void);
bool readpe_get_resource_statistics_enabled(void);
bool readpe_get_resource_tree_enabled(void);

char        *readpe_get_section_name(void);
unsigned int readpe_get_section_index(void);

int readpe_get_string_min_length(void);
int readpe_get_string_offset(void);
int readpe_get_string_section(void);

void readpe_set_all(bool all);

#ifdef __cplusplus
} // extern "C"
#endif

#endif

