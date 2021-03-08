/*
	pev - the PE file analyzer toolkit

	yarascan.h - Scan in memory PE files using libyara.

	Copyright (C) 2013 - 2020 pev authors

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

#ifdef __cplusplus
extern "C" {
#endif
#include "common.h"
#include "pev_api.h"
#include "general_plugin.h"

#include <stdio.h>
#include <yara.h>
#include <dirent.h>

#include <unistd.h>
#include <fcntl.h>

#define MAX_MSG 256

#define PANIC_MEMORY(blame) \
	fprintf(stderr, "fatal: memory exhausted ("blame")\n"); \
	yr_finalize();\
	exit(-1);\

typedef enum yara_erros {
	ERROR_COMPILER = -1,
	ERROR_COMPILER_LOAD_RULE = -2,
	ERROR_DIR_NOT_FOUND = -3,
	ERROR_COMPILER_LOAD_FILE = -4,
	ERROR_NO_ERROR = -5,
	ERROR_FILE_ACCESS = -6
} yr_error;


typedef struct _yara_context {
	YR_COMPILER* yr_compiler;
	YR_RULES* yr_rules;
	void* user_data;
	yr_error error;
	int print_fmt;
	char* rule_path;
} yara_context;

yara_context yara_ctx;

void compiler_callback( int error_level,
			const char* file_name,
			int line_number,
			const YR_RULE* rule,
			const char* message,
			void* user_data);

int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data);


void scan_pe(pe_ctx_t* ctx, void* scan_callback);
int start_yara(const char* rule_path, void* compiler_callback);
void destroy_yara();

#ifdef __cplusplus
} // closes extern C
#endif



