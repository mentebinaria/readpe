/*
	pev - the PE file analyzer toolkit

	plugins.h - Symbols and definitions for the plugins subsystem.

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
*/

#pragma once

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

int plugins_load(const char *path);
int plugins_load_all(pev_config_t *config);
int plugins_load_all_from_directory(const char *path);
void plugins_unload_all(void);

#ifdef __cplusplus
}
#endif
