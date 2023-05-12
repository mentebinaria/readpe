/* vim: set ts=4 sw=4 noet: */
/*
	readpe - the PE file analyzer toolkit

	main.h - main executable entry

	Copyright (C) 2023 readpe authors

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

#include <stdbool.h>

int pedis(int argc, char *argv[]);
int pehash(int argc, char *argv[]);
int peldd(int argc, char *argv[]);
int pepack(int argc, char *argv[]);
int peres(int argc, char *argv[]);
int pescan(int argc, char *argv[]);
int pesec(int argc, char *argv[]);
int pestr(int argc, char *argv[]);

int ofs2rva(int argc, char *argv[]);
int rva2ofs(int argc, char *argv[]);

int _main(int argc, char *argv[]);

typedef struct g_readpe_settings {
	char * format;
	// bool help;
	bool list;
	bool verbose;
	bool file_version;

	bool res_info;
	bool res_statistics;
	bool res_tree;

	int str_offset;
	int str_section;
	int str_min_length;

	void * cert_out;
	void * cert_format;

	char * section_name;
	unsigned int section_index;

	bool all;
} readpe_settings_t;

