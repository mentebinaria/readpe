/* vim :set ts=4 sw=4 sts=4 et : */
/*
    readpe - the PE file analyzer toolkit

    api.h - Readpe API that plugins can use to access internal functions.

    Copyright (C) 2012 - 2026 readpe authors

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
#ifndef READPE_API_H
#define READPE_API_H

#ifdef __cplusplus
extern "C" {
#endif

struct readpe_api;
struct readpe_output_api;

/* This is the api that is provided by readpe and thus contains symbols
 * and functions that plugins can call from the main executable.
 */
struct readpe_api {
    const unsigned int              version;
    const struct readpe_output_api *output;
};

struct readpe_api *readpe_api_ptr(void);

#ifdef __cplusplus
} // extern "C"
#endif
#endif // READPE_API_H

