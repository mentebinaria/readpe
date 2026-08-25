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
#ifndef READPE_MODES_H
#define READPE_MODES_H

#ifdef __cplusplus
extern "C" {
#endif

enum MODES {
    MODE_BASE = 0,

    MODE_START = 256,
    MODE_HEADERS,
    MODE_HEADERS_DOS,
    MODE_HEADERS_COFF,
    MODE_HEADERS_OPTIONAL,
    MODE_DIRECTORIES,
    MODE_EXPORTS,
    MODE_IMPORTS,
    MODE_RESOURCES,
    // MODE_EXCEPTIONS,
    MODE_CERTIFICATES, // not part of image
    // MODE_BASE_RELOCATIONS,
    // MODE_DEBUG,
    // MODE_ARCHITECTURE,
    // MODE_GLOBAL_PTR,
    // MODE_TLS,
    // MODE_LOAD_CONFIGS,
    // MODE_BOUND_IMPORT,
    // MODE_IAT,
    // MODE_DELAY_IMPORT_DESCRIPTOR,
    // MODE_CLR_RUNTIME_HEADER,
    MODE_SECURITY, // security/features
    MODE_SECTIONS,
    MODE_SECTION,

    COMMAND_START,
    COMMAND_SCAN,
    COMMAND_EXTRACT,
    COMMAND_HASH,
    // COMMAND_HASH_MD5,
    // COMMAND_HASH_SHA1,
    // COMMAND_HASH_SHA256,
    // COMMAND_HASH_SSDEEP,
    // COMMAND_HASH_IMPHASH,
    COMMAND_STRINGS,
    // MODE_STRINGS_ASCII,
    // MODE_STRINGS_UNICODE,

    // COMMAND_DISASSAMBLE = 100000,
    // COMMAND_PACK,
    // COMMAND_ADDRESSING_RELATIVE,
    // COMMAND_ADDRESSING_OFFSET,
    COMMAND_END
};

#ifdef __cplusplus
} // extern "C"
#endif

#endif

