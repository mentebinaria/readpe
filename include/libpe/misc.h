/*
    libpe - the PE library

    Copyright (C) 2010 - 2017 libpe authors
    
    This file is part of libpe.

    libpe is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libpe is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libpe.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef LIBPE_MISC
#define LIBPE_MISC

#include "pe.h"

#ifdef __cplusplus
extern "C" {
#endif

double pe_calculate_entropy_file(pe_ctx_t *ctx);
bool pe_fpu_trick(pe_ctx_t *ctx);
int pe_get_cpl_analysis(pe_ctx_t *ctx);
int pe_has_fake_entrypoint(pe_ctx_t *ctx);

// TLS Functions
int pe_get_tls_callback(pe_ctx_t *ctx);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
