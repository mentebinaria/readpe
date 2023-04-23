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

#ifndef LIBPE_MACROS_H
#define LIBPE_MACROS_H

#ifdef __cplusplus
extern "C" {
#endif

#define LIBPE_PTR_ADD(p, o)						((void *)((char *)(p) + (o)))
#define LIBPE_SIZEOF_ARRAY(array)				(sizeof(array) / sizeof(array[0]))
#define LIBPE_SIZEOF_MEMBER(type, member)		sizeof(((type *)0)->member)

#define LIBPE_WARNING(msg) \
{ \
	fprintf(stderr, "WARNING: %s [at %s:%d]\n", msg, __FILE__, __LINE__); \
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif
