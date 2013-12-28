/*
	pev - the PE file analyzer toolkit

	Copyright (C) 2013 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef PEV_REGEX_H
#define PEV_REGEX_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcre.h>

typedef struct  {
	char *pattern;
	int options;
	pcre *regex;
	pcre_extra *extra;
	struct {
		const char *ptr;
		int offset;
	} error;
} regex_t;

regex_t *regex_alloc(void);
regex_t *regex_alloc_with_pattern(const char *pattern, int options);
void regex_free(regex_t *obj);
int regex_init(regex_t *obj);
int regex_init_with_pattern(regex_t *obj, const char *pattern, int options);
void regex_cleanup(regex_t *obj);
int regex_compile(regex_t *obj);
int regex_exec(regex_t *obj, const char *subject, int length, int startoffset, int options, int *ovector, int ovecsize);

regex_t *regex_alloc(void) {
	regex_t *obj = malloc(sizeof(regex_t));
	if (obj == NULL) {
		perror("malloc");
		return NULL;
	}

	int ret = regex_init(obj);
	if (ret < 0) {
		regex_free(obj);
		return NULL;
	}

	return obj;
}

regex_t *regex_alloc_with_pattern(const char *pattern, int options) {
	regex_t *obj = regex_alloc();
	if (obj == NULL)
		return NULL;

	int ret = regex_init_with_pattern(obj, pattern, options);
	if (ret < 0) {
		regex_free(obj);
		return NULL;
	}

	return obj;
}

void regex_free(regex_t *obj) {
	if (obj == NULL)
		return;

	regex_cleanup(obj);
	free(obj);
}

int regex_init(regex_t *obj) {
	if (obj == NULL)
		return -1;

	memset(obj, 0, sizeof(regex_t));

	return 0;
}

int regex_init_with_pattern(regex_t *obj, const char *pattern, int options) {
	if (obj == NULL)
		return -1;

	obj->pattern = strdup(pattern);
	if (obj->pattern == NULL) {
		perror("strdup");
		return -2;
	}

	obj->options = options;

	return 0;
}

void regex_cleanup(regex_t *obj) {
	if (obj == NULL)
		return;

	if (obj->pattern != NULL) {
		free(obj->pattern);
		obj->pattern = NULL;
	}

	if (obj->regex != NULL) {
		pcre_free(obj->regex);
		obj->regex = NULL;
	}

	if (obj->extra != NULL) {
		//pcre_free_study(obj->extra);
		pcre_free(obj->extra);
		obj->extra = NULL;
	}
}

int regex_compile(regex_t *obj) {
	if (obj == NULL)
		return -1;

	// If it was already compiled, deallocate it.
	if (obj->regex != NULL) {
		pcre_free(obj->regex);
		obj->regex = NULL;
	}

	pcre *compiled = pcre_compile(obj->pattern, obj->options,
		&obj->error.ptr, &obj->error.offset,
		NULL
	);

	if (compiled == NULL) {
		fprintf(stderr, "pcre_compile failed - %d, %s\n",
			obj->error.offset, obj->error.ptr);
		return -2;
	}

	obj->regex = compiled;

	return 0;
}

int regex_exec(regex_t *obj, const char *subject, int length, int startoffset, int options, int *ovector, int ovecsize) {
	if (obj == NULL)
		return -1;

	int ret = pcre_exec(obj->regex, obj->extra,
            subject, length, startoffset,
            options, ovector, ovecsize);

	if (ret >= 0) {
		obj->extra = pcre_study(obj->regex, options, &obj->error.ptr);
		if (obj->extra == NULL) {
			fprintf(stderr, "pcre_study failed - %s\n", obj->error.ptr);
			// We do not return an error because this is a recoverable error.
		}
	}

	return ret;
}

#endif
