/*
	pev - the PE file analyzer toolkit
	
	stack.c - A simple stack implementation compatible with C99.

	Copyright (C) 2014 pev authors

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

#pragma once

#include <stdint.h>

#define STACK_PASTE_2_(_1,_2)		_1 ## _2
#define STACK_PASTE_2(_1,_2)		STACK_PASTE_2_(_1, _2)

#if !defined(STACK_PREFIX)
#	define STACK_PREFIX				PEV_
#endif
#if !defined(STACK_ELEMENT_TYPE)
#	define STACK_ELEMENT_TYPE		int
#endif
#define STACK_TYPE 					STACK_PASTE_2(STACK_PREFIX, stack_t)
#define STACK_API(fnname)			STACK_PASTE_2(STACK_PREFIX, fnname)

// Use these macros! Don't call functions directly.
#define STACK_ALLOC(capacity)				STACK_API(stack_alloc)(capacity)
#define STACK_DEALLOC(stack_ptr)			STACK_API(stack_dealloc)(stack_ptr)
#define STACK_COUNT(stack_ptr)				STACK_API(stack_count)(stack_ptr)
#define STACK_GROW(stack_ptr, capacity)		STACK_API(stack_grow)(stack_ptr, capacity)
#define STACK_PUSH(stack_ptr, element)		STACK_API(stack_push)(stack_ptr, element)
#define STACK_POP(stack_ptr, element_ptr)	STACK_API(stack_pop)(stack_ptr, element_ptr)

typedef struct {
	uint16_t capacity;
	uint16_t used;
	STACK_ELEMENT_TYPE *elements;
} STACK_TYPE;

static STACK_TYPE *STACK_API(stack_alloc)(uint16_t capacity);
static void STACK_API(stack_dealloc)(STACK_TYPE *stack);
static uint16_t STACK_API(stack_count)(STACK_TYPE *stack);
static int STACK_API(stack_grow)(STACK_TYPE *stack, uint16_t capacity);
static int STACK_API(stack_push)(STACK_TYPE *stack, STACK_ELEMENT_TYPE element);
static int STACK_API(stack_pop)(STACK_TYPE *stack, STACK_ELEMENT_TYPE *element);

// ----------------------------------------------------------------------------

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

STACK_TYPE * STACK_API(stack_alloc)(uint16_t capacity) {
	STACK_TYPE *stack = malloc(sizeof(STACK_TYPE));
	if (stack == NULL) {
		fprintf(stderr, "stack: failed to allocate\n");
		return NULL;
	}

	memset(stack, 0, sizeof(*stack));

	if (capacity > 0) {
		int ret = STACK_API(stack_grow)(stack, capacity);
		if (ret < 0) {
			STACK_API(stack_dealloc)(stack);
			return NULL;
		}
	}

	return stack;
}

void STACK_API(stack_dealloc)(STACK_TYPE *stack) {
	assert(stack != NULL);

	if (stack == NULL) {
		fprintf(stderr, "stack: attempt to deallocate NULL stack\n");
		return;
	}

	if (stack->elements != NULL)
		free(stack->elements);

	//memset(stack, 0, sizeof(*stack));
	free(stack);
}

uint16_t STACK_API(stack_count)(STACK_TYPE *stack) {
	assert(stack != NULL);
	return stack->used;
}

int STACK_API(stack_grow)(STACK_TYPE *stack, uint16_t capacity) {
	assert(stack != NULL);
	assert(capacity > stack->capacity);

	if (capacity <= stack->capacity) {
		fprintf(stderr, "stack: capacity cannot be decreased\n");
		return -1;
	}

	const size_t element_size = sizeof(STACK_ELEMENT_TYPE);
	const size_t new_size = capacity * element_size;
	
	STACK_ELEMENT_TYPE *temp = realloc(stack->elements, new_size);
	if (temp == NULL) {
		fprintf(stderr, "stack: failed to allocate requested capacity\n");
		return -2;
	}

	stack->elements = temp;
	stack->capacity = capacity;

	return 0;
}

int STACK_API(stack_push)(STACK_TYPE *stack, STACK_ELEMENT_TYPE element) {
	assert(stack != NULL);
	
	// Stack is full?
	if (stack->used >= stack->capacity) {
		fprintf(stderr, "stack: stack is full - failed to push\n");
		return -1;
	}

	stack->elements[stack->used++] = element;

	return 0;
}

int STACK_API(stack_pop)(STACK_TYPE *stack, STACK_ELEMENT_TYPE *element) {
	assert(stack != NULL);

	// Stack is empty?
	if (stack->used == 0) {
		fprintf(stderr, "stack: stack is empty - failed to pop\n");
		return -1;
	}

	if (element != NULL) {
		*element = stack->elements[--stack->used];
	}

	return 0;
}
