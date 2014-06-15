/*
	stack.h - A simple stack implementation compatible with C99.

	The MIT License (MIT)

	Copyright (c) 2013, Jardel Weyrich <jweyrich at gmail dot com>

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

#pragma once

#include <stdint.h>

#define STACK_PASTE_2_(_1,_2)		_1 ## _2
#define STACK_PASTE_2(_1,_2)		STACK_PASTE_2_(_1, _2)

#if !defined(STACK_PREFIX)
#	define STACK_PREFIX				PEV_
#endif
#if !defined(STACK_ELEMENT_TYPE)
#	define STACK_ELEMENT_TYPE		void *
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
#define STACK_PEEK(stack_ptr, element_ptr)	STACK_API(stack_peek)(stack_ptr, element_ptr)

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
static int STACK_API(stack_peek)(STACK_TYPE *stack, STACK_ELEMENT_TYPE *element);

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
		// TODO(jweyrich): We could call `stack_grow` instead of failing miserably. Make this behavior adjustable?
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

int STACK_API(stack_peek)(STACK_TYPE *stack, STACK_ELEMENT_TYPE *element) {
	assert(stack != NULL);

	// Stack is empty?
	if (stack->used == 0) {
		fprintf(stderr, "stack: stack is empty - failed to peek\n");
		return -1;
	}

	if (element != NULL) {
		*element = stack->elements[stack->used - 1];
	}

	return 0;
}
