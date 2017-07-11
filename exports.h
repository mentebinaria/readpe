#include <stdint.h>
#include <stdio.h>
#include "pe.h"


typedef struct {
	char *addr;
	char *function_name;
}exports;

exports *get_exports(pe_ctx_t *ctx);
int get_exports_functions_count(pe_ctx_t *ctx);

