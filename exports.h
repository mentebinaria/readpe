#include "pe.h"


typedef struct {
	uint32_t addr;
	char *function_name;  // name of the function at that address
}exports_t;

int get_exports(pe_ctx_t *ctx, exports_t *output);
int get_exports_functions_count(pe_ctx_t *ctx);

