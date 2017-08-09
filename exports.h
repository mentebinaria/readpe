#ifndef LIBPE_EXPORTS
#define LIBPE_EXPORTS

#ifdef __cplusplus
extern "C" {
#endif

#include "pe.h"
#include "error.h"

typedef struct {
	uint32_t addr;
	char *name;	// name of the function at that address
} pe_exported_function_t;

typedef struct {
	pe_err_e err;
	uint32_t functions_count;
	pe_exported_function_t *functions; // array of exported functions
} pe_exports_t;

pe_exports_t pe_get_exports(pe_ctx_t *ctx);
void pe_dealloc_exports(pe_exports_t exports);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
