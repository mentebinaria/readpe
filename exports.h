#ifndef LIBPE_EXPORTS
#define LIBPE_EXPORTS

#ifdef __cplusplus
extern "C" {
#endif

#include "pe.h"
#include "error.h"

	typedef struct {
		uint32_t addr;
		char *function_name;	// name of the function at that address
	}exports_t;

	typedef struct {
		pe_err_e err;
		exports_t* exports;
		int functions_count;
	}pe_exports_t;

	pe_exports_t get_exports(pe_ctx_t *ctx);
	// Deallocation Function
	void pe_dealloc_exports(pe_exports_t exports);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
