#include "pe.h"
#include "error.h"

/*typedef enum {
	LIBPE_E_EXPORTS_OK = 0,
	LIBPE_E_EXPORTS_DIR,
	LIBPE_E_EXPORTS_VA,
	LIBPE_E_EXPORTS_CANT_READ_RVA,
	LIBPE_E_EXPORTS_CANT_READ_EXP,
	LIBPE_E_EXPORTS_FUNC_NEQ_NAMES
}pe_err_exports_e;*/

typedef struct {
	uint32_t addr;
	char *function_name;  // name of the function at that address
}exports_t;

typedef struct {
	pe_err_e err;
	exports_t* exports;
	int functions_count;
}pe_exports_t;

pe_exports_t get_exports(pe_ctx_t *ctx);
int get_exports_functions_count(pe_ctx_t *ctx);
void pe_dealloc_exports(pe_exports_t exports);
