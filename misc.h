
#include <stdint.h>
#include <stdio.h>
#include "pe.h"
#include <openssl/evp.h>
#include <openssl/md5.h>

double calculate_entropy(const unsigned int counted_bytes[256], const size_t total_length);
double calculate_entropy_file(pe_ctx_t *ctx);
bool fpu_trick(pe_ctx_t *ctx);
int cpl_analysis(pe_ctx_t *ctx);
int get_cpl_analysis(pe_ctx_t *ctx);
int check_fake_entrypoint(pe_ctx_t *ctx);
const IMAGE_SECTION_HEADER *pe_check_fake_entrypoint(pe_ctx_t *ctx, uint32_t ep);

// TLS Functions
int get_tls_callback(pe_ctx_t *ctx);
int pe_get_tls_callbacks(pe_ctx_t *ctx);
uint32_t pe_get_tls_directory(pe_ctx_t *ctx);

