#include "yarascan.h"

#define PLUGIN_NAMESPACE "Yara"

#define OUTPUT_SCOPE_NAME "Yara"

// YARA_RULES_DIR are defined in plugins Makefile
#define YARA_PLUGIN_RULES YARA_RULES_DIR 

const struct _pev_api_t *pev_api;

const char* include_callback( const char* include_name,
			      const char* calling_rule_filename,
			      const char* calling_rule_namespace,
			      void* user_data)
{
	printf("Fixing include name from %s, include: %s\n", calling_rule_filename, include_name);

	return include_name;
	
}


void compiler_callback( int error_level,
			const char* file_name,
			int line_number,
			const YR_RULE* rule,
			const char* message,
			void* user_data)
{

	if (error_level == YARA_ERROR_LEVEL_ERROR) {

		yara_ctx.error = ERROR_COMPILER_LOAD_RULE;

	}
}

int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_RULE* rule_match = (YR_RULE*) message_data;
		pev_api->output(NULL, rule_match->identifier);
	}

	return EXIT_SUCCESS;
}

// pe_ctx_t*
int scan_mem(void* _pe_ctx)
{
	pe_ctx_t* pe_ctx = (pe_ctx_t*) _pe_ctx;
	if (yara_ctx.error != ERROR_NO_ERROR) return ERROR_COMPILER;
	int flags = SCAN_FLAGS_FAST_MODE;
	
	pev_api->output_open_scope(OUTPUT_SCOPE_NAME, OUTPUT_SCOPE_TYPE_ARRAY);
	yr_rules_scan_mem(yara_ctx.yr_rules, pe_ctx->map_addr, pe_ctx->map_size, flags, scan_callback, yara_ctx.user_data, 0);
	pev_api->output_close_scope();

	return EXIT_SUCCESS;
}


// Start libyara internal variables, create the compiler and load the sources
int load_rules() 
{
	yr_initialize();	
	if (yr_compiler_create(&yara_ctx.yr_compiler) != ERROR_SUCCESS) {
		return ERROR_COMPILER;
	}
	
	yr_compiler_set_callback(yara_ctx.yr_compiler, compiler_callback, yara_ctx.user_data);
	yr_compiler_set_include_callback(yara_ctx.yr_compiler, include_callback,NULL, yara_ctx.user_data);
	
	struct dirent* dir_entry;
	DIR* dir = opendir(YARA_PLUGIN_RULES);
	if (!dir) {
		return ERROR_DIR_NOT_FOUND;
	}

	char* full_path;
	int fd;
	int has_rules = false;
	while ( (dir_entry = readdir(dir)) != NULL ) {
		if (!strcmp(dir_entry->d_name, ".") || !strcmp(dir_entry->d_name, "..")) continue;

		if (!pe_utils_str_ends_with(dir_entry->d_name, "yar") &&
			!pe_utils_str_ends_with(dir_entry->d_name, "yr")  &&
			!pe_utils_str_ends_with(dir_entry->d_name, "yara")) continue;

		full_path = calloc(sizeof(char), strlen(dir_entry->d_name) + strlen(YARA_PLUGIN_RULES));
		
		if (asprintf(&full_path, "%s%s", YARA_PLUGIN_RULES, dir_entry->d_name) < 0) {
			PANIC_MEMORY("Allocating directory");
		}

		fd = open(full_path, O_RDONLY);
		if (!fd) {
			free(full_path);
			continue;
		}

		yr_compiler_add_fd(yara_ctx.yr_compiler, fd, NULL, full_path);

		free(full_path);
		close(fd);
	}

	if (yr_compiler_get_rules(yara_ctx.yr_compiler, &yara_ctx.yr_rules) != ERROR_SUCCESS) {
		PANIC_MEMORY();
	}

	yara_ctx.error = ERROR_NO_ERROR;

	return ERROR_SUCCESS;
}


void destroy_yara()
{
	if (yara_ctx.yr_compiler)
		yr_compiler_destroy(yara_ctx.yr_compiler);

	yr_finalize();
}

// Plugin functions

int plugin_initialize(const struct _pev_api_t *api)
{
	yr_initialize();
	pev_api = api;
	return 0;
}

void plugin_shutdown()
{

}


void plugin_unloaded()
{
	destroy_yara();
}

int plugin_loaded()
{
	return 0;
}

void plugin_scan(pe_ctx_t* pe) 
{
	if (load_rules() == ERROR_SUCCESS) {
		scan_mem(pe);
	}
}

 