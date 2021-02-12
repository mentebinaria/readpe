#include "yarascan.h"

#define PLUGIN_NAMESPACE "Yara"
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

}

int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_RULE* rule_match = (YR_RULE*) message_data;

		printf("Rule_match %s\n", rule_match->identifier);
	}
}

// pe_ctx_t*
int scan_mem(void* _pe_ctx)
{
	pe_ctx_t* pe_ctx = (pe_ctx_t*) _pe_ctx;

	if (yara_ctx.error != ERROR_NO_ERROR) return;
	int flags = SCAN_FLAGS_FAST_MODE;

	output_open_scope("Yara", OUTPUT_SCOPE_TYPE_ARRAY);
	int err = yr_rules_scan_mem(yara_ctx.yr_rules, pe_ctx->map_addr, pe_ctx->map_size, flags, scan_callback, yara_ctx.user_data, 0);
	//output_close_scope();
}


// Start libyara internal variables, create the compiler and load the sources
int load_rules(void* rule) 
{
	char* rule_path = (char*) rule;
	yr_initialize();	
	if (yr_compiler_create(&yara_ctx.yr_compiler) != ERROR_SUCCESS) {
		yr_finalize();
		return ERROR_COMPILER;
	}

	if (access(rule_path, F_OK) < 0) {
		yr_finalize();
		return ERROR_FILE_ACCESS;
	}

	int rule_fd = open(rule_path, O_RDONLY);
	
	yr_compiler_set_callback(yara_ctx.yr_compiler, compiler_callback, yara_ctx.user_data);
	yr_compiler_set_include_callback(yara_ctx.yr_compiler, include_callback,NULL, yara_ctx.user_data);

	if (yr_compiler_add_fd(yara_ctx.yr_compiler, rule_fd, NULL, rule_path) != 0) {
		yr_finalize();
	} else {
		yara_ctx.error = ERROR_NO_ERROR;
		if (yr_compiler_get_rules(yara_ctx.yr_compiler, &yara_ctx.yr_rules) != ERROR_SUCCESS) {
			fprintf(stderr, "fatal: memory exhausted (Yara scan rule)\n");
			exit(-1);
		}
	}
	
	close(rule_fd);

	return ERROR_SUCCESS;
}


void destroy_yara()
{
	if (yara_ctx.yr_compiler)
		yr_compiler_destroy(yara_ctx.yr_compiler);
	
	yr_finalize();
}



void say_hello(void)
{
	puts("Hello");
}

void say_world(void) 
{
	puts("world");
}

// Plugin functions

int plugin_initialize(const struct _pev_api_t *api)
{
	yr_initialize();
	pev_api = api;
	pev_api->plugin->general_plugin_register_function(PLUGIN_NAMESPACE, "load_rule", load_rules);
	pev_api->plugin->general_plugin_register_function(PLUGIN_NAMESPACE, "yara_scan_mem", scan_mem);
//	pev_api->plugin->general_plugin_register_function(PLUGIN_NAMESPACE, "say_world", say_world);
	return 0;
}

void plugin_shutdown()
{
	yr_initialize();
}


void plugin_unloaded()
{
	pev_api->plugin->general_plugin_unregister_namespace(PLUGIN_NAMESPACE);
	yr_initialize();
}

int plugin_loaded()
{
	return 0;
}

 