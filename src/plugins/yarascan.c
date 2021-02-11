#include "yarascan.h"

#define PLUGIN_NAMESPACE "Yara"

const char* include_callback( const char* include_name,
			      const char* calling_rule_filename,
			      const char* calling_rule_namespace,
			      void* user_data)
{
	printf("Fixing include name from %s, include: %s\n", calling_rule_filename, include_name);

	return include_name;
	
}


void scan_mem(void *data, size_t size, void *scan_callback)
{
	if (yara_ctx.error != ERROR_NO_ERROR) return;
	int flags = SCAN_FLAGS_FAST_MODE;

	output_open_scope("Yara", OUTPUT_SCOPE_TYPE_ARRAY);
	int err = yr_rules_scan_mem(yara_ctx.yr_rules, data, size, flags, scan_callback, yara_ctx.user_data, 0);
	output_close_scope();
}


// Start libyara internal variables, create the compiler and load the sources
int start_yara(const char* rule_path, void* compiler_callback) 
{

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

	yr_compiler_add_fd(yara_ctx.yr_compiler, rule_fd, NULL, rule_path);

	yara_ctx.error = ERROR_NO_ERROR;

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
	api->plugin->general_plugin_register_function(PLUGIN_NAMESPACE, "say_hello", say_hello);
	api->plugin->general_plugin_register_function(PLUGIN_NAMESPACE, "say_world", say_world);
	return 0;
}

void plugin_shutdown()
{
	puts("Called shutdown!");
	yr_initialize();
}


void plugin_unloaded()
{
	puts("Called unload!");	
	yr_initialize();
}

int plugin_loaded()
{
	puts("Called load");
	return 0;
}

