#include "yarascan.h"

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

const char* include_callback( const char* include_name,
			      const char* calling_rule_filename,
			      const char* calling_rule_namespace,
			      void* user_data)
{
	printf("Fixing include name from %s, include: %s\n", calling_rule_filename, include_name);

	return include_name;
	
}


void scan_callback( YR_SCAN_CONTEXT* context,
		    int message,
		    void* message_data,
		    void* user_data)
{
	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_RULE* rule_match = (YR_RULE*) message_data;
		output((const char*) rule_match->identifier, NULL);
	}
}



void scan_pe(pe_ctx_t* pe_ctx) 
{
	if (yara_ctx.error != ERROR_NO_ERROR) return;
	int flags = SCAN_FLAGS_FAST_MODE;

	output_open_scope("Yara", OUTPUT_SCOPE_TYPE_ARRAY);
	int err = yr_rules_scan_mem(yara_ctx.yr_rules, pe_ctx->map_addr, pe_ctx->map_size, flags, scan_callback, yara_ctx.user_data, 0);
	output_close_scope();

}


// Start libyara internal variables, create the compiler and load the sources
int start_yara(const char* rules_folder) 
{

	yr_initialize();	
	if (yr_compiler_create(&yara_ctx.yr_compiler) != ERROR_SUCCESS) {
		return ERROR_COMPILER;
	}
	
	yr_compiler_set_callback(yara_ctx.yr_compiler, compiler_callback, yara_ctx.user_data);
	yr_compiler_set_include_callback(yara_ctx.yr_compiler, include_callback,NULL, yara_ctx.user_data);
	struct dirent* dir_entry;
	DIR* dir = opendir(rules_folder);
	
	if (!dir) {
		destroy_yara();
		return ERROR_DIR_NOT_FOUND;
	}
	

	// Recursive walk into directory loading all rules inside
	FILE* f;
	char* full_path;	
	
	while ( (dir_entry = readdir(dir)) != NULL ) {
		if (!strcmp(dir_entry->d_name, ".") || !strcmp(dir_entry->d_name, "..")) continue;

		full_path = calloc(sizeof(char), strlen(dir_entry->d_name) + strlen(rules_folder));

		memcpy(full_path, rules_folder, strlen(rules_folder));
		strcat(full_path, dir_entry->d_name);
		
		f = fopen(full_path, "r");
		if (!f) continue;
		
		yr_compiler_add_file(yara_ctx.yr_compiler, f, NULL, full_path);
		

		free(full_path);
		fclose(f);

		if (yara_ctx.error == ERROR_COMPILER_LOAD_RULE) {
			destroy_yara();
			return ERROR_COMPILER_LOAD_RULE;
		}

	}
	
	yr_compiler_get_rules(yara_ctx.yr_compiler, &yara_ctx.yr_rules);
	yara_ctx.error = ERROR_NO_ERROR;

	return ERROR_SUCCESS;
}

void destroy_yara()
{
	if (yara_ctx.yr_compiler)
		yr_compiler_destroy(yara_ctx.yr_compiler);
	
	yr_finalize();
}



