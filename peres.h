typedef enum {
	RDT_LEVEL1 = 1,
	RDT_LEVEL2 = 2,
	RDT_LEVEL3 = 3
}NODE_LEVEL_PERES;

typedef enum {
	RDT_RESOURCE_DIRECTORY = 1,
	RDT_DIRECTORY_ENTRY = 2,
	RDT_DATA_STRING = 3,
	RDT_DATA_ENTRY = 4
} NODE_TYPE_PERES;

typedef struct _NODE_PERES {
	NODE_TYPE_PERES nodeType;
	NODE_LEVEL_PERES nodeLevel;
	union {
		IMAGE_RESOURCE_DIRECTORY *resourceDirectory; // nodeType == 1
		IMAGE_RESOURCE_DIRECTORY_ENTRY *directoryEntry; // nodeType == 2
		IMAGE_RESOURCE_DATA_STRING *dataString; // nodeType == 3
		IMAGE_RESOURCE_DATA_ENTRY *dataEntry; // nodeType == 4
	} resource;
	struct _NODE_PERES *nextNode;
	struct _NODE_PERES *lastNode;
	struct _NODE_PERES *rootNode;
} NODE_PERES;

typedef struct {
	int NodeType;
	int Characteristics;
	int TimeDateStamp;
	int MajorVersion;
	int MinorVersion;
	int NumberOfNamedEntries;
	int NumberOfIdEntries;
}type_RDT_RESOURCE_DIRECTORY;

typedef struct {
	int NodeType;
	int NameOffset;
	int NameIsString;
	int OffsetIsDirectory;
	int DataIsDirectory;
}type_RDT_DIRECTORY_ENTRY;

typedef struct {
	int NodeType;
	int Strlen;
	int String;
}type_RDT_DATA_STRING;

typedef struct {
	int NodeType;
	int OffsetToData;
	int Size;
	int CodePage;
	int Reserved;
}type_RDT_DATA_ENTRY;

typedef struct {
 NODE_TYPE_PERES kind;
	union {
		type_RDT_RESOURCE_DIRECTORY resourcesDirectory;
		type_RDT_DIRECTORY_ENTRY directoryEntry;
		type_RDT_DATA_STRING dataString;
		type_RDT_DATA_ENTRY dataEntry;
	}node_type;

}output_node_t;

// counting
typedef struct {
	int resourcesDirectory;
	int directoryEntry;
	int dataString;
	int dataEntry;
}resources_count_t;

typedef struct {
	NODE_TYPE_PERES kind;
}count_output_node;

typedef struct {
	type_RDT_RESOURCE_DIRECTORY *resourcesDirectory;
	type_RDT_DIRECTORY_ENTRY *directoryEntry;
	type_RDT_DATA_STRING *dataString;
	type_RDT_DATA_ENTRY *dataEntry;
}final_output_t;

final_output_t get_resources(pe_ctx_t *ctx);
//output_count get_count(NODE_PERES *node);
resources_count_t get_resources_count(pe_ctx_t *ctx);
