project(libpe LANGUAGES C)

set(HEADERS
	include/libpe/context.h
	include/libpe/directories.h
	include/libpe/dir_import.h
	include/libpe/dir_resources.h
	include/libpe/dir_security.h
	include/libpe/error.h
	include/libpe/exports.h
	include/libpe/hashes.h
	include/libpe/hdr_dos.h
	include/libpe/hdr_coff.h
	include/libpe/hdr_optional.h
	include/libpe/imports.h
	include/libpe/macros.h
	include/libpe/ordlookup.h
	include/libpe/pe.h
	include/libpe/resources.h
	include/libpe/sections.h
	include/libpe/types_resources.h
	include/libpe/utils.h
	include/libpe/utlist.h

	libfuzzy/fuzzy.h
)
set(SOURCES
	libfuzzy/edit_dist.c
	libfuzzy/fuzzy.c

	security.c
	error.c
	exports.c
	hashes.c
	imports.c

	misc.c
	pe.c
	resources.c
	utils.c
)

find_package(OpenSSL REQUIRED)

if(BUILD_STATIC)
    add_library(pe STATIC ${HEADERS} ${SOURCES})
else()
    add_library(pe SHARED ${HEADERS} ${SOURCES})
endif()

target_link_libraries(pe PRIVATE OpenSSL::Crypto OpenSSL::SSL )

target_include_directories(pe PRIVATE "include" ${OPENSSL_INCLUDE_DIR} )
if(MSVC)
	target_compile_options(pe PRIVATE /W4 /WX)
else()
	target_compile_options(pe PRIVATE
		-Wall
		-Wextra
		-Wpedantic
		-Wshadow
		-Wundef
		-Wdouble-promotion
		-Wformat=2
		-Wformat-security
		-Wconversion
	)
endif()

install(TARGETS pe
    EXPORT peTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include/libpe
)

