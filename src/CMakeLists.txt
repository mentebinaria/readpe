project(readpe LANGUAGES C)

set(HEADERS
	../include/compat/sys/queue.h
	../include/compat/strlcat.h
	../include/common.h
	../include/config.h
	../include/output.h
	../include/output_plugin.h
	../include/peldd.h
	../include/peres.h
	../include/pescan.h
	../include/pesec.h
	../include/pestr.h
	../include/pev_api.h
	../include/plugin.h
	../include/plugins.h
	../include/readpe.h
	../include/stack.h

	dylib.h
	main.h
)

set(SOURCES
	compat/strlcat.c

	config.c
	dylib.c
	main.c
	malloc_s.c
	output.c
	output_plugin.c
	output_text.c
	pedis.c
	pehash.c
	peldd.c
	pepack.c
	peres.c
	pescan.c
	pesec.c
	pestr.c
	pev_api.c
	plugins.c
	readpe.c
)

if(BUILD_STATIC)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	set(BUILD_SHARED_LIBS OFF)
	set(CMAKE_EXE_LINKER_FLAGS "-no-pie -static")

	# set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
	# target_compile_options(your_target_name [PUBLIC|PRIVATE] /MT)
	# target_link_options(your_target_name [PUBLIC|PRIVATE] /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)
	# set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	# https://stackoverflow.com/questions/24648357/compiling-a-static-executable-with-cmake
	# set(CMAKE_MFC_FLAG 1)

endif()

if(WIN32)
	append( SOURCES
		windows/cpload.c
	)
endif()

add_compile_definitions(
    _GNU_SOURCE
    SHAREDIR=""
    PLUGINSDIR="pev/plugins"
)

find_package(OpenSSL)

add_executable(readpe ${HEADERS} ${SOURCES})
target_include_directories(readpe PRIVATE
	"../include"
	"../lib"
	"../lib/libpe/include"
)
target_link_libraries(readpe PRIVATE pe udis86 OpenSSL::Crypto m)
if(MSVC)
	target_compile_options(readpe PRIVATE /W4 /WX)
else()
	target_compile_options(readpe PRIVATE
		-Wall
		-Wextra
		-Wpedantic
		-Wshadow
		-Wundef
		-Wdouble-promotion
		-Wformat=2
		-Wformat-security
		-Wconversion
		-ggdb3
	)
endif()

