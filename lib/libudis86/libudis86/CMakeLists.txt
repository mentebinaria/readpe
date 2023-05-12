project(libudis86)

set(HEADERS
	decode.h
	extern.h
	itab.h
	syn.h
	types.h
	udint.h
)

set(SOURCES
	decode.c
	itab.c
	syn-att.c
	syn-intel.c
	syn.c
	udis86.c
)

add_compile_definitions(
	HAVE_STRING_H=1
)

add_library(udis86 STATIC ${HEADERS} ${SOURCES})

