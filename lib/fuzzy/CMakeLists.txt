project(libfuzzy)

set(HEADERS
    fuzzy.h
)

set(SOURCES
    edit_dist.c
    fuzzy.c
)

add_library(fuzzy STATIC ${HEADERS} ${SOURCES})

