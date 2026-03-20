
set(HEADERS
    compat.h
)

set(SOURCES
    strlcat.c
    asprintf.c
)

if(MSVC)
    list(APPEND HEADERS
        include/getopt.h
        include/sys/queue.h
        include/unistd.h
    )
    list(APPEND SOURCES
        getline.c
        getopt.c
        strndup.c
    )
endif()

add_library(compat OBJECT ${HEADERS} ${SOURCES})

set(COMPAT_INCLUDE_DIRS 
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

if(MSVC)
    target_link_libraries(compat PUBLIC dl)
    list(APPEND COMPAT_INCLUDE_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
    )

endif()

target_include_directories(compat PRIVATE
    "${COMPAT_INCLUDE_DIRS}"
)
set_target_properties(compat PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${COMPAT_INCLUDE_DIRS}"
)

add_library(readpe::compat ALIAS compat)

# TODO: Option to install compatibility headers

