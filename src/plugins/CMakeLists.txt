include_directories(../../include)

add_library(csv SHARED output/csv.c)
add_library(html SHARED  output/html.c)
add_library(json SHARED output/json.c)
add_library(xml SHARED output/xml.c)

install(TARGETS csv html json xml
    LIBRARY DESTINATION share/readpe/plugins
    ARCHIVE DESTINATION share/readpe/plugins
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include/readpe
)

