include_directories(../../include)

add_library(csv SHARED output/csv.c)
add_library(html SHARED  output/html.c)
add_library(json SHARED output/json.c)
add_library(xml SHARED output/xml.c)

