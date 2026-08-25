
include(GNUInstallDirs)

include_directories(
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/include/readpe"
)

add_library(out_csv  MODULE output/csv.c)
add_library(out_html MODULE output/html.c)
add_library(out_json MODULE output/json.c)
add_library(out_xml  MODULE output/xml.c)

install(TARGETS out_csv out_html out_json out_xml
    RUNTIME DESTINATION ${CMAKE_INSTALL_DATADIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_DATADIR}/readpe/plugins
    ARCHIVE DESTINATION ${CMAKE_INSTALL_DATADIR}/readpe/plugins
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/readpe
)

