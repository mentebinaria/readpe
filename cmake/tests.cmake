enable_testing()

include(ExternalProject)
ExternalProject_Add(texe
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/t/texe/
    CMAKE_ARGS "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/cmake/TC-mingw64.cmake"
    INSTALL_COMMAND ""
)

file(WRITE "${CMAKE_BINARY_DIR}/pev.conf" "plugins_dir=src/plugins")

set(TEXE "texe-prefix/src/texe-build/t.exe")
set(TRPE "src/readpe")

#################################
#        Black Box Tests        #
#################################

add_test(NAME FormatText COMMAND ${TRPE}         ${TEXE})
add_test(NAME FormatCsv  COMMAND ${TRPE} -f csv  ${TEXE})
add_test(NAME FormatHtml COMMAND ${TRPE} -f html ${TEXE})
add_test(NAME FormatJson COMMAND ${TRPE} -f json ${TEXE})
add_test(NAME FormatXml  COMMAND ${TRPE} -f xml  ${TEXE})

# TODO No Tests:
# readpe resources extract
# readpe resources extract --name
# readpe certificates --out <filename>

# TODO Not implemented:
# readpe resources --tree
# readpe [...] hash

# TODO Quiet fails/Wrong Output:
# readpe resources --help

add_test(NAME OutputDefault                 COMMAND ${TRPE} -f json                             ${TEXE})
add_test(NAME OutputCertificates            COMMAND ${TRPE} -f json certificates                ${TEXE})
add_test(NAME OutputCertificatesPem         COMMAND ${TRPE} -f json certificates -f pem         ${TEXE})
add_test(NAME OutputCertificatesText        COMMAND ${TRPE} -f json certificates -f text        ${TEXE})
add_test(NAME OutputCertificatesX509        COMMAND ${TRPE} -f json certificates -f x509        ${TEXE})
add_test(NAME OutputDirectoryListVerbose    COMMAND ${TRPE} -f json directory --list --verbose  ${TEXE})
add_test(NAME OutputDirectoryVerbose        COMMAND ${TRPE} -f json directory --verbose         ${TEXE})
add_test(NAME OutputExports                 COMMAND ${TRPE} -f json exports                     ${TEXE})
add_test(NAME OutputFeatures                COMMAND ${TRPE} -f json features                    ${TEXE})
add_test(NAME OutputFileVersion             COMMAND ${TRPE} -f json --file-version              ${TEXE})
add_test(NAME OutputHeader                  COMMAND ${TRPE} -f json header                      ${TEXE})
add_test(NAME OutputHeaderAll               COMMAND ${TRPE} -f json header --all                ${TEXE})
add_test(NAME OutputHeaderCoff              COMMAND ${TRPE} -f json header coff                 ${TEXE})
add_test(NAME OutputHeaderDos               COMMAND ${TRPE} -f json header dos                  ${TEXE})
add_test(NAME OutputHeaderOptional          COMMAND ${TRPE} -f json header optional             ${TEXE})
add_test(NAME OutputImports                 COMMAND ${TRPE} -f json imports                     ${TEXE})
add_test(NAME OutputImportsList             COMMAND ${TRPE} -f json imports --list              ${TEXE})
add_test(NAME OutputImportsVerbose          COMMAND ${TRPE} -f json imports --verbose           ${TEXE})
add_test(NAME OutputResources               COMMAND ${TRPE} -f json resources                   ${TEXE})
add_test(NAME OutputResourcesFileVersion    COMMAND ${TRPE} -f json resources --file-version    ${TEXE})
add_test(NAME OutputResourcesHelp           COMMAND ${TRPE} -f json resources --help            ${TEXE})
add_test(NAME OutputResourcesList           COMMAND ${TRPE} -f json resources --list            ${TEXE})
add_test(NAME OutputResourcesListVerbose    COMMAND ${TRPE} -f json resources --list --verbose  ${TEXE})
add_test(NAME OutputResourcesStatistics     COMMAND ${TRPE} -f json resources --statistics      ${TEXE})
add_test(NAME OutputResourcesTree           COMMAND ${TRPE} -f json resources --tree            ${TEXE})
add_test(NAME OutputResourcesVerbose        COMMAND ${TRPE} -f json resources --verbose         ${TEXE})
add_test(NAME OutputScan                    COMMAND ${TRPE} -f json scan                        ${TEXE})
add_test(NAME OutputScanVerbose             COMMAND ${TRPE} -f json scan --verbose              ${TEXE})
add_test(NAME OutputSection                 COMMAND ${TRPE} -f json section                     ${TEXE})
add_test(NAME OutputSectionAll              COMMAND ${TRPE} -f json section --all               ${TEXE})
add_test(NAME OutputSecurity                COMMAND ${TRPE} -f json security                    ${TEXE})

set(TestsOutput
    OutputDefault
    OutputCertificates
    OutputCertificatesPem
    OutputCertificatesText
    OutputCertificatesX509
    OutputDirectoryListVerbose
    OutputDirectoryVerbose
    OutputExports
    OutputFeatures
    OutputFileVersion
    OutputHeader
    OutputHeaderAll
    OutputHeaderCoff
    OutputHeaderDos
    OutputHeaderOptional
    OutputImports
    OutputImportsList
    OutputImportsVerbose
    OutputResources
    OutputResourcesFileVersion
    OutputResourcesHelp
    OutputResourcesList
    OutputResourcesListVerbose
    OutputResourcesStatistics
    OutputResourcesTree
    OutputResourcesVerbose
    OutputScan
    OutputScanVerbose
    OutputSection
    OutputSectionAll
    OutputSecurity
)

add_test(NAME HashDefault                   COMMAND ${TRPE} -f json hash                        ${TEXE})
add_test(NAME HashHeader                    COMMAND ${TRPE} -f json header hash                 ${TEXE})
add_test(NAME HashHeaderDos                 COMMAND ${TRPE} -f json header dos hash             ${TEXE})
add_test(NAME HashHeaderCoff                COMMAND ${TRPE} -f json header coff hash            ${TEXE})
add_test(NAME HashHeaderOptional            COMMAND ${TRPE} -f json header optional hash        ${TEXE})
add_test(NAME HashSection                   COMMAND ${TRPE} -f json section hash                ${TEXE})
add_test(NAME HashSectionText               COMMAND ${TRPE} -f json section .text hash          ${TEXE})

set_tests_properties(${TestsOutput}
    PROPERTIES FAIL_REGULAR_EXPRESSION "unrecognized option")

