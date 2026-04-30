find_program(BISON_BIN bison REQUIRED)
find_program(FLEX_BIN flex REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/src/common)
include_directories(${K1_USER_INCLUDES})
include_directories(${K1_PARSER_INCLUDES})

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/parser.tab.c ${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    COMMAND ${BISON_BIN}
    ARGS
    -d ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    --header=${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    -o ${CMAKE_BINARY_DIR}/parser.tab.c
)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/lexer.yy.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l ${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    COMMAND ${FLEX_BIN}
    ARGS -o ${CMAKE_BINARY_DIR}/lexer.yy.c ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l
)

add_library(parser
    STATIC
    ${CMAKE_BINARY_DIR}/parser.tab.c
    ${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    ${CMAKE_BINARY_DIR}/lexer.yy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/parser_enum_maps/parser_enum_maps.c
)

target_include_directories(parser SYSTEM BEFORE PRIVATE ${K1_USER_INCLUDES})
target_include_directories(parser SYSTEM BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/parser_enum_maps)
