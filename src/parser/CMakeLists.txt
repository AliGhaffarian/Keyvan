include_directories(${CMAKE_SOURCE_DIR}/src/common)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/parser.tab.c ${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    COMMAND bison
    ARGS
    -d ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    --header=${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    -o ${CMAKE_BINARY_DIR}/parser.tab.c
)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/lexer.yy.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l ${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    COMMAND flex
    ARGS -o ${CMAKE_BINARY_DIR}/lexer.yy.c ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l
)

add_library(parser
    STATIC
    ${CMAKE_BINARY_DIR}/parser.tab.c
    ${CMAKE_BINARY_DIR}/src/include/parser.tab.h
    ${CMAKE_BINARY_DIR}/lexer.yy.c
)
