cmake_minimum_required(VERSION 3.31.6)
project(keyvan)

set(CMAKE_C_COMPILER clang)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
set(K1_OUTPUT_DIR output)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${K1_OUTPUT_DIR})

add_compile_options("-fmacro-prefix-map=${CMAKE_SOURCE_DIR}/src/=")
add_compile_options("-g")
make_directory(${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

make_directory(${CMAKE_BINARY_DIR}/src/bpf/include/)
make_directory(${CMAKE_BINARY_DIR}/src/include/)

Include_directories(src/common)
Include_directories(src/external/include)
Include_directories(${CMAKE_BINARY_DIR}/src/include)

set(K1_USER_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/src/libk1/include)
set(K1_PARSER_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/src/parser/include)
file(GLOB COMMON_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/common/*.c")

# includes cmake modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)

add_subdirectory(tools)
add_subdirectory(src/bpf)
add_subdirectory(src/libk1)
add_subdirectory(src/parser)
add_subdirectory(src/k1cli)
add_subdirectory(tests)
