cmake_minimum_required(VERSION 3.31.6)
project(keyvan)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
set(K1_OUTPUT_DIR output)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${K1_OUTPUT_DIR})
make_directory(${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

Include_directories(src/include)
Include_directories(${CMAKE_BINARY_DIR}/src/include)
add_subdirectory(src/bpf)
add_subdirectory(src/k1cli)
