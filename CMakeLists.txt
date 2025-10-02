cmake_minimum_required(VERSION 3.31.6)
project(keyvan)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
Include_directories(src/include)
Include_directories(${CMAKE_BINARY_DIR}/src/include)
add_subdirectory(src/bpf)
add_subdirectory(src/k1cli)
