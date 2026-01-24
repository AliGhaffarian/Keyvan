include_directories(${CMAKE_SOURCE_DIR}/src/userspace_include)
file(GLOB COMMON_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/common/*.c")
add_executable(k1cli k1cli.c opt.c ${COMMON_SOURCES})
target_link_libraries(k1cli bpf)
