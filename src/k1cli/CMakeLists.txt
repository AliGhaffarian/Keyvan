add_executable(k1cli k1cli.c opt.c ${CMAKE_SOURCE_DIR}/src/common/common.c)
target_link_libraries(k1cli bpf)
