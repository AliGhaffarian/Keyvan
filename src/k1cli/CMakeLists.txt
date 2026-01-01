add_executable(k1cli k1cli.c opt.c ${CMAKE_SOURCE_DIR}/src/common/enum_to_str_maps.c)
target_link_libraries(k1cli bpf)
