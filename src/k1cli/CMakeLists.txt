file(GLOB INCLUDE_DEFS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/user_include/*.c")
include_directories(${K1_USER_INCLUDES})
include_directories(${K1_PARSER_INCLUDES})
add_executable(
    k1cli
    k1cli.c opt.c config_ops.c
    ${COMMON_SOURCES} ${INCLUDE_DEFS}
)
target_link_libraries(k1cli bpf)
target_link_libraries(k1cli parser)
target_link_libraries(k1cli k1)
