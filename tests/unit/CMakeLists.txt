file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
file(GLOB_RECURSE TO_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/common/*.h")

add_executable(run_units
    ${TEST_SOURCES}
    ${TO_TEST_SOURCES}
)

target_link_libraries(run_units cmocka)
