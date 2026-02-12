file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
set(TO_TEST_SOURCES ${CMAKE_SOURCE_DIR}/src/common/k1_set.h ${CMAKE_SOURCE_DIR}/src/libk1/ima.c)
set(DEPENDANCY_SOURCES ${CMAKE_SOURCE_DIR}/src/libk1/logger.c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test_shared)

add_executable(run_units
    ${TEST_SOURCES}
    ${TO_TEST_SOURCES}
    ${COMMON_SOURCES}
    ${DEPENDANCY_SOURCES}
)

target_include_directories(run_units SYSTEM BEFORE
    PRIVATE ${K1_USER_INCLUDES}
)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/libk1/dummy_executable.sh DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

target_link_libraries(run_units cmocka)
