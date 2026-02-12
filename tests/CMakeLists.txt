set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test)

add_custom_target(
    test
    COMMAND
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test.sh
    COMMAND
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/run_units ARGS --dummy-executable-path ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dummy_executable.sh
)

configure_file(functional/test.sh ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test.sh COPYONLY)
add_subdirectory(unit)
