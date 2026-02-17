set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test)

add_custom_target(
    test
    COMMAND
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/run_units --dummy-executable-path ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dummy_executable.sh
)

add_subdirectory(unit)
