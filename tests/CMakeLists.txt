find_program(PYTHON_BIN python3 REQUIRED) # for functional tests

set(OLD_CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

file(
    COPY
    functional
    DESTINATION
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

add_subdirectory(unit)

add_custom_target(
    test
    DEPENDS
    run_functional_tests
    run_unit_tests
)

add_custom_target(
    run_unit_tests
    COMMENT "running unit tests"
    DEPENDS
    run_units
    COMMAND
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/run_units --dummy-executable-path ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dummy_executable.sh
)
add_custom_target(
    run_functional_tests
    COMMENT "running functional tests"
    DEPENDS
    k1cli
    COMMAND
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/functional/functional_tests.py --k1cli-path ${OLD_CMAKE_RUNTIME_OUTPUT_DIRECTORY}/k1cli
)
