find_program(CLANG_FORMAT NAMES clang-format REQUIRED)

file(GLOB_RECURSE srcs 
${CMAKE_SOURCE_DIR}/*.c
${CMAKE_SOURCE_DIR}/*.h
)

add_custom_target(
    fixstyle
    COMMAND ${CLANG_FORMAT} --style=file:${CMAKE_SOURCE_DIR}/.clang-format -i ${srcs}
)
