include_directories(include)
add_library(
    k1
    linked_list.c
    logger.c
    ima.c
    exception/pathname.c
)
target_link_libraries(k1 bpf)
install(TARGETS k1)
install(
    DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/include/k1
    TYPE INCLUDE
)
