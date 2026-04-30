include_directories(include)
add_library(
    k1
    STATIC
    linked_list.c
    logger.c
    ima.c
    exception/pathname.c
)
target_link_libraries(k1 bpf)
