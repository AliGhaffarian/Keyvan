set(CMAKE_C_COMPILER clang)
set(K1_BPF_OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bpf)

make_directory(${K1_BPF_OUTPUT_DIR})

# vmlinux.h
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/src/bpf/include/vmlinux.h
    DEPENDS /sys/kernel/btf/vmlinux
    COMMAND bpftool
    ARGS btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_BINARY_DIR}/src/bpf/include/vmlinux.h
)
add_custom_target(
    vmlinux_hdr
    ALL
    DEPENDS ${CMAKE_BINARY_DIR}/src/bpf/include/vmlinux.h
)


function(skel_from_bpf_dir DIRNAME OUTPUT_NAME)
    file(GLOB_RECURSE BPF_TARGETS ${DIRNAME}/*.bpf.c)
    # build individual bpf programs
    foreach(TARGET IN LISTS BPF_TARGETS)
        get_filename_component(TARGET_FILE_NAME ${TARGET} NAME)
        set(TARGET_OUTPUT_PATH ${K1_BPF_OUTPUT_DIR}/${TARGET_FILE_NAME}.o)
        add_custom_command(
            OUTPUT ${TARGET_OUTPUT_PATH}
            COMMAND ${CMAKE_C_COMPILER}
            ARGS -O2 -target bpf -g -c ${TARGET}
                -I${CMAKE_SOURCE_DIR}/src/bpf/include -I${CMAKE_SOURCE_DIR}/src/common -I${CMAKE_BINARY_DIR}/src/bpf/include
                -fmacro-prefix-map=${CMAKE_SOURCE_DIR}/src/=
                -o ${TARGET_OUTPUT_PATH}
        )
        add_custom_target(
            ${TARGET_FILE_NAME}
            DEPENDS ${TARGET_OUTPUT_PATH}
        )
        list(APPEND BPF_OBJECT_LIBS ${TARGET_OUTPUT_PATH})
    endforeach()

    # skel files
    add_custom_command(
        OUTPUT ${K1_BPF_OUTPUT_DIR}/${OUTPUT_NAME}.o
        DEPENDS ${BPF_OBJECT_LIBS}
        COMMAND bpftool
        ARGS gen obj ${K1_BPF_OUTPUT_DIR}/${OUTPUT_NAME}.o ${BPF_OBJECT_LIBS}
    )

    # skel files
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/src/include/${OUTPUT_NAME}.skel.h
        DEPENDS ${K1_BPF_OUTPUT_DIR}/${OUTPUT_NAME}.o
        COMMAND bpftool
        ARGS gen skel ${K1_BPF_OUTPUT_DIR}/${OUTPUT_NAME}.o > ${CMAKE_BINARY_DIR}/src/include/${OUTPUT_NAME}.skel.h
    )

    add_custom_target(
        skel
        ALL
        DEPENDS ${CMAKE_BINARY_DIR}/src/include/${OUTPUT_NAME}.skel.h
    )
endfunction(skel_from_bpf_dir)
