# Small bpf build system using clang and bpftool
# Requires the vmlinux to be present in /sys/kernel/btf/vmlinux

find_program(BPFTOOL_BIN bpftool REQUIRED)
find_program(CLANG_BIN clang REQUIRED)
set(CMAKE_C_COMPILER ${CLANG_BIN})

# vmlinux.h
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/src/bpf/include/vmlinux.h
    DEPENDS /sys/kernel/btf/vmlinux
    COMMAND ${BPFTOOL_BIN}
    ARGS btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_BINARY_DIR}/src/bpf/include/vmlinux.h
)
add_custom_target(
    vmlinux_hdr
    ALL
    DEPENDS ${CMAKE_BINARY_DIR}/src/bpf/include/vmlinux.h
)

# Compile a single BPF object file from C source.
#
# Usage:
#   bpf_obj(
#     <input_path>    # Path to the .c source file
#     <output_path>   # Output filepath (e.g., /home/xdp_filter.o)
#   )
function(single_bpf_obj input_path output_path compile_flags)
    get_filename_component(TARGET_NAME ${input_path} NAME)
    separate_arguments(_compile_flags NATIVE_COMMAND ${compile_flags})

    add_custom_command(
        OUTPUT ${output_path}
        COMMAND ${CMAKE_C_COMPILER}
            -O2 -target bpf -g ${_compile_flags} -c ${input_path}
            -o ${output_path}
        DEPENDS vmlinux_hdr ${input_path}
    )

endfunction()

# Compile a all BPF source files into one bpf object file using bpftool.
#
# Usage:
#   bpf_obj(
#     <input_dir>     # Path to the directory of bpf source files.
#     <output_path>   # Output filepath (e.g., /home/obj.o)
#     <compile_flags> # Compile flags to append to the default flags
#   )
function(bpfobj_from_dir input_dir output_pathname compile_flags)
    file(GLOB_RECURSE BPF_TARGETS ${input_dir}/*.bpf.c)

    # build individual bpf programs
    foreach(BPF_SOURCEFILE_PATHNAME IN LISTS BPF_TARGETS)
        get_filename_component(BPF_SOURCEFILE_NAME ${BPF_SOURCEFILE_PATHNAME} NAME)
        get_filename_component(OUTPUT_DIR ${output_pathname} DIRECTORY)

        set(BPF_OBJ_NAME ${OUTPUT_DIR}/${BPF_SOURCEFILE_NAME}.o)
        single_bpf_obj(${BPF_SOURCEFILE_PATHNAME} ${BPF_OBJ_NAME} ${compile_flags})

        list(APPEND BPF_OBJECT_NAMES ${BPF_OBJ_NAME})
    endforeach()

    add_custom_command(
        OUTPUT ${output_pathname}
        DEPENDS ${BPF_OBJECT_NAMES}
        COMMAND ${BPFTOOL_BIN}
        ARGS gen obj ${output_pathname} ${BPF_OBJECT_NAMES}
    )

endfunction()

# Compile a all BPF source files into one bpf skeleton file using bpftool.
#
# Usage:
#   bpf_obj(
#     <input_dir>     # Path to the directory of bpf source files.
#     <output_path>   # Output filepath without extension (e.g., /home/programs_skeleton_file)
#     <compile_flags> # Compile flags to append to the default flags
#   )
function(skel_from_bpf_dir dirname output_pathname_w_e compile_flags)

    bpfobj_from_dir(${dirname} ${output_pathname_w_e}.o ${compile_flags})

    get_filename_component(OUTPUT_NAME ${output_pathname_w_e} NAME)
    # skel files
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/src/include/${OUTPUT_NAME}.skel.h
        DEPENDS ${output_pathname_w_e}.o
        COMMAND ${BPFTOOL_BIN}
        ARGS gen skel ${output_pathname_w_e}.o > ${CMAKE_BINARY_DIR}/src/include/${OUTPUT_NAME}.skel.h
    )

    add_custom_target(
        skel
        ALL
        DEPENDS ${CMAKE_BINARY_DIR}/src/include/${OUTPUT_NAME}.skel.h
    )

endfunction()
