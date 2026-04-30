include(BPFBuild)

set(K1_BPF_OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bpf)
make_directory(${K1_BPF_OUTPUT_DIR})


set(BPF_COMPILE_OPTIONS
    "-I${CMAKE_SOURCE_DIR}/src/bpf/include \
    -I${CMAKE_SOURCE_DIR}/src/common \
    -I${CMAKE_BINARY_DIR}/src/bpf/include \
    -fmacro-prefix-map=${CMAKE_SOURCE_DIR}/src/="
)

skel_from_bpf_dir(${CMAKE_CURRENT_SOURCE_DIR} "${K1_BPF_OUTPUT_DIR}/bpf_progs" ${BPF_COMPILE_OPTIONS})
