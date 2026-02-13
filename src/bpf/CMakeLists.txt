set(K1_BPF_OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bpf)

make_directory(${K1_BPF_OUTPUT_DIR})

#find_package(BPFBuild REQUIRED)
include(BPFBuild)

skel_from_bpf_dir(${CMAKE_CURRENT_SOURCE_DIR} bpf_progs)
