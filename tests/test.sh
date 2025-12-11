#!/bin/bash

#This script relies heavily on kill command being a shell builtin
#Note: we won't check if k1cli cleansup the maps afterwards as we will replace k1cli with keyvand later on, and the current implementation will probably be completely rewritten
#TODO: make this test a python script that also checks the map values

TEST_BUILD_LOC=$(git rev-parse --show-toplevel)/test_build
K1_BIN_PATH=$TEST_BUILD_LOC/output/k1cli

LINE_DELIM="############"

K1_CLI_PID=0

log_msg(){
    echo
    echo $LINE_DELIM
    echo $1
    echo $LINE_DELIM
    echo
}
build() {
    cmake -S . -B $TEST_BUILD_LOC
    make -C $TEST_BUILD_LOC
}
cleanup_n_quit() {
    err_code=$1

    log_msg "Cleaning up"
    kill $K1_CLI_PID
    rm -rf $TEST_BUILD_LOC
    exit
}

main() {

    cd $(git rev-parse --show-toplevel)

    log_msg "Building"
    build

    sudo $K1_BIN_PATH -u $(id -u) -a K1_AUTH_TYPE_EXECVE -p /some/password&
    K1_CLI_PID=$!

    log_msg "Sleeping for k1cli to setup"
    sleep 1

    log_msg "Testing"

    if ping -c 2 google.com &> /dev/null ;then
        log_msg "Failed to deny ping"
        cleanup_n_quit 1
    fi

    if ls &> /dev/null ;then
        log_msg "Failed to deny ls"
        cleanup_n_quit 1
    fi

    if /random_command &> /dev/null ;then
        log_msg "Failed to deny /random_command"
        cleanup_n_quit 1
    fi

    /some/password &> /dev/null

    if ! ls &> /dev/null ;then
        log_msg "Failed to allow ls"
        cleanup_n_quit 1
    fi

    log_msg "Passed"
    cleanup_n_quit 0
}

main
