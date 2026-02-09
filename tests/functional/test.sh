#!/bin/bash

#This script relies heavily on kill command being a shell builtin
#Note: we won't check if k1cli cleansup the maps afterwards as we will replace k1cli with keyvand later on, and the current implementation will probably be completely rewritten
#TODO: make this test a python script that also checks the map values

echo Warning: this test script is highly unstable, it is discouraged to use it. you may get locked out of your computer and need to reboot.

read -p "run the test anyway? [y/N]:" -r input
if [ "$input" != "y" ] && [ "$input" != "Y" ]; then
	exit 0
fi

TEST_BUILD_LOC=$(git rev-parse --show-toplevel)/test_build
K1_BIN_PATH=$TEST_BUILD_LOC/output/k1cli

LINE_DELIM="############"

K1_CLI_PID=0

PASSWORD_EXECVE="/some/password"

EXPECT_ERROR=1
EXPECT_NO_ERROR=0

TEST_CONFIG="\
uid: 1000 #some comment\n\
#another comment\n\
auth: {\n\
#comment\n\
    type: execve\n\
    pathname: $PASSWORD_EXECVE\n\
    verdict_sub_type: K1_VERDICT_MAP_UID\n\
    verdict: {\n\
        type: execve\n\
    }\n\
}\n\
"

log_msg() {
	echo
	echo $LINE_DELIM
	echo "$1"
	echo $LINE_DELIM
	echo
}
build() {
	cmake -S . -B "$TEST_BUILD_LOC"
	make -C "$TEST_BUILD_LOC"
}
cleanup_n_quit() {
	err_code=$1

	log_msg "Cleaning up"
	kill $K1_CLI_PID
	rm -rf "$TEST_BUILD_LOC"

	exit "$err_code"
}

run_test_case() {
	cmd="$1"
	do_expect_err="$2"

	"$cmd" &>/dev/null
	err=$?

	if (((do_expect_err != 0) != (err != 0))); then
		log_msg "failed test. cmd: $cmd, expect error: $do_expect_err"
		cleanup_n_quit 1
	fi
}

main() {

	cd "$(git rev-parse --show-toplevel)" || (
		echo "err going to project root"
		exit 1
	)

	log_msg "Building"
	build

	tmp_config_file=$(mktemp)
	echo -e "$TEST_CONFIG" >"$tmp_config_file"

	sudo "$K1_BIN_PATH" -c "$tmp_config_file" &
	err=$?
	K1_CLI_PID=$!
	if ((err != 0)); then
		log_msg "failed to run k1cli"
		exit 1
	fi

	log_msg "Sleeping for k1cli to setup"
	sleep 1

	log_msg "Testing"

	run_test_case "ls" $EXPECT_ERROR

	run_test_case "$PASSWORD_EXECVE" $EXPECT_ERROR #execs afterwards should succeed

	run_test_case "ls" $EXPECT_NO_ERROR

	log_msg "Passed"
	cleanup_n_quit 0
}

main
