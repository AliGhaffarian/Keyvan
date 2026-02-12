// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include <enum_to_str_maps.h>
#include <errno.h>
#include <helper.h>
#include <k1/ima.h>
#include <linux/hash_info.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SET_NTH_BIT(n) (((k1_set_batch_t)1) << (n));

const char *dummy_executable_sha256 =
    "9ce4d205ede1d2b1cfc0a2e7fbb4f1adcfd0d8d0370c77bae30c23a12a784054";
char *dummy_executable_relative_path = "./dummy_executable.sh";

void test_k1_ima_current_hash_algo(void **state)
{
    errno = 0;
    // incomplete, need to mock fopen to challenge this function
    {
        FILE *cmdline = fopen("/proc/cmdline", "r");
        char buf[64] = {0};
        int matched = 0;

        setvbuf(cmdline, NULL, _IONBF, 0);
        matched = fscanf(cmdline, fmt_proc_cmdline_ima_hash, buf);
        fclose(cmdline);

        int hash_algo = k1_ima_current_hash_algo();

        if(matched == 0)
            assert_int_equal(hash_algo, HASH_ALGO_SHA1);
        else
            assert_string_equal(hash_algo_name[hash_algo], buf);
        assert_int_equal(errno, 0);
    }
}

void test_k1_ima_get_sha256(void **state)
{
    errno = 0;
    // expect to get a hash
    {
        sha256 expected_hash;
        sha256 result_hash;
        int err = 0;
        int cmp_result = 0;
        char dummy_executable_realpath[4096] = {0};

        sha256_hex_to_bytes(dummy_executable_sha256, (char *)expected_hash);

        realpath(dummy_executable_relative_path, dummy_executable_realpath);

        // ensure dummpy_executable is logged, if ima policy is set to tcb
        system(dummy_executable_realpath);

        err = k1_ima_get_sha256(&result_hash, dummy_executable_realpath);
        cmp_result = memcmp(result_hash, expected_hash, sizeof(sha256));

        assert_int_equal(err, 0);
        assert_int_equal(cmp_result, 0);
    }

    errno = 0;

    // nonexisting pathname
    {
        char random_pathname[256] = {0};
        sha256 expected_hash = {0};
        FILE *mktemp_pipe = NULL;
        sha256 result_hash = {0};
        int err = 0;
        int cmp_result = 0;
        int rbytes = -1;

        mktemp_pipe = popen("mktemp", "r");
        rbytes =
            fread(random_pathname, 1, sizeof(random_pathname), mktemp_pipe);
        if(random_pathname[rbytes - 1] == '\n')
            random_pathname[rbytes - 1] = 0;

        err = k1_ima_get_sha256(&result_hash, random_pathname);
        cmp_result = memcmp(result_hash, expected_hash, sizeof(sha256));

        assert_int_equal(err, 1);
        assert_int_equal(errno, ENOENT);
        assert_int_equal(cmp_result, 0);
    }
}

int test_k1_ima()
{
    if(geteuid() != 0) {
        printf("ima units must be ran as root\n");
        return 1;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_k1_ima_current_hash_algo),
        cmocka_unit_test(test_k1_ima_get_sha256),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
