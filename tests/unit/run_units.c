// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "run_units.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct option long_options[] = {
    {.name = "dummy-executable-path",
     .has_arg = required_argument,
     .flag = NULL,
     .val = 'c'},
};

void handle_args(int argc, char **argv)
{
    int option_index = -1;
    int err;
    int c;
    while(1) {
        c = getopt_long(argc, argv, "hc:", long_options, &option_index);
        if(c == -1)
            break;
        switch(c) {
        case 'c':
            dummy_executable_relative_path = strdup(optarg);
            break;
        default:
            break;
        }
    }
    return;
}

int main(int argc, char **argv)
{
    handle_args(argc, argv);
    test_k1_set();
    test_k1_ima();
}
